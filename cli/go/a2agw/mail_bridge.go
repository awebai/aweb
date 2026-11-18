package a2agw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/awebai/aw/awid"
)

type MailTransport interface {
	SendMessage(context.Context, *awid.SendMessageRequest) (*awid.SendMessageResponse, error)
	SendMessageByIdentity(context.Context, *awid.SendMessageRequest) (*awid.SendMessageResponse, error)
	MailConversation(context.Context, string, int) (*awid.InboxResponse, error)
}

type RouteScopedMailTransport interface {
	MailConversationForRoute(context.Context, string, string, string, int) (*awid.InboxResponse, error)
}

type RouteBoundMailTransport interface {
	SendMessageForRoute(context.Context, string, string, bool, *awid.SendMessageRequest) (*awid.SendMessageResponse, error)
}

type recipientIdentityResolver interface {
	ResolveIdentity(context.Context, string) (*awid.ResolvedIdentity, error)
}

type recipientIdentityProvider interface {
	ProvidesRecipientIdentity() bool
}

type recipientIdentity struct{ DID, StableID string }

type ReplyApplier interface {
	ApplyBridgeReply(BridgeReply) (Task, bool, error)
}

type MailBridgeConfig struct {
	Client                    MailTransport
	GatewayIdentity           string
	UseIdentityAuth           bool
	PollInterval              time.Duration
	PollTimeout               time.Duration
	RequireVerifiedReplies    bool
	AllowUnverifiedLocalReply bool
	AllowQuestionReply        bool
	Audit                     AuditSink
}

// RequiresVerifiedReplies implements the explicit requirement's precedence over
// the local override (docs/a2a.md:959-961). The safe zero-value requires it.
func (config MailBridgeConfig) RequiresVerifiedReplies() bool {
	return config.RequireVerifiedReplies || !config.AllowUnverifiedLocalReply
}

type MailBridge struct {
	client                 MailTransport
	gatewayIdentity        string
	useIdentityAuth        bool
	pollInterval           time.Duration
	pollTimeout            time.Duration
	requireVerifiedReplies bool
	allowQuestionReply     bool
	audit                  AuditSink

	mu      sync.Mutex
	threads map[string]*mailBridgeThread
	applier ReplyApplier
}

type mailBridgeThread struct {
	TaskID           string
	ContextID        string
	RequestID        string
	RouteID          string
	TargetAddress    string
	TargetDID        string
	TargetStableID   string
	CallerScope      string
	ConversationID   string
	MessageID        string
	SeenMessages     map[string]bool
	CreatedAt        time.Time
	ReplyDeadline    time.Time
	PollContext      context.Context
	StopPolling      context.CancelFunc
	RetentionContext context.Context
	StopRetention    context.CancelFunc
}

type a2aTaskEnvelope struct {
	TaskID          string `json:"task_id"`
	ContextID       string `json:"context_id,omitempty"`
	RouteID         string `json:"route_id"`
	TargetAddress   string `json:"target_address"`
	GatewayIdentity string `json:"gateway_identity,omitempty"`
	CallerScope     string `json:"caller_scope,omitempty"`
	State           string `json:"state"`
	RequestID       string `json:"request_id"`
}

type a2aReplyEnvelope struct {
	TaskID    string `json:"task_id"`
	ContextID string `json:"context_id,omitempty"`
	State     string `json:"state"`
	Artifacts []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"artifacts,omitempty"`
	Text string `json:"text,omitempty"`
}

func NewMailBridge(config MailBridgeConfig) (*MailBridge, error) {
	if config.Client == nil {
		return nil, errors.New("mail bridge client is required")
	}
	pollInterval := config.PollInterval
	if pollInterval <= 0 {
		pollInterval = 500 * time.Millisecond
	}
	return &MailBridge{
		client:                 config.Client,
		gatewayIdentity:        strings.TrimSpace(config.GatewayIdentity),
		useIdentityAuth:        config.UseIdentityAuth,
		pollInterval:           pollInterval,
		pollTimeout:            config.PollTimeout,
		requireVerifiedReplies: config.RequiresVerifiedReplies(),
		allowQuestionReply:     config.AllowQuestionReply,
		audit:                  config.Audit,
		threads:                map[string]*mailBridgeThread{},
	}, nil
}

func (b *MailBridge) SetReplyApplier(applier ReplyApplier) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applier = applier
}

func (b *MailBridge) SetGatewayIdentity(identity string) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.gatewayIdentity = strings.TrimSpace(identity)
}

func (b *MailBridge) gatewayIdentitySnapshot() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.gatewayIdentity
}

// ValidateTarget shares the pre-send rule with startup validation. Managed
// providers enforce target addressability in their own configuration authority.
func (b *MailBridge) ValidateTarget(ctx context.Context, address string) error {
	_, err := b.resolveTargetIdentity(ctx, address)
	return err
}

// resolveTargetIdentity implements docs/a2a.md:943-952: a public route cannot
// expose a local identity, even through an alias. Resolve through aw mail's
// authority before signing; provider receipts carry the same signed binding.
func (b *MailBridge) resolveTargetIdentity(ctx context.Context, address string) (recipientIdentity, error) {
	if resolver, ok := b.client.(recipientIdentityResolver); ok {
		identity, err := resolver.ResolveIdentity(ctx, address)
		if err != nil {
			return recipientIdentity{}, fmt.Errorf("Resolve the A2A target before sending: %w. Check the route address and registry, then retry.", err)
		}
		if identity == nil || identity.DID == "" {
			return recipientIdentity{}, errors.New("A2A target has no resolved signing identity. Check its registry binding, then retry.")
		}
		if err := requirePublicA2ATarget(identity); err != nil {
			return recipientIdentity{}, err
		}
		return recipientIdentity{DID: identity.DID, StableID: identity.StableID}, nil
	}
	if b.requireVerifiedReplies {
		provider, ok := b.client.(recipientIdentityProvider)
		if !ok || !provider.ProvidesRecipientIdentity() {
			return recipientIdentity{}, errors.New("A2A provider cannot bind the reply identity. Upgrade the provider to support recipient_identity_v1 before sending.")
		}
	}
	return recipientIdentity{}, nil
}

// requirePublicA2ATarget enforces public addressability on the resolved
// identity, never on an alias or submitted address alone (docs/a2a.md:943-949).
func requirePublicA2ATarget(identity *awid.ResolvedIdentity) error {
	_, addressErr := awid.CanonicalFederationAddress(identity.Address)
	if identity.IdentityScope == awid.IdentityModeLocal || !strings.HasPrefix(identity.StableID, "did:aw:") || addressErr != nil {
		return errors.New("An A2A route needs an agent with a public address, and local agents can't be reached from outside their team. Choose a global agent's public address for this route.")
	}
	return nil
}

func (b *MailBridge) SendTask(ctx context.Context, task BridgeTask) error {
	start := time.Now()
	gatewayIdentity := b.gatewayIdentitySnapshot()
	body, err := FormatA2ATaskMessage(a2aTaskEnvelope{
		TaskID:          task.TaskID,
		ContextID:       task.ContextID,
		RouteID:         task.RouteID,
		TargetAddress:   task.Address,
		GatewayIdentity: gatewayIdentity,
		CallerScope:     bridgeVisibleCallerScope(task.CallerScope),
		State:           TaskStateWorking,
		RequestID:       task.RequestID,
	}, task.Text)
	if err != nil {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "error", Code: "format_failed", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return err
	}
	req := &awid.SendMessageRequest{
		ToAddress:   task.Address,
		Subject:     "A2A task " + task.TaskID,
		Body:        body,
		ContentMode: awid.ContentModeLegacyPlaintextV1,
		Priority:    awid.PriorityNormal,
	}
	recipient, err := b.resolveTargetIdentity(ctx, task.Address)
	if err != nil {
		return err
	}
	req.ToDID, req.ToStableID = recipient.DID, recipient.StableID
	resp, err := b.sendForRoute(ctx, task.RouteID, task.Address, req)
	if err != nil {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "error", Code: "send_failed", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return err
	}
	recipient = recipientFromSend(req, resp)
	thread := &mailBridgeThread{
		TaskID:         task.TaskID,
		ContextID:      task.ContextID,
		RequestID:      task.RequestID,
		RouteID:        task.RouteID,
		TargetAddress:  task.Address,
		TargetDID:      recipient.DID,
		TargetStableID: recipient.StableID,
		CallerScope:    task.CallerScope,
		ConversationID: strings.TrimSpace(resp.ConversationID),
		MessageID:      strings.TrimSpace(resp.MessageID),
		SeenMessages:   map[string]bool{strings.TrimSpace(resp.MessageID): true},
		CreatedAt:      time.Now(),
		ReplyDeadline:  replyDeadline(time.Now(), task.TaskTTL, b.pollTimeout),
	}
	if thread.ConversationID == "" {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "error", Code: "missing_conversation_id", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return errors.New("mail bridge send response missing conversation_id")
	}
	thread.RetentionContext, thread.StopRetention = context.WithDeadline(context.Background(), replyDeadline(thread.CreatedAt, task.TaskTTL, 0))
	thread.PollContext, thread.StopPolling = context.WithDeadline(thread.RetentionContext, thread.ReplyDeadline)
	b.mu.Lock()
	b.threads[task.TaskID] = thread
	shouldPoll := b.applier != nil
	b.mu.Unlock()
	context.AfterFunc(thread.RetentionContext, func() { b.finishThread(task.TaskID) })
	b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "ok", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	if shouldPoll {
		go b.pollTaskReplies(task.TaskID)
	}
	return nil
}

func (b *MailBridge) CancelTask(ctx context.Context, cancel BridgeCancel) error {
	start := time.Now()
	gatewayIdentity := b.gatewayIdentitySnapshot()
	thread := b.thread(cancel.TaskID)
	b.finishThread(cancel.TaskID)
	body := FormatA2ACancelMessage(cancel.TaskID, cancel.ContextID, cancel.RequestID)
	req := &awid.SendMessageRequest{
		ConversationID: cancel.ContextID,
		ToAddress:      cancel.Address,
		Subject:        "A2A task canceled " + cancel.TaskID,
		Body:           body,
		ContentMode:    awid.ContentModeLegacyPlaintextV1,
		Priority:       awid.PriorityNormal,
	}
	if thread != nil && thread.ConversationID != "" {
		req.ConversationID = thread.ConversationID
	}
	_, err := b.sendForRoute(ctx, cancel.RouteID, cancel.Address, req)
	outcome := "ok"
	code := ""
	if err != nil {
		outcome = "error"
		code = "cancel_send_failed"
	}
	b.recordAudit(AuditEvent{Stage: "bridge_cancel", RequestID: cancel.RequestID, RouteID: cancel.RouteID, TaskID: cancel.TaskID, GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(cancel.Address), Outcome: outcome, Code: code, LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	return err
}

func (b *MailBridge) IngestInboxMessage(ctx context.Context, msg awid.InboxMessage) (Task, bool, error) {
	gatewayIdentity := b.gatewayIdentitySnapshot()
	reply, found, err := ParseA2AReplyWithOptions(ReplyParseInput{Body: msg.Body, AllowQuestionReply: b.allowQuestionReply})
	if err != nil || !found {
		if err != nil {
			b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: "", TaskID: reply.TaskID, Outcome: "error", Code: "malformed_reply", VerificationTier: string(msg.VerificationStatus)})
		}
		return Task{}, false, err
	}
	thread := b.thread(reply.TaskID)
	if thread == nil && reply.TaskID == "" && msg.ConversationID != "" {
		thread = b.threadByConversation(msg.ConversationID)
		if thread != nil {
			reply.TaskID = thread.TaskID
			reply.ContextID = thread.ContextID
		}
	}
	if thread == nil {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: "", TaskID: reply.TaskID, Outcome: "ignored", Code: "unknown_task", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if thread.ConversationID != "" && msg.ConversationID != thread.ConversationID {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "ignored", Code: "conversation_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if msg.MessageID != "" && thread.SeenMessages[msg.MessageID] {
		return Task{}, false, nil
	}
	if thread.ContextID != "" && reply.ContextID != thread.ContextID {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "ignored", Code: "context_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if err := b.verifyReplyMessage(msg); err != nil {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "error", Code: "verification_failed", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, err
	}
	if b.requireVerifiedReplies && !thread.matchesSender(msg) {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, Outcome: string(AuditIgnored), Code: "target_identity_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, errors.New("A2A reply is not from the target identity bound at task creation. Have the configured target agent reply in the original conversation.")
	}
	reply.Verification = awid.Unverified
	if b.requireVerifiedReplies {
		reply.Verification = msg.VerificationStatus
	}
	b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "ok", VerificationTier: string(msg.VerificationStatus)})
	b.mu.Lock()
	if msg.MessageID != "" {
		b.markSeenLocked(thread.TaskID, msg.MessageID)
	}
	applier := b.applier
	b.mu.Unlock()
	if applier == nil {
		return Task{}, false, nil
	}
	start := time.Now()
	task, ok, err := applier.ApplyBridgeReply(reply)
	if ok {
		b.finishThread(thread.TaskID)
	}
	outcome := "ok"
	code := ""
	if err != nil {
		outcome = "error"
		code = "state_transition_failed"
	} else if !ok {
		outcome = "ignored"
		code = "state_transition_ignored"
	}
	b.recordAudit(AuditEvent{Stage: "task_state_transition", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: outcome, Code: code, LatencyMS: latencyMS(start), VerificationTier: string(msg.VerificationStatus)})
	return task, ok, err
}

func (b *MailBridge) send(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	if b.useIdentityAuth {
		return b.client.SendMessageByIdentity(ctx, req)
	}
	return b.client.SendMessage(ctx, req)
}

func (b *MailBridge) sendForRoute(ctx context.Context, routeID, address string, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	if transport, ok := b.client.(RouteBoundMailTransport); ok {
		return transport.SendMessageForRoute(ctx, routeID, address, b.useIdentityAuth, req)
	}
	return b.send(ctx, req)
}

func bridgeVisibleCallerScope(scope string) string {
	scope = strings.TrimSpace(scope)
	if strings.HasPrefix(scope, "auth:") {
		return "auth:" + auditHash(strings.TrimPrefix(scope, "auth:"))
	}
	return scope
}

func (b *MailBridge) thread(taskID string) *mailBridgeThread {
	b.mu.Lock()
	defer b.mu.Unlock()
	thread := b.threads[taskID]
	if thread == nil {
		return nil
	}
	copy := *thread
	copy.SeenMessages = make(map[string]bool, len(thread.SeenMessages))
	for k, v := range thread.SeenMessages {
		copy.SeenMessages[k] = v
	}
	return &copy
}

func (b *MailBridge) threadByConversation(conversationID string) *mailBridgeThread {
	conversationID = strings.TrimSpace(conversationID)
	if conversationID == "" {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, thread := range b.threads {
		if thread.ConversationID == conversationID {
			copy := *thread
			copy.SeenMessages = make(map[string]bool, len(thread.SeenMessages))
			for k, v := range thread.SeenMessages {
				copy.SeenMessages[k] = v
			}
			return &copy
		}
	}
	return nil
}

func (b *MailBridge) markSeenLocked(taskID, messageID string) {
	thread := b.threads[taskID]
	if thread == nil || strings.TrimSpace(messageID) == "" {
		return
	}
	if thread.SeenMessages == nil {
		thread.SeenMessages = map[string]bool{}
	}
	thread.SeenMessages[messageID] = true
}

// finishThread ends both the in-flight read and retained bridge state
// (docs/a2a.md:938-939).
func (b *MailBridge) finishThread(taskID string) {
	b.mu.Lock()
	thread := b.threads[taskID]
	delete(b.threads, taskID)
	b.mu.Unlock()
	if thread != nil && thread.StopPolling != nil {
		thread.StopPolling()
	}
	if thread != nil && thread.StopRetention != nil {
		thread.StopRetention()
	}
}

func (b *MailBridge) pollTaskReplies(taskID string) {
	thread := b.thread(taskID)
	if thread == nil || thread.ConversationID == "" {
		return
	}
	defer thread.StopPolling()
	for {
		if thread.PollContext.Err() != nil {
			return
		}
		resp, err := b.mailConversationForThread(thread.PollContext, thread, 20)
		if err != nil && thread.PollContext.Err() == nil {
			log.Printf("aweb-a2a-gw: reply poll failed task=%s: %v", taskID, err)
		}
		if err == nil && resp != nil {
			for _, msg := range resp.Messages {
				_, applied, err := b.IngestInboxMessage(thread.PollContext, msg)
				if err != nil {
					log.Printf("aweb-a2a-gw: reply rejected task=%s: %v", taskID, err)
				}
				if applied {
					return
				}
			}
		}
		timer := time.NewTimer(replyPollInterval(b.pollInterval, time.Since(thread.CreatedAt)))
		select {
		case <-thread.PollContext.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}

// replyDeadline bounds reply polling by the task TTL (default one hour) and,
// when configured, by an explicit poll timeout cap.
func replyDeadline(start time.Time, taskTTL, pollTimeout time.Duration) time.Time {
	ttl := taskTTL
	if ttl <= 0 {
		ttl = time.Hour
	}
	if pollTimeout > 0 && pollTimeout < ttl {
		ttl = pollTimeout
	}
	return start.Add(ttl)
}

// replyPollInterval keeps the configured cadence for the first minute, when
// most agents answer, then backs off so long-lived tasks poll gently.
func replyPollInterval(base time.Duration, elapsed time.Duration) time.Duration {
	if elapsed <= time.Minute {
		return base
	}
	backoff := 5 * time.Second
	if base > backoff {
		return base
	}
	return backoff
}

func (b *MailBridge) mailConversationForThread(ctx context.Context, thread *mailBridgeThread, limit int) (*awid.InboxResponse, error) {
	if scoped, ok := b.client.(RouteScopedMailTransport); ok {
		return scoped.MailConversationForRoute(ctx, thread.RouteID, thread.TargetAddress, thread.ConversationID, limit)
	}
	return b.client.MailConversation(ctx, thread.ConversationID, limit)
}

func (b *MailBridge) verifyReplyMessage(msg awid.InboxMessage) error {
	if !b.requireVerifiedReplies {
		return nil
	}
	switch msg.VerificationStatus {
	case awid.Verified, awid.VerifiedCustodial, awid.VerifiedLegacy:
		return nil
	default:
		return fmt.Errorf("A2A reply verification status %q is not accepted. Have the target agent send a signed reply from its configured identity.", msg.VerificationStatus)
	}
}

func (b *MailBridge) recordAudit(event AuditEvent) {
	if b.audit == nil {
		return
	}
	b.audit.RecordA2A(event)
}

// recipientFromSend preserves the bound outgoing identity, or the provider's
// exact signed recipient (docs/a2a.md:951-956).
func recipientFromSend(req *awid.SendMessageRequest, resp *awid.SendMessageResponse) recipientIdentity {
	if req.ToDID != "" {
		return recipientIdentity{DID: req.ToDID, StableID: req.ToStableID}
	}
	return recipientIdentity{DID: strings.TrimSpace(resp.RecipientDID), StableID: strings.TrimSpace(resp.RecipientStableID)}
}

// matchesSender applies the recorded target binding after mail verification
// (docs/a2a.md:963-967).
func (thread *mailBridgeThread) matchesSender(msg awid.InboxMessage) bool {
	if thread.TargetStableID != "" {
		return msg.FromStableID == thread.TargetStableID
	}
	return thread.TargetDID != "" && msg.FromDID == thread.TargetDID
}

func FormatA2ATaskMessage(env a2aTaskEnvelope, text string) (string, error) {
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	reply := map[string]any{
		"task_id": env.TaskID,
		"state":   "completed",
		"artifacts": []map[string]string{
			{"type": "text", "text": "<your answer>"},
		},
	}
	if strings.TrimSpace(env.ContextID) != "" {
		reply["context_id"] = env.ContextID
	}
	replyBody, err := json.MarshalIndent(reply, "", "  ")
	if err != nil {
		return "", err
	}
	instructions := "To complete this task, reply in this mail conversation with a fenced a2a-reply block:\n\n" +
		"```a2a-reply\n" + string(replyBody) + "\n```\n\n" +
		"Allowed state values: completed, input_required, failed, rejected. " +
		"Replies without a valid a2a-reply block do not change the task.\n"
	return "```a2a-task\n" + string(body) + "\n```\n\n" + instructions + "\nCustomer message (untrusted):\n\n" + text, nil
}

func FormatA2ACancelMessage(taskID, contextID, requestID string) string {
	body, _ := json.MarshalIndent(map[string]string{
		"task_id":    taskID,
		"context_id": contextID,
		"request_id": requestID,
		"state":      TaskStateCanceled,
	}, "", "  ")
	return "```a2a-cancel\n" + string(body) + "\n```\n\nThe A2A caller canceled this task."
}

func ParseA2AReply(body string, allowQuestion bool) (BridgeReply, bool, error) {
	return ParseA2AReplyWithOptions(ReplyParseInput{Body: body, AllowQuestionReply: allowQuestion})
}

type ReplyParseInput struct {
	Body               string
	AllowQuestionReply bool
}

// ParseA2AReplyWithOptions owns bridge reply parsing (docs/a2a.md:968-970).
// ParseA2AReply retains the published Go entry point and delegates here.
func ParseA2AReplyWithOptions(input ReplyParseInput) (BridgeReply, bool, error) {
	block, found := extractFence(fenceInput{Body: input.Body, Label: "a2a-reply"})
	if !found {
		if input.AllowQuestionReply {
			trimmed := strings.TrimSpace(input.Body)
			if strings.HasPrefix(trimmed, "QUESTION:") {
				return BridgeReply{State: TaskStateInputRequired, Text: strings.TrimSpace(strings.TrimPrefix(trimmed, "QUESTION:"))}, true, nil
			}
		}
		return BridgeReply{}, false, nil
	}
	if block == "" {
		return BridgeReply{}, true, errors.New("A2A reply is empty, unfinished, or ambiguous. Reply with one complete standalone a2a-reply block outside quoted customer text.")
	}
	var env a2aReplyEnvelope
	if err := json.Unmarshal([]byte(block), &env); err != nil {
		return BridgeReply{}, true, err
	}
	reply := BridgeReply{TaskID: strings.TrimSpace(env.TaskID), ContextID: strings.TrimSpace(env.ContextID), State: strings.TrimSpace(env.State), Text: strings.TrimSpace(env.Text)}
	for _, artifact := range env.Artifacts {
		if strings.TrimSpace(artifact.Type) != "" && strings.TrimSpace(artifact.Type) != "text" {
			continue
		}
		text := strings.TrimSpace(artifact.Text)
		if text == "" {
			continue
		}
		reply.Artifacts = append(reply.Artifacts, Artifact{Name: "answer", Parts: []A2APart{{Text: text, MediaType: "text/plain"}}})
		if reply.Text == "" {
			reply.Text = text
		}
	}
	if strings.TrimSpace(reply.TaskID) == "" {
		return BridgeReply{}, true, errors.New("a2a-reply task_id is required")
	}
	if strings.TrimSpace(reply.State) == "" {
		return BridgeReply{}, true, errors.New("a2a-reply state is required")
	}
	if _, err := normalizeReplyState(reply.State); err != nil {
		return BridgeReply{}, true, err
	}
	return reply, true, nil
}

type fenceInput struct{ Body, Label string }

// extractFence selects one standalone fence without treating quoted or nested
// customer text as reply instructions (docs/a2a.md:968-970).
func extractFence(input fenceInput) (string, bool) {
	var marker byte
	var width int
	var capture, found bool
	var content []string
	var block string
	for _, line := range strings.Split(input.Body, "\n") {
		trimmed := strings.TrimSpace(line)
		// Markdown block quotes and indented code are data, not reply instructions.
		if width == 0 && (strings.HasPrefix(trimmed, ">") || strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "\t")) {
			continue
		}
		if width > 0 {
			n := 0
			for n < len(trimmed) && trimmed[n] == marker {
				n++
			}
			if n >= width && strings.TrimSpace(trimmed[n:]) == "" {
				if capture {
					block = strings.TrimSpace(strings.Join(content, "\n"))
				}
				width, capture = 0, false
			} else if capture {
				content = append(content, line)
			}
			continue
		}
		if len(trimmed) < 3 || (trimmed[0] != '`' && trimmed[0] != '~') {
			continue
		}
		marker = trimmed[0]
		n := 0
		for n < len(trimmed) && trimmed[n] == marker {
			n++
		}
		if n < 3 {
			continue
		}
		width = n
		capture = strings.TrimSpace(trimmed[n:]) == input.Label
		if capture {
			if found {
				return "", true
			} // An ambiguous answer must not select customer text.
			found, content = true, nil
		}
	}
	if capture {
		return "", true
	}
	return block, found
}
