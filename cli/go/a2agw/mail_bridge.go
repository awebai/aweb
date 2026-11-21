package a2agw

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/awebai/aw/awid"
)

// MailTransport is the public mail send and verified conversation-reader interface.
type MailTransport interface {
	SendMessage(context.Context, *awid.SendMessageRequest) (*awid.SendMessageResponse, error)
	SendMessageByIdentity(context.Context, *awid.SendMessageRequest) (*awid.SendMessageResponse, error)
	MailConversation(context.Context, string, int) (*awid.InboxResponse, error)
}

// RouteScopedMailTransport reads a managed route conversation under its task context.
type RouteScopedMailTransport interface {
	MailConversationForRoute(context.Context, string, string, string, int) (*awid.InboxResponse, error)
}

// RouteBoundMailTransport sends through a managed provider with explicit route context.
// The identity-auth argument preserves the released provider interface.
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

// ReplyApplier applies an admitted, parsed reply to its matching live task.
type ReplyApplier interface {
	ApplyBridgeReply(BridgeReply) (Task, bool, error)
}

// MailBridgeConfig sets reply policy and the public mail transport.
// Verified replies are required unless explicitly configured otherwise.
type MailBridgeConfig struct {
	Client MailTransport
	// ProviderName is a public label; a supplied URL is reduced to its origin.
	ProviderName              string
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
// the local override (docs/a2a.md:963-965). The safe zero-value requires it.
func (config MailBridgeConfig) RequiresVerifiedReplies() bool {
	return config.RequireVerifiedReplies || !config.AllowUnverifiedLocalReply
}

// MailBridge binds admitted tasks to intended recipients and verifies target replies.
type MailBridge struct {
	client                 MailTransport
	providerName           string
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
	pollers sync.WaitGroup
}

type mailBridgeThread struct {
	TaskID           string
	ContextID        string
	CallerContextID  string
	RequestID        string
	RouteID          string
	TargetAddress    string
	TargetDID        string
	TargetStableID   string
	CallerScope      string
	ConversationID   string
	SeenMessages     map[string]bool
	CreatedAt        time.Time
	ReplyDeadline    time.Time
	PollContext      context.Context
	StopPolling      context.CancelFunc
	RetentionContext context.Context
	StopRetention    context.CancelFunc
	AwaitingInput    bool
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

// NewMailBridge constructs the bridge and its thread retention store.
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
		providerName:           ProviderDisplayName(config.ProviderName),
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

// SetReplyApplier installs the task store receiving admitted replies.
func (b *MailBridge) SetReplyApplier(applier ReplyApplier) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applier = applier
}

// Close cancels retained threads and joins reply workers, including their final
// audit writes (docs/a2a.md:938-941). Stop accepting sends before calling Close.
func (b *MailBridge) Close() {
	b.mu.Lock()
	taskIDs := make([]string, 0, len(b.threads))
	for taskID := range b.threads {
		taskIDs = append(taskIDs, taskID)
	}
	b.mu.Unlock()
	for _, taskID := range taskIDs {
		b.finishThread(taskID)
	}
	b.pollers.Wait()
}

// SetGatewayIdentity updates the sender identity used for bridge audit context.
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

// ProviderDisplayName exposes the provider origin without private URL paths,
// userinfo or query credentials in a public task failure.
func ProviderDisplayName(name string) string {
	name = strings.TrimSpace(name)
	endpoint, err := url.Parse(name)
	if err != nil {
		if strings.Contains(name, "://") {
			return "configured mail provider"
		}
		return name
	}
	if endpoint.IsAbs() && endpoint.Host != "" {
		return endpoint.Scheme + "://" + endpoint.Host
	}
	return name
}

func (b *MailBridge) providerDisplayName() string {
	if b.providerName != "" {
		return b.providerName
	}
	return fmt.Sprintf("%T", b.client)
}

// ValidateTarget shares the pre-send rule with startup validation. Managed
// providers enforce target addressability in their own configuration authority.
func (b *MailBridge) ValidateTarget(ctx context.Context, address string) error {
	_, err := b.resolveTargetIdentity(ctx, address)
	return err
}

// resolveTargetIdentity implements docs/a2a.md:943-956: a public route cannot
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
			return recipientIdentity{}, fmt.Errorf("A2A provider %s cannot bind the reply identity. Upgrade the provider to support recipient_identity_v1 before sending.", b.providerDisplayName())
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

// SendTask resolves the public target, sends a signed task envelope, and retains
// the exact recipient and conversation before polling for task-bound replies.
func (b *MailBridge) SendTask(ctx context.Context, task BridgeTask) error {
	start := time.Now()
	gatewayIdentity := b.gatewayIdentitySnapshot()
	contextID := mailContextID(task.ContextID)
	body, err := FormatA2ATaskMessage(a2aTaskEnvelope{
		TaskID:          task.TaskID,
		ContextID:       contextID,
		RouteID:         task.RouteID,
		TargetAddress:   task.Address,
		GatewayIdentity: gatewayIdentity,
		CallerScope:     bridgeVisibleCallerScope(task.CallerScope),
		State:           TaskStateWorking,
		RequestID:       task.RequestID,
	}, task.Text)
	if err != nil {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: string(AuditError), Code: "format_failed", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
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
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: string(AuditError), Code: "target_identity_unavailable", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return err
	}
	req.ToDID, req.ToStableID = recipient.DID, recipient.StableID
	resp, err := b.sendForRoute(ctx, task.RouteID, task.Address, req)
	if err != nil {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: string(AuditError), Code: "send_failed", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return err
	}
	validatedRecipient, fault := b.validateSendReceipt(req, resp)
	if fault != nil {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: string(AuditError), Code: string(fault.Fault), LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return fault
	}
	recipient = validatedRecipient

	thread := &mailBridgeThread{
		TaskID:          task.TaskID,
		ContextID:       contextID,
		CallerContextID: task.ContextID,
		RequestID:       task.RequestID,
		RouteID:         task.RouteID,
		TargetAddress:   task.Address,
		TargetDID:       recipient.DID,
		TargetStableID:  recipient.StableID,
		CallerScope:     task.CallerScope,
		ConversationID:  strings.TrimSpace(resp.ConversationID),
		SeenMessages:    map[string]bool{strings.TrimSpace(resp.MessageID): true},
		CreatedAt:       time.Now(),
		ReplyDeadline:   replyDeadline(time.Now(), task.TaskTTL, b.pollTimeout),
	}

	thread.RetentionContext, thread.StopRetention = context.WithDeadline(context.Background(), replyDeadline(thread.CreatedAt, task.TaskTTL, 0))
	thread.PollContext, thread.StopPolling = context.WithDeadline(thread.RetentionContext, thread.ReplyDeadline)
	b.mu.Lock()
	b.threads[task.TaskID] = thread
	shouldPoll := b.applier != nil
	if shouldPoll {
		b.pollers.Add(1)
	}
	b.mu.Unlock()
	context.AfterFunc(thread.RetentionContext, func() { b.finishThread(task.TaskID) })
	b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: string(AuditOK), LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	if shouldPoll {
		go func() {
			defer b.pollers.Done()
			b.pollTaskReplies(task.TaskID)
		}()
	}
	return nil
}

// CancelTask stops polling and sends a visible task-specific notice in its
// retained conversation. Local cancellation is the gateway caller's responsibility.
func (b *MailBridge) CancelTask(ctx context.Context, cancel BridgeCancel) error {
	start := time.Now()
	gatewayIdentity := b.gatewayIdentitySnapshot()
	thread := b.finishThread(cancel.TaskID)
	var err error
	outcome := AuditOK
	code := ""
	address, routeID := cancel.Address, cancel.RouteID
	if thread == nil || thread.ConversationID == "" {
		err = errors.New("No retained mail conversation for this A2A task. Contact the target agent with this task ID to confirm cancellation.")
		outcome, code = AuditError, "cancel_binding_missing"
	} else {
		address, routeID = thread.TargetAddress, thread.RouteID
		request := &awid.SendMessageRequest{
			ConversationID: thread.ConversationID,
			ToAddress:      address,
			Subject:        "A2A task canceled " + thread.TaskID,
			Body:           FormatA2ACancelMessage(thread.TaskID, thread.ContextID, cancel.RequestID),
			ContentMode:    awid.ContentModeLegacyPlaintextV1,
			Priority:       awid.PriorityNormal,
		}
		if _, err = b.sendForRoute(ctx, routeID, address, request); err != nil {
			outcome, code = AuditError, "cancel_send_failed"
		}
	}
	b.recordAudit(AuditEvent{Stage: "bridge_cancel", RequestID: cancel.RequestID, RouteID: routeID, TaskID: cancel.TaskID, GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(address), Outcome: string(outcome), Code: code, LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	return err
}

// IngestInboxMessage admits a reply under sender, signature and signed-task rules.
// A refused reply leaves all tasks unchanged and may send binding instructions.
func (b *MailBridge) IngestInboxMessage(ctx context.Context, msg awid.InboxMessage) (Task, bool, error) {
	if b.seenConversationMessage(msg) {
		return Task{}, false, nil
	}
	gatewayIdentity := b.gatewayIdentitySnapshot()
	reply, found, err := ParseA2AReplyWithOptions(ReplyParseInput{Body: msg.Body, AllowQuestionReply: b.allowQuestionReply || b.requireVerifiedReplies})
	if err != nil || !found {
		if err != nil {
			b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: "", TaskID: reply.TaskID, Outcome: string(AuditError), Code: "malformed_reply", VerificationTier: string(msg.VerificationStatus)})
		}
		return Task{}, false, err
	}
	if reply.TaskID == "" && msg.ConversationID == "" {
		err := errors.New("A QUESTION reply has no recorded conversation. Reply in the original conversation with a fenced a2a-reply block naming the task_id and context_id.")
		b.recordAudit(AuditEvent{Stage: "reply_ingest", Outcome: string(AuditDenied), Code: "missing_reply_conversation", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, err
	}
	attachment := b.attachReply(msg, reply)
	thread, reply := attachment.Thread, attachment.Reply

	if thread == nil {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: "", TaskID: reply.TaskID, Outcome: string(AuditIgnored), Code: "unknown_task", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if thread.ConversationID != "" && msg.ConversationID != thread.ConversationID {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(AuditIgnored), Code: "conversation_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if msg.MessageID != "" && thread.SeenMessages[msg.MessageID] {
		return Task{}, false, nil
	}
	if thread.ContextID != "" && reply.ContextID != thread.ContextID {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(AuditIgnored), Code: "context_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if err := b.verifyReplyMessage(msg); err != nil {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(AuditError), Code: "verification_failed", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, err
	}
	if b.requireVerifiedReplies && !thread.matchesSender(msg) {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(AuditIgnored), Code: "target_identity_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, errors.New("A2A reply is not from the target identity bound at task creation. Have the configured target agent reply in the original conversation.")
	}
	if refusal := b.conversationReplyRefusal(attachment); refusal != nil {
		return Task{}, false, b.refuseConversationReply(ctx, replyCorrection{Attachment: attachment, Message: msg, Refusal: refusal})
	}

	reply.Verification = awid.Unverified
	if b.requireVerifiedReplies {
		reply.Verification = msg.VerificationStatus
	}
	b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(AuditOK), VerificationTier: string(msg.VerificationStatus)})
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
	if thread.ContextID != thread.CallerContextID {
		reply.ContextID = thread.CallerContextID
	}
	task, ok, err := applier.ApplyBridgeReply(reply)
	if err != nil && msg.MessageID != "" {
		// The task store reports errors before changing the task. Release the
		// ingestion reservation so a transient identifier failure can be retried.
		b.mu.Lock()
		if current := b.threads[thread.TaskID]; current != nil {
			delete(current.SeenMessages, msg.MessageID)
		}
		b.mu.Unlock()
	}
	if ok {
		state := taskState(task.Status.State)
		switch {
		case isInterruptedState(state):
			b.interruptThread(thread.TaskID)
		case isTerminalState(state):
			b.finishThread(thread.TaskID)
		}
	}
	outcome := AuditOK
	code := ""
	if err != nil {
		outcome = AuditError
		code = "state_transition_failed"
	} else if !ok {
		outcome = AuditIgnored
		code = "state_transition_ignored"
	}
	b.recordAudit(AuditEvent{Stage: "task_state_transition", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(outcome), Code: code, LatencyMS: latencyMS(start), VerificationTier: string(msg.VerificationStatus)})
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

// interruptThread removes the thread from reply admission and stops its poller,
// leaving its original mail binding available for cancellation (docs/a2a.md:938).
func (b *MailBridge) interruptThread(taskID string) {
	b.mu.Lock()
	thread := b.threads[taskID]
	if thread != nil {
		thread.AwaitingInput = true
	}
	b.mu.Unlock()
	if thread != nil && thread.StopPolling != nil {
		thread.StopPolling()
	}
}

// finishThread ends polling and returns the binding it removed from retention.
func (b *MailBridge) finishThread(taskID string) *mailBridgeThread {
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
	return thread
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
				// A shared conversation can carry replies for other tasks. Only
				// this task's poll context controls the lifetime of its reader.
				if thread.PollContext.Err() != nil {
					return
				}
				_, _, err := b.IngestInboxMessage(thread.PollContext, msg)
				if err != nil {
					log.Printf("aweb-a2a-gw: reply rejected task=%s: %v", taskID, err)
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

// mailContextID preserves ordinary correlation tokens and gives arbitrary RPC
// context values a bounded representation in signed agent-facing blocks.
func mailContextID(value string) string {
	if len(value) <= 128 && !strings.ContainsFunc(value, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._:-", r))
	}) {
		return value
	}
	digest := sha256.Sum256([]byte(value))
	return "ctx_" + hex.EncodeToString(digest[:])
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

// verifyReplyMessage accepts VerifiedLegacy because its signature covers the
// body, and verified admission requires that body to carry the fenced task ID
// (docs/a2a.md:978-984,990). conversationReplyRefusal separately rejects the
// conversation-only form.
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
// exact signed recipient (docs/a2a.md:955-960).
func recipientFromSend(req *awid.SendMessageRequest, resp *awid.SendMessageResponse) recipientIdentity {
	if req.ToDID != "" {
		return recipientIdentity{DID: req.ToDID, StableID: req.ToStableID}
	}
	return recipientIdentity{DID: strings.TrimSpace(resp.RecipientDID), StableID: strings.TrimSpace(resp.RecipientStableID)}
}

// matchesSender applies the recorded target binding after mail verification
// (docs/a2a.md:978-984).
func (thread *mailBridgeThread) matchesSender(msg awid.InboxMessage) bool {
	if thread.TargetStableID != "" {
		return msg.FromStableID == thread.TargetStableID
	}
	return thread.TargetDID != "" && msg.FromDID == thread.TargetDID
}

// FormatA2ATaskMessage encodes the task envelope and instructions for fenced
// answers and questions; caller text remains outside the control fence.
func FormatA2ATaskMessage(env a2aTaskEnvelope, text string) (string, error) {
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	replyForm, err := questionReplyForm(questionReplyFields{TaskID: env.TaskID, ContextID: env.ContextID})
	if err != nil {
		return "", err
	}
	instructions := "To respond to this task, reply in this mail conversation with one fenced a2a-reply block. To ask the caller a question, use this exact input_required form and replace its question text:\n\n" +
		replyForm + "\n\nTo complete the task, set state to completed and replace the artifact text with your answer. " +
		"Allowed state values: completed, input_required, failed, rejected. " +
		"Use the fenced form to bind every answer or question to this task.\n"

	return "```a2a-task\n" + string(body) + "\n```\n\n" + instructions + "\nCustomer message (untrusted):\n\n" + text, nil
}

// FormatA2ACancelMessage encodes a visible notice naming its original task.
func FormatA2ACancelMessage(taskID, contextID, requestID string) string {
	body, err := json.MarshalIndent(map[string]string{
		"task_id":    taskID,
		"context_id": contextID,
		"request_id": requestID,
		"state":      TaskStateCanceled,
	}, "", "  ")
	if err != nil {
		log.Printf("aweb-a2a-gw: cancellation notice encoding failed: %v", err)
		return "The A2A caller canceled task " + taskID + ". Contact the gateway operator with this task ID to recover the cancellation notice."
	}
	return "```a2a-cancel\n" + string(body) + "\n```\n\nThe A2A caller canceled this task."
}

// ParseA2AReply parses reply syntax under the released question option.
// It does not establish sender identity or authorize a task transition.
func ParseA2AReply(body string, allowQuestion bool) (BridgeReply, bool, error) {
	return ParseA2AReplyWithOptions(ReplyParseInput{Body: body, AllowQuestionReply: allowQuestion})
}

// ReplyParseInput supplies untrusted mail text and the plain-question option.
type ReplyParseInput struct {
	Body               string
	AllowQuestionReply bool
}

// ParseA2AReplyWithOptions owns bridge reply parsing (docs/a2a.md:997-999).
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
	if reply.TaskID == "" {
		return BridgeReply{}, true, errors.New("a2a-reply task_id is required. Copy the task_id from the gateway task message and retry with one fenced reply.")
	}
	if reply.State == "" {
		return BridgeReply{}, true, errors.New("a2a-reply state is required. Set state to completed, input_required, failed, or rejected and retry.")
	}
	state, err := normalizeReplyState(reply.State)
	if err != nil {
		return BridgeReply{}, true, err
	}
	for _, artifact := range env.Artifacts {
		if strings.TrimSpace(artifact.Type) != "" && strings.TrimSpace(artifact.Type) != "text" {
			continue
		}
		text := strings.TrimSpace(artifact.Text)
		if text == "" {
			continue
		}
		reply.Artifacts = append(reply.Artifacts, Artifact{Name: replyArtifactName(state), Parts: []A2APart{{Text: text, MediaType: "text/plain"}}})
		if reply.Text == "" {
			reply.Text = text
		}
	}
	return reply, true, nil
}

type fenceInput struct{ Body, Label string }

// extractFence selects one standalone fence without treating quoted or nested
// customer text as reply instructions (docs/a2a.md:997-999).
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
