package a2agw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type MailBridge struct {
	client                    MailTransport
	gatewayIdentity           string
	useIdentityAuth           bool
	pollInterval              time.Duration
	pollTimeout               time.Duration
	requireVerifiedReplies    bool
	allowUnverifiedLocalReply bool
	allowQuestionReply        bool
	audit                     AuditSink

	mu      sync.Mutex
	threads map[string]*mailBridgeThread
	applier ReplyApplier
}

type mailBridgeThread struct {
	TaskID         string
	ContextID      string
	RequestID      string
	RouteID        string
	TargetAddress  string
	CallerScope    string
	ConversationID string
	MessageID      string
	SeenMessages   map[string]bool
	CreatedAt      time.Time
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
		client:                    config.Client,
		gatewayIdentity:           strings.TrimSpace(config.GatewayIdentity),
		useIdentityAuth:           config.UseIdentityAuth,
		pollInterval:              pollInterval,
		pollTimeout:               config.PollTimeout,
		requireVerifiedReplies:    config.RequireVerifiedReplies || !config.AllowUnverifiedLocalReply,
		allowUnverifiedLocalReply: config.AllowUnverifiedLocalReply,
		allowQuestionReply:        config.AllowQuestionReply,
		audit:                     config.Audit,
		threads:                   map[string]*mailBridgeThread{},
	}, nil
}

func (b *MailBridge) SetReplyApplier(applier ReplyApplier) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applier = applier
}

func (b *MailBridge) SendTask(ctx context.Context, task BridgeTask) error {
	start := time.Now()
	body, err := FormatA2ATaskMessage(a2aTaskEnvelope{
		TaskID:          task.TaskID,
		ContextID:       task.ContextID,
		RouteID:         task.RouteID,
		TargetAddress:   task.Address,
		GatewayIdentity: b.gatewayIdentity,
		CallerScope:     bridgeVisibleCallerScope(task.CallerScope),
		State:           TaskStateWorking,
		RequestID:       task.RequestID,
	}, task.Text)
	if err != nil {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "error", Code: "format_failed", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return err
	}
	req := &awid.SendMessageRequest{
		ToAddress:   task.Address,
		Subject:     "A2A task " + task.TaskID,
		Body:        body,
		ContentMode: awid.ContentModeLegacyPlaintextV1,
		Priority:    awid.PriorityNormal,
	}
	resp, err := b.send(ctx, req)
	if err != nil {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "error", Code: "send_failed", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return err
	}
	thread := &mailBridgeThread{
		TaskID:         task.TaskID,
		ContextID:      task.ContextID,
		RequestID:      task.RequestID,
		RouteID:        task.RouteID,
		TargetAddress:  task.Address,
		CallerScope:    task.CallerScope,
		ConversationID: strings.TrimSpace(resp.ConversationID),
		MessageID:      strings.TrimSpace(resp.MessageID),
		SeenMessages:   map[string]bool{strings.TrimSpace(resp.MessageID): true},
		CreatedAt:      time.Now(),
	}
	if thread.ConversationID == "" {
		b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "error", Code: "missing_conversation_id", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
		return errors.New("mail bridge send response missing conversation_id")
	}
	b.mu.Lock()
	b.threads[task.TaskID] = thread
	shouldPoll := b.applier != nil && b.pollTimeout > 0
	b.mu.Unlock()
	b.recordAudit(AuditEvent{Stage: "bridge_send", RequestID: task.RequestID, RouteID: task.RouteID, TaskID: task.TaskID, CallerScopeClass: callerScopeClass(task.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(task.Address), Outcome: "ok", LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	if shouldPoll {
		go b.pollTaskReplies(task.TaskID)
	}
	return nil
}

func (b *MailBridge) CancelTask(ctx context.Context, cancel BridgeCancel) error {
	start := time.Now()
	thread := b.thread(cancel.TaskID)
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
	_, err := b.send(ctx, req)
	outcome := "ok"
	code := ""
	if err != nil {
		outcome = "error"
		code = "cancel_send_failed"
	}
	b.recordAudit(AuditEvent{Stage: "bridge_cancel", RequestID: cancel.RequestID, RouteID: cancel.RouteID, TaskID: cancel.TaskID, GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(cancel.Address), Outcome: outcome, Code: code, LatencyMS: latencyMS(start), VerificationTier: "unsigned"})
	return err
}

func (b *MailBridge) IngestInboxMessage(ctx context.Context, msg awid.InboxMessage) (Task, bool, error) {
	reply, found, err := ParseA2AReply(msg.Body, b.allowQuestionReply)
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
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "ignored", Code: "conversation_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if msg.MessageID != "" && thread.SeenMessages[msg.MessageID] {
		return Task{}, false, nil
	}
	if thread.ContextID != "" && reply.ContextID != thread.ContextID {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "ignored", Code: "context_mismatch", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, nil
	}
	if err := b.verifyReplyMessage(msg); err != nil {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "error", Code: "verification_failed", VerificationTier: string(msg.VerificationStatus)})
		return Task{}, false, err
	}
	b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: "ok", VerificationTier: string(msg.VerificationStatus)})
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
	outcome := "ok"
	code := ""
	if err != nil {
		outcome = "error"
		code = "state_transition_failed"
	} else if !ok {
		outcome = "ignored"
		code = "state_transition_ignored"
	}
	b.recordAudit(AuditEvent{Stage: "task_state_transition", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentity), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: outcome, Code: code, LatencyMS: latencyMS(start), VerificationTier: string(msg.VerificationStatus)})
	return task, ok, err
}

func (b *MailBridge) send(ctx context.Context, req *awid.SendMessageRequest) (*awid.SendMessageResponse, error) {
	if b.useIdentityAuth {
		return b.client.SendMessageByIdentity(ctx, req)
	}
	return b.client.SendMessage(ctx, req)
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

func (b *MailBridge) pollTaskReplies(taskID string) {
	thread := b.thread(taskID)
	if thread == nil || thread.ConversationID == "" {
		return
	}
	deadline := time.Now().Add(b.pollTimeout)
	for {
		if time.Now().After(deadline) {
			return
		}
		resp, err := b.mailConversationForThread(context.Background(), thread, 20)
		if err == nil && resp != nil {
			for _, msg := range resp.Messages {
				if _, ok, _ := b.IngestInboxMessage(context.Background(), msg); ok {
					return
				}
			}
		}
		time.Sleep(b.pollInterval)
	}
}

func (b *MailBridge) mailConversationForThread(ctx context.Context, thread *mailBridgeThread, limit int) (*awid.InboxResponse, error) {
	if scoped, ok := b.client.(RouteScopedMailTransport); ok {
		return scoped.MailConversationForRoute(ctx, thread.RouteID, thread.TargetAddress, thread.ConversationID, limit)
	}
	return b.client.MailConversation(ctx, thread.ConversationID, limit)
}

func (b *MailBridge) verifyReplyMessage(msg awid.InboxMessage) error {
	if !b.requireVerifiedReplies || b.allowUnverifiedLocalReply {
		return nil
	}
	switch msg.VerificationStatus {
	case awid.Verified, awid.VerifiedCustodial, awid.VerifiedLegacy:
		return nil
	default:
		return fmt.Errorf("a2a reply message verification status %q is not accepted", msg.VerificationStatus)
	}
}

func (b *MailBridge) recordAudit(event AuditEvent) {
	if b.audit == nil {
		return
	}
	b.audit.RecordA2A(event)
}

func FormatA2ATaskMessage(env a2aTaskEnvelope, text string) (string, error) {
	body, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", err
	}
	return "```a2a-task\n" + string(body) + "\n```\n\nCustomer message (untrusted):\n\n" + text, nil
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
	block, found := extractFence(body, "a2a-reply")
	if !found {
		if allowQuestion {
			trimmed := strings.TrimSpace(body)
			if strings.HasPrefix(trimmed, "QUESTION:") {
				return BridgeReply{State: TaskStateInputRequired, Text: strings.TrimSpace(strings.TrimPrefix(trimmed, "QUESTION:"))}, true, nil
			}
		}
		return BridgeReply{}, false, nil
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

func extractFence(body, label string) (string, bool) {
	startMarker := "```" + label
	start := strings.Index(body, startMarker)
	if start < 0 {
		return "", false
	}
	afterMarker := body[start+len(startMarker):]
	newline := strings.Index(afterMarker, "\n")
	if newline < 0 {
		return "", true
	}
	content := afterMarker[newline+1:]
	end := strings.Index(content, "```")
	if end < 0 {
		return "", true
	}
	return strings.TrimSpace(content[:end]), true
}
