package a2agw

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/awebai/aw/awid"
)

type replyBindingKind int

const (
	taskNamedInBody replyBindingKind = iota
	conversationOnly
)

type replyAttachment struct {
	Reply      BridgeReply
	Thread     *mailBridgeThread
	Candidates []*mailBridgeThread
	Binding    replyBindingKind
}

// attachReply maps a signed task body directly, or finds all eligible tracked
// tasks for a conversation-only QUESTION (docs/a2a.md:978-994).
func (b *MailBridge) attachReply(msg awid.InboxMessage, reply BridgeReply) replyAttachment {
	if reply.TaskID != "" {
		thread := b.thread(reply.TaskID)
		if !thread.acceptsReplies() {
			thread = nil
		}
		return replyAttachment{Reply: reply, Thread: thread, Binding: taskNamedInBody}
	}
	candidates := b.threadsByConversation(msg.ConversationID)
	if b.requireVerifiedReplies {
		matched := make([]*mailBridgeThread, 0, len(candidates))
		for _, thread := range candidates {
			if thread.matchesSender(msg) {
				matched = append(matched, thread)
			}
		}
		if len(matched) > 0 {
			candidates = matched
		}
	}
	attachment := replyAttachment{Reply: reply, Candidates: candidates, Binding: conversationOnly}
	if len(candidates) > 0 {
		attachment.Thread = candidates[0]
		attachment.Reply.TaskID, attachment.Reply.ContextID = candidates[0].TaskID, candidates[0].ContextID
	}
	return attachment
}

func (b *MailBridge) threadsByConversation(conversationID string) []*mailBridgeThread {
	b.mu.Lock()
	defer b.mu.Unlock()
	var threads []*mailBridgeThread
	for _, thread := range b.threads {
		if conversationID != "" && thread.ConversationID == conversationID && thread.acceptsReplies() {
			copy := *thread
			copy.SeenMessages = make(map[string]bool, len(thread.SeenMessages))
			for id, seen := range thread.SeenMessages {
				copy.SeenMessages[id] = seen
			}
			threads = append(threads, &copy)
		}
	}
	sort.Slice(threads, func(i, j int) bool { return threads[i].TaskID < threads[j].TaskID })
	return threads
}

func (thread *mailBridgeThread) acceptsReplies() bool {
	return thread != nil && !thread.AwaitingInput && thread.RetentionContext.Err() == nil
}

type replyRefusalCode string

const (
	taskBindingRequired   replyRefusalCode = "reply_task_binding_required"
	ambiguousQuestionTask replyRefusalCode = "reply_task_ambiguous"
)

type replyBindingRefusal struct {
	Code    replyRefusalCode
	Message string
}

func (e *replyBindingRefusal) Error() string { return e.Message }

// conversationReplyRefusal requires a signed task body for verified replies;
// unverified plain questions also need one when the conversation has several
// eligible tasks (docs/a2a.md:978-994,1031-1034).
func (b *MailBridge) conversationReplyRefusal(attachment replyAttachment) *replyBindingRefusal {
	if attachment.Binding == conversationOnly && b.requireVerifiedReplies {
		return &replyBindingRefusal{Code: taskBindingRequired, Message: "The plain QUESTION was not applied because it does not name the A2A task in its signed body. Use aw 1.19.0 or later to reply in the original conversation with the fenced input_required form below."}
	}
	if attachment.Binding == conversationOnly && len(attachment.Candidates) > 1 {
		return &replyBindingRefusal{Code: ambiguousQuestionTask, Message: "The plain QUESTION was not applied because several live A2A tasks share this conversation. Use aw 1.19.0 or later to reply in the original conversation with the fenced input_required form for the intended task below."}
	}
	return nil
}

type questionReplyFields struct{ TaskID, ContextID string }
type agentReplyState string

const questionState agentReplyState = "input_required"

// questionReplyForm is shared by the initial task instructions and refusal
// feedback, so both show the same signed task/context question form
// (docs/a2a.md:980-990).
func questionReplyForm(fields questionReplyFields) (string, error) {
	reply := map[string]any{"task_id": fields.TaskID, "state": questionState, "artifacts": []map[string]string{{"type": "text", "text": "Your question here"}}}
	if fields.ContextID != "" {
		reply["context_id"] = fields.ContextID
	}
	body, err := json.MarshalIndent(reply, "", "  ")
	if err != nil {
		return "", err
	}
	return "```a2a-reply\n" + string(body) + "\n```", nil
}

type replyCorrection struct {
	Attachment replyAttachment
	Message    awid.InboxMessage
	Refusal    *replyBindingRefusal
}

// refuseConversationReply preserves every task and notifies the known target
// in its original mail conversation. Repeated polling sends one correction.
func (b *MailBridge) refuseConversationReply(ctx context.Context, input replyCorrection) error {
	thread, msg := input.Attachment.Thread, input.Message
	if !b.markRejectedReply(input) {
		return nil
	}
	b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentitySnapshot()), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(AuditDenied), Code: string(input.Refusal.Code), VerificationTier: string(msg.VerificationStatus)})
	forms := make([]string, 0, len(input.Attachment.Candidates))
	for _, candidate := range input.Attachment.Candidates {
		form, err := questionReplyForm(questionReplyFields{TaskID: candidate.TaskID, ContextID: candidate.ContextID})
		if err != nil {
			return errors.Join(input.Refusal, fmt.Errorf("prepare A2A question correction: %w", err))
		}
		forms = append(forms, "\n\nFor task "+candidate.TaskID+":\n"+form)
	}
	refusal := fmt.Errorf("%s%s\n\nNo task was changed. Choose the form for the intended task, replace the question text, and send it in the original conversation.", input.Refusal.Error(), strings.Join(forms, ""))
	request := &awid.SendMessageRequest{ConversationID: thread.ConversationID, ToAddress: thread.TargetAddress, ToDID: thread.TargetDID, ToStableID: thread.TargetStableID, Subject: "A2A reply needs binding", Body: refusal.Error(), ContentMode: awid.ContentModeLegacyPlaintextV1, Priority: awid.PriorityNormal}
	// A verified sender may use its current signing key under the bound stable
	// identity. Unverified input cannot select the correction's recipient key.
	if b.requireVerifiedReplies && msg.FromDID != "" {
		request.ToDID = msg.FromDID
	}
	response, err := b.sendForRoute(ctx, thread.RouteID, thread.TargetAddress, request)
	if err != nil {
		b.recordAudit(AuditEvent{Stage: "reply_ingest", RequestID: thread.RequestID, RouteID: thread.RouteID, TaskID: thread.TaskID, CallerScopeClass: callerScopeClass(thread.CallerScope), GatewayIdentityHash: auditHash(b.gatewayIdentitySnapshot()), TargetAddressHash: auditHash(thread.TargetAddress), Outcome: string(AuditError), Code: "reply_correction_failed", VerificationTier: string(msg.VerificationStatus)})
		return errors.Join(refusal, fmt.Errorf("A2A reply correction could not reach the target: %w. Contact the target agent with the task ID and binding instructions.", err))
	}
	if response != nil && response.MessageID != "" {
		b.mu.Lock()
		for _, candidate := range input.Attachment.Candidates {
			b.markSeenLocked(candidate.TaskID, response.MessageID)
		}
		b.mu.Unlock()
	}
	return refusal
}

// seenConversationMessage skips known sent/processed messages before parsing;
// correction mail can contain a separate fenced example for each live task.
func (b *MailBridge) seenConversationMessage(msg awid.InboxMessage) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := replyMessageKey(msg)
	for _, thread := range b.threads {
		if thread.ConversationID == msg.ConversationID && thread.SeenMessages[key] {
			return true
		}
	}
	return false
}

func replyMessageKey(msg awid.InboxMessage) string {
	if msg.MessageID != "" {
		return msg.MessageID
	}
	return "reply:" + auditHash(msg.SignedPayload+msg.Body)
}

func (b *MailBridge) markRejectedReply(input replyCorrection) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	key := replyMessageKey(input.Message)
	for _, candidate := range input.Attachment.Candidates {
		if thread := b.threads[candidate.TaskID]; thread != nil && thread.SeenMessages[key] {
			return false
		}
	}
	for _, candidate := range input.Attachment.Candidates {
		b.markSeenLocked(candidate.TaskID, key)
	}
	return true
}
