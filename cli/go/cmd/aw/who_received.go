package main

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/awebai/aw/awid"
	"strings"
)

type whoMessages interface {
	Inbox(context.Context, awid.InboxParams) (*awid.InboxResponse, error)
	Message(context.Context, string) (*awid.InboxResponse, error)
	ChatHistory(context.Context, awid.ChatHistoryParams) (*awid.ChatHistoryResponse, error)
	ListConversationsWithParams(context.Context, awid.ConversationListParams) (*awid.ConversationsResponse, error)
}

func whoSenderMatches(message awid.InboxMessage, target string) bool {
	if strings.HasPrefix(target, "did:") {
		return message.FromStableID == target || message.FromDID == target
	}
	if strings.Contains(target, "/") {
		return strings.EqualFold(message.FromAddress, target)
	}
	return message.FromAlias == target
}

func whoChatMessage(message awid.ChatMessage) awid.InboxMessage {
	return awid.InboxMessage{MessageID: message.MessageID, FromAlias: message.FromAgent, FromAddress: message.FromAddress,
		FromDID: message.FromDID, FromStableID: message.FromStableID, IDChain: message.IDChain,
		VerificationStatus: message.VerificationStatus, SignedPayload: message.SignedPayload, ContentMode: message.ContentMode}
}

func findWhoSender(ctx context.Context, reader whoMessages, target, messageID, sessionID string) (awid.InboxMessage, error) {
	match := func(messages []awid.InboxMessage) (awid.InboxMessage, bool) {
		for _, message := range messages {
			if (target == "" || whoSenderMatches(message, target)) && (messageID == "" || message.MessageID == messageID) {
				return message, true
			}
		}
		return awid.InboxMessage{}, false
	}
	chat := func(sessionID string) (awid.InboxMessage, bool, error) {
		history, err := reader.ChatHistory(ctx, awid.ChatHistoryParams{SessionID: sessionID, MessageID: messageID, Limit: 1000})
		if err != nil {
			return awid.InboxMessage{}, false, err
		}
		messages := make([]awid.InboxMessage, 0, len(history.Messages))
		for _, message := range history.Messages {
			messages = append(messages, whoChatMessage(message))
		}
		// Chat history is chronological; choose the newest matching presentation.
		for i, j := 0, len(messages)-1; i < j; i, j = i+1, j-1 {
			messages[i], messages[j] = messages[j], messages[i]
		}
		message, ok := match(messages)
		return message, ok, nil
	}
	if sessionID != "" {
		message, ok, err := chat(sessionID)
		if err != nil {
			return message, err
		}
		if ok {
			return message, nil
		}
	} else if messageID != "" {
		response, err := reader.Message(ctx, messageID)
		if err != nil {
			return awid.InboxMessage{}, err
		}
		if message, ok := match(response.Messages); ok {
			return message, nil
		}
	} else {
		cursor := ""
		seen := map[string]bool{}
		for {
			response, err := reader.Inbox(ctx, awid.InboxParams{Limit: 100, Cursor: cursor})
			if err != nil {
				return awid.InboxMessage{}, err
			}
			if message, ok := match(response.Messages); ok {
				return message, nil
			}
			if !response.HasMore {
				break
			}
			cursor = response.NextCursor
			if cursor == "" || seen[cursor] {
				return awid.InboxMessage{}, fmt.Errorf("incomplete inbox pagination; select an exact --message-id")
			}
			seen[cursor] = true
		}
		cursor = ""
		seen = map[string]bool{}
		for {
			conversations, err := reader.ListConversationsWithParams(ctx, awid.ConversationListParams{ConversationType: "chat", Limit: 100, Cursor: cursor})
			if err != nil {
				return awid.InboxMessage{}, err
			}
			for _, conversation := range conversations.Conversations {
				message, ok, err := chat(conversation.ConversationID)
				if err != nil {
					return awid.InboxMessage{}, err
				}
				if ok {
					return message, nil
				}
			}
			cursor = conversations.NextCursor
			if cursor == "" {
				break
			}
			if seen[cursor] {
				return awid.InboxMessage{}, fmt.Errorf("incomplete chat pagination; select --session-id and --message-id")
			}
			seen[cursor] = true
		}
	}
	return awid.InboxMessage{}, fmt.Errorf("no received message from %q found; use --message-id or --session-id for an exact received message", target)
}

func executeWhoReceived(ctx context.Context, message awid.InboxMessage, opts whoOptions) (whoOutput, error) {
	subject := awid.IDChainSubject{ID: message.FromStableID, DIDKey: message.FromDID}
	if subject.ID == "" {
		subject.ID = subject.DIDKey
	}
	authenticated := message.VerificationStatus == awid.Verified || message.VerificationStatus == awid.VerifiedLegacy || message.VerificationStatus == awid.VerifiedCustodial
	// Projection metadata may not replace the sender in independently signed bytes.
	if message.SignedPayload != "" && message.ContentMode != awid.ContentModeEncryptedV2 {
		var signed struct {
			FromDID      string `json:"from_did"`
			FromStableID string `json:"from_stable_id"`
		}
		if json.Unmarshal([]byte(message.SignedPayload), &signed) != nil || signed.FromDID != subject.DIDKey || (signed.FromStableID != "" && signed.FromStableID != message.FromStableID) {
			authenticated = false
		}
	}
	if !authenticated {
		invalid := false
		return whoOutput{ID: subject.ID, IDChainResult: awid.IDChainResult{Outcome: "unknown", Reason: "subject_mismatch", IdentityValid: &invalid}}, nil
	}
	domain := ""
	bundle := message.IDChain
	if bundle != nil {
		// The shared planner validates size, shape and signatures before extraction.
		plan, err := awid.IDStatusRequest(bundle, subject, "")
		if err != nil {
			return whoOutput{ID: subject.ID, IDChainResult: awid.VerifyIDChain(bundle, subject, nil, "")}, nil
		}
		domain, _ = plan["domain"].(string)
	} else if strings.HasPrefix(subject.ID, "did:aw:") && opts.ReceivedEnrollment != nil {
		enrollment := opts.ReceivedEnrollment(ctx, subject.ID, subject.DIDKey)
		if enrollment.State == "not_enrolled" {
			return whoOutput{ID: subject.ID, IDChainResult: awid.IDChainResult{Outcome: "unknown", Reason: "unregistered_identity"}}, nil
		}
		if enrollment.State == "enrolled" && enrollment.Domain != nil {
			domain = *enrollment.Domain
		}
	}
	return verifyWhoPresentation(ctx, subject, bundle, domain, opts)
}
