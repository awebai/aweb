package main

import (
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
)

func TestFormatChatSendUsesReplyMessageTagsNotReadReceipt(t *testing.T) {
	// Regression: send-and-wait can receive a read_receipt before the reply
	// message, and the read_receipt is typically unsigned/unverified. The
	// output should reflect the reply message's verification status, not the
	// read receipt's.
	result := &chat.SendResult{
		Status:      "replied",
		TargetAgent: "juan/merlin",
		Reply:       "hello",
		Events: []chat.Event{
			{
				Type:               "read_receipt",
				ReaderAlias:        "merlin",
				VerificationStatus: awid.Unverified,
			},
			{
				Type:               "message",
				FromAgent:          "juan/merlin",
				Body:               "hello",
				VerificationStatus: awid.Failed,
			},
		},
	}

	out := formatChatSend(result)
	if strings.Contains(out, "[unverified]") {
		t.Fatalf("output should not use read_receipt verification tag:\n%s", out)
	}
	if !strings.Contains(out, "[VERIFICATION FAILED]") {
		t.Fatalf("output should use reply message verification tag:\n%s", out)
	}
}

func TestFormatChatPendingOmitsOpenHintForGroupSession(t *testing.T) {
	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				Participants:  []string{"bob", "carol"},
				LastFrom:      "carol",
				UnreadCount:   1,
				SenderWaiting: true,
			},
		},
	}

	out := formatChatPending(result)
	if strings.Contains(out, `aw chat open carol`) {
		t.Fatalf("group pending output should not suggest ambiguous open hint:\n%s", out)
	}
}

func TestFormatChatPendingKeepsOpenHintForDirectSession(t *testing.T) {
	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				Participants:         []string{"carol"},
				ParticipantAddresses: []string{"otherco/carol"},
				LastFrom:             "carol",
				LastFromAddress:      "otherco/carol",
				UnreadCount:          1,
				SenderWaiting:        true,
			},
		},
	}

	out := formatChatPending(result)
	if !strings.Contains(out, `aw chat open otherco/carol`) {
		t.Fatalf("direct pending output should keep open hint:\n%s", out)
	}
}

func TestFormatMailInboxPrefersFromAddress(t *testing.T) {
	resp := &awid.InboxResponse{
		Messages: []awid.InboxMessage{
			{
				FromAlias:   "carol",
				FromAddress: "otherco/carol",
				Subject:     "hello",
				Body:        "world",
			},
		},
	}

	out := formatMailInbox(resp)
	if !strings.Contains(out, "- otherco/carol") {
		t.Fatalf("mail inbox should prefer address labels:\n%s", out)
	}
	if strings.Contains(out, "- carol") {
		t.Fatalf("mail inbox should not collapse to alias-only label:\n%s", out)
	}
}

func TestFormatMailInboxFallsBackToStableID(t *testing.T) {
	resp := &awid.InboxResponse{
		Messages: []awid.InboxMessage{
			{
				FromAlias:    "",
				FromAddress:  "",
				FromStableID: "did:aw:carol",
				Subject:      "hello",
				Body:         "world",
			},
		},
	}

	out := formatMailInbox(resp)
	if !strings.Contains(out, "- did:aw:carol") {
		t.Fatalf("mail inbox should preserve stable identity fallback:\n%s", out)
	}
}

func TestFormatChatPendingPrefersLastFromAddress(t *testing.T) {
	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				Participants:         []string{"carol"},
				ParticipantAddresses: []string{"otherco/carol"},
				LastFrom:             "carol",
				LastFromAddress:      "otherco/carol",
				UnreadCount:          1,
				SenderWaiting:        true,
			},
		},
	}

	out := formatChatPending(result)
	if !strings.Contains(out, "CHAT WAITING: otherco/carol") {
		t.Fatalf("pending output should prefer sender address:\n%s", out)
	}
	if strings.Contains(out, "CHAT WAITING: carol") {
		t.Fatalf("pending output should not use alias-only sender label:\n%s", out)
	}
}

func TestFormatChatPendingFallsBackToStableID(t *testing.T) {
	result := &chat.PendingResult{
		Pending: []chat.PendingConversation{
			{
				Participants:         []string{""},
				ParticipantDIDs:      []string{"did:aw:carol"},
				ParticipantAddresses: []string{""},
				LastFrom:             "",
				LastFromDID:          "did:aw:carol",
				LastFromAddress:      "",
				UnreadCount:          1,
				SenderWaiting:        true,
			},
		},
	}

	out := formatChatPending(result)
	if !strings.Contains(out, "CHAT WAITING: did:aw:carol") {
		t.Fatalf("pending output should preserve stable identity fallback:\n%s", out)
	}
	if !strings.Contains(out, `aw chat open did:aw:carol`) {
		t.Fatalf("pending output should use participant stable identity in direct-session open hint:\n%s", out)
	}
}

func TestFormatChatHistoryPrefersFromAddress(t *testing.T) {
	result := &chat.HistoryResult{
		Messages: []chat.Event{
			{
				Type:        "message",
				FromAgent:   "carol",
				FromAddress: "otherco/carol",
				Body:        "hello",
			},
		},
	}

	out := formatChatHistory(result)
	if !strings.Contains(out, "otherco/carol: hello") {
		t.Fatalf("chat history should prefer sender address:\n%s", out)
	}
	if strings.Contains(out, "\ncarol: hello") {
		t.Fatalf("chat history should not use alias-only sender label:\n%s", out)
	}
}

func TestFormatChatHistoryFallsBackToStableID(t *testing.T) {
	result := &chat.HistoryResult{
		Messages: []chat.Event{
			{
				Type:         "message",
				FromAgent:    "",
				FromAddress:  "",
				FromStableID: "did:aw:carol",
				Body:         "hello",
			},
		},
	}

	out := formatChatHistory(result)
	if !strings.Contains(out, "did:aw:carol: hello") {
		t.Fatalf("chat history should preserve stable identity fallback:\n%s", out)
	}
}

func TestFormatChatSendPrefersFromAddress(t *testing.T) {
	result := &chat.SendResult{
		Status:      "replied",
		TargetAgent: "carol",
		Reply:       "hello",
		Events: []chat.Event{
			{
				Type:        "message",
				FromAgent:   "carol",
				FromAddress: "otherco/carol",
				Body:        "hello",
			},
		},
	}

	out := formatChatSend(result)
	if !strings.Contains(out, "Chat from: otherco/carol") {
		t.Fatalf("chat send output should prefer sender address:\n%s", out)
	}
	if strings.Contains(out, "Chat from: carol") {
		t.Fatalf("chat send output should not use alias-only sender label:\n%s", out)
	}
}

func TestFormatChatSendFallsBackToStableID(t *testing.T) {
	result := &chat.SendResult{
		Status:      "replied",
		TargetAgent: "did:aw:carol",
		Reply:       "hello",
		Events: []chat.Event{
			{
				Type:         "message",
				FromAgent:    "",
				FromAddress:  "",
				FromStableID: "did:aw:carol",
				Body:         "hello",
			},
		},
	}

	out := formatChatSend(result)
	if !strings.Contains(out, "Chat from: did:aw:carol") {
		t.Fatalf("chat send output should preserve stable identity fallback:\n%s", out)
	}
}

func TestFormatChatSendPendingTreatsIdentityTargetReplyAsIncoming(t *testing.T) {
	result := &chat.SendResult{
		Status:      "pending",
		TargetAgent: "did:aw:carol",
		Reply:       "hello",
		Events: []chat.Event{
			{
				Type:        "message",
				FromAgent:   "carol",
				FromAddress: "otherco/carol",
				FromDID:     "did:aw:carol",
				Body:        "hello",
			},
		},
	}

	out := formatChatSend(result)
	if !strings.Contains(out, "Chat from: otherco/carol") {
		t.Fatalf("pending chat send output should treat identity target reply as incoming:\n%s", out)
	}
	if strings.Contains(out, "Chat to: did:aw:carol") {
		t.Fatalf("pending chat send output should not misclassify identity target reply as outgoing:\n%s", out)
	}
}
