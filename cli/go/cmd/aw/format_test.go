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
				Participants:  []string{"carol"},
				LastFrom:      "carol",
				UnreadCount:   1,
				SenderWaiting: true,
			},
		},
	}

	out := formatChatPending(result)
	if !strings.Contains(out, `aw chat open carol`) {
		t.Fatalf("direct pending output should keep open hint:\n%s", out)
	}
}
