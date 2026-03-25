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

