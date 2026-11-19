package main

import (
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
)

// Every message a wait presents is marked read, so text output shows every
// one of them, not only the reply: whatever ended the wait.
func TestFormatChatSendShowsEveryMessageTheWaitPresented(t *testing.T) {
	other := chat.Event{Type: "message", MessageID: "m1", FromAgent: "dave", FromAddress: "myco/dave", Body: "fyi: the build is red", VerificationStatus: awid.Verified}
	reply := chat.Event{Type: "message", MessageID: "m2", FromAgent: "carol", FromAddress: "myco/carol", Body: "done", VerificationStatus: awid.Verified}
	receipt := chat.Event{Type: "read_receipt", MessageID: "m3", FromAgent: "carol"}
	for _, tc := range []struct {
		name   string
		result *chat.SendResult
	}{
		{name: "replied", result: &chat.SendResult{Status: "replied", TargetAgent: "carol", Reply: "done", Events: []chat.Event{other, receipt, reply}}},
		{name: "timeout", result: &chat.SendResult{Status: "timeout", TargetAgent: "carol", WaitedSeconds: 5, Events: []chat.Event{other, receipt}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := formatChatSend(tc.result)
			if !strings.Contains(out, "myco/dave: fyi: the build is red") {
				t.Fatalf("output omits a presented message:\n%s", out)
			}
			if strings.Count(out, "done") > 1 {
				t.Fatalf("the reply is shown twice:\n%s", out)
			}
		})
	}
}
