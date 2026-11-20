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
		name      string
		result    *chat.SendResult
		wantReply bool
		wantTail  string
	}{
		{name: "replied", result: &chat.SendResult{Status: "replied", TargetAgent: "carol", Reply: "done", Events: []chat.Event{other, receipt, reply}}, wantReply: true},
		{name: "timeout", result: &chat.SendResult{Status: "timeout", TargetAgent: "carol", WaitedSeconds: 5, Events: []chat.Event{other, receipt}}, wantTail: "Waited 5s — no reply"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := formatChatSend(tc.result)
			also, rest, found := strings.Cut(out, "\n\n")
			if !found || !strings.HasPrefix(also, "Also received:\n") {
				t.Fatalf("output does not open with the presented messages:\n%s", out)
			}
			// The presented block lists messages only: the read receipt is not one.
			if lines := strings.Split(strings.TrimPrefix(also, "Also received:\n"), "\n"); len(lines) != 1 || lines[0] != "  myco/dave: fyi: the build is red" {
				t.Fatalf("presented block = %q, want only dave's message", lines)
			}
			replyBlock := "Chat from: myco/carol\nBody: done"
			if got := strings.Count(rest, replyBlock); tc.wantReply && got != 1 || !tc.wantReply && got != 0 {
				t.Fatalf("reply shown %d times, want reply=%v:\n%s", got, tc.wantReply, out)
			}
			if strings.Count(out, "done") != strings.Count(rest, replyBlock) {
				t.Fatalf("the reply text appears outside its one reply block:\n%s", out)
			}
			if tc.wantTail != "" && !strings.Contains(rest, tc.wantTail) {
				t.Fatalf("output does not say %q:\n%s", tc.wantTail, out)
			}
		})
	}
}
