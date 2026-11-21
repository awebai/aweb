package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Delegate mail shows what verification concluded about a received message,
// through the same tag rule as aw mail: the bd delegate after the sender, and
// every delegate in the local log.
func TestDelegateMailCarriesVerificationStatus(t *testing.T) {
	for _, tc := range []struct {
		status awid.VerificationStatus
		tag    string
	}{
		{status: awid.Verified, tag: ""},
		{status: awid.Failed, tag: " [VERIFICATION FAILED]"},
		{status: awid.IdentityMismatch, tag: " [IDENTITY MISMATCH]"},
		{status: "", tag: " [unverified]"},
	} {
		t.Run(string(tc.status), func(t *testing.T) {
			msg := &awid.InboxMessage{MessageID: "m1", ConversationID: "c1", FromAddress: "acme.com/mayor", FromDID: "did:key:z6Mkmayor", Subject: "s", Body: "b", VerificationStatus: tc.status}

			if got, want := beadsMailSenderLabel(beadsMailAddressMap{}, msg), "acme.com/mayor"+tc.tag; got != want {
				t.Fatalf("bd sender label=%q, want %q", got, want)
			}

			state := t.TempDir()
			t.Setenv("HOME", state)
			t.Setenv("XDG_STATE_HOME", state)
			sel := &awconfig.Selection{DID: "did:key:z6Mkreader"}
			delegateMailLogReceived(sel, msg)
			entries, err := readCommLog(filepath.Join(defaultLogsDir(), commLogNameForSelection(sel)+".jsonl"), 0)
			if err != nil || len(entries) != 1 {
				t.Fatalf("log entries=%+v err=%v", entries, err)
			}
			if entries[0].Verification != string(tc.status) {
				t.Fatalf("logged verification=%q, want %q", entries[0].Verification, tc.status)
			}
			if strings.TrimSpace(defaultLogsDir()) == "" || !strings.HasPrefix(defaultLogsDir(), state) {
				t.Fatalf("log dir %q is outside the test state dir", defaultLogsDir())
			}
		})
	}
}
