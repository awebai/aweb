package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// Chat reads set up decryption the way mail reads do: a missing key is a
// warning and the read goes on (encrypted messages stay unreadable), and a
// key state that cannot be loaded refuses the read instead of being ignored.
func TestChatReadsReportDecryptionSetupLikeMail(t *testing.T) {
	t.Setenv("AWEB_IDENTITY_HOME", "")
	t.Setenv("AW_NO_UPDATE_CHECK", "1")
	for _, tc := range []struct {
		name, state string
		refuses     bool
	}{
		{name: "missing key state", state: ""},
		{name: "unreadable key state", state: "{not yaml: [", refuses: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			selfPub, selfKey, _ := ed25519.GenerateKey(nil)
			pendingReads := 0
			api := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/v1/chat/pending" {
					pendingReads++
				}
				_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
			}))
			writeSelectionFixtureForTest(t, root, testSelectionFixture{AwebURL: api.URL, TeamID: "backend:demo", Alias: "ada", WorkspaceID: "ada-workspace", DID: awid.ComputeDIDKey(selfPub), StableID: awid.ComputeStableID(selfPub), Address: "demo/ada", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, SigningKey: selfKey})
			if tc.state != "" {
				if err := os.WriteFile(awconfig.WorktreeEncryptionStatePath(root), []byte(tc.state), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var stderr bytes.Buffer
			cmd := &cobra.Command{}
			cmd.SetErr(&stderr)
			cmd.SetOut(&bytes.Buffer{})
			err := chatPendingCmd.RunE(cmd, nil)
			if tc.refuses {
				if err == nil || pendingReads != 0 {
					t.Fatalf("err=%v pending reads=%d, want a refusal before reading", err, pendingReads)
				}
				return
			}
			if err != nil || pendingReads != 1 {
				t.Fatalf("err=%v pending reads=%d", err, pendingReads)
			}
			if !strings.Contains(stderr.String(), "Warning: ") || !strings.Contains(stderr.String(), "no encryption key state found") {
				t.Fatalf("stderr=%q, want the missing-key warning", stderr.String())
			}
		})
	}
}
