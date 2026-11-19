package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/chat"
	"github.com/spf13/cobra"
)

// A bare alias is confirmed in the selected team before anything is sent. When
// the lookup that would confirm it fails (the team's agent list, or the
// registry's live roster for a name the agent list lacks), mail and chat
// refuse with the source that failed and post nothing; a failed lookup is
// never read as "no such member".
func TestAliasSendRefusesWhenTheConfirmingLookupFails(t *testing.T) {
	t.Setenv("AWEB_IDENTITY_HOME", "")
	t.Setenv("AW_NO_UPDATE_CHECK", "1")
	resetMailSendGlobalsForLiveRosterTest(t)
	for _, tc := range []struct {
		name, kind, failing string
	}{
		{name: "mail, agent list fails", kind: "mail", failing: "agent list"},
		{name: "mail, live roster fails", kind: "mail", failing: "live roster"},
		{name: "chat, agent list fails", kind: "chat", failing: "agent list"},
		{name: "chat, live roster fails", kind: "chat", failing: "live roster"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			t.Chdir(root)
			selfPub, selfKey, _ := ed25519.GenerateKey(nil)
			selfDID := awid.ComputeDIDKey(selfPub)
			posts := 0
			api := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/agents" && tc.failing == "agent list":
					http.Error(w, "agent list unavailable", http.StatusServiceUnavailable)
				case r.URL.Path == "/v1/agents":
					_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "backend:demo"})
				case r.Method == http.MethodPost:
					posts++
					http.Error(w, "must not send", http.StatusTeapot)
				default:
					_ = json.NewEncoder(w).Encode(map[string]any{})
				}
			}))
			registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				http.Error(w, "registry unavailable", http.StatusServiceUnavailable)
			}))
			t.Setenv("AWID_REGISTRY_URL", registry.URL)
			writeSelectionFixtureForTest(t, root, testSelectionFixture{AwebURL: api.URL, TeamID: "backend:demo", Alias: "ada", WorkspaceID: "ada-workspace", DID: selfDID, StableID: awid.ComputeStableID(selfPub), Address: "demo/ada", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: registry.URL, SigningKey: selfKey})

			var err error
			if tc.kind == "mail" {
				mailSendTo, mailSendSubject, mailSendBody = "juan", "team mail", "hello"
				cmd := &cobra.Command{}
				cmd.Flags().Bool("e2ee", false, "")
				err = mailSendCmd.RunE(cmd, nil)
			} else {
				_, _, err = chatSend(context.Background(), "juan", "hello", chat.SendOptions{})
			}
			want := `cannot confirm recipient "juan": ` + tc.failing + " lookup failed"
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("err=%v, want %q", err, want)
			}
			if posts != 0 {
				t.Fatalf("%d sends posted after a failed lookup", posts)
			}
		})
	}
}
