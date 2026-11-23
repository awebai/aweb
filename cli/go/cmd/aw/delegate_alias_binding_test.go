package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// bd and gc mail to a bare teammate name follow aw mail send's convention
// (docs/beads-mail-delegate.md:153-156, docs/gascity-mail-provider.md:192-196):
// the team's agent list confirms the name, the signature binds the member it
// names, and a failed lookup refuses with nothing sent.
func TestDelegateMailToAnAliasSignsTheMemberTheAgentListConfirms(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)

	for _, tc := range []struct {
		name, delegate string
		agentListFails bool
	}{
		{name: "bd", delegate: "beads-mail"},
		{name: "gc", delegate: "gc-mail"},
		{name: "bd, agent list fails", delegate: "beads-mail", agentListFails: true},
		{name: "gc, agent list fails", delegate: "gc-mail", agentListFails: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selfPub, selfKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			selfDID, selfStable := awid.ComputeDIDKey(selfPub), awid.ComputeStableID(selfPub)
			juanPub, _, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			juanDID, juanStable := awid.ComputeDIDKey(juanPub), awid.ComputeStableID(juanPub)

			var posted []map[string]any
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.URL.Path == "/v1/agents" && tc.agentListFails:
					http.Error(w, "agent list unavailable", http.StatusServiceUnavailable)
				case r.URL.Path == "/v1/agents":
					_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "backend:acme.com", Agents: []awid.AgentView{{AgentID: "juan-agent", Alias: "juan", DIDKey: juanDID, DIDAW: juanStable}}})
				case r.URL.Path == "/v1/messages" && r.Method == http.MethodPost:
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					posted = append(posted, body)
					_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "m1", ConversationID: body["conversation_id"].(string), Status: "delivered", DeliveredAt: "2026-11-18T00:00:00Z"})
				case r.URL.Path == "/v1/agents/heartbeat":
					w.WriteHeader(http.StatusOK)
				default:
					http.NotFound(w, r)
				}
			}))

			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(dir), selfKey); err != nil {
				t.Fatal(err)
			}
			writeIdentityForTest(t, dir, awconfig.WorktreeIdentity{DID: selfDID, StableID: selfStable, Address: "acme.com/ada", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, CreatedAt: "2026-11-18T00:00:00Z"})
			writeTeamCertFixturesForTest(t, dir, server.URL, selfDID, selfStable, []teamCertFixture{{TeamID: "backend:acme.com", Alias: "ada", WorkspaceID: "ws-ada", Address: "acme.com/ada"}})
			for _, marker := range []string{".beads", ".gc"} {
				if err := os.MkdirAll(filepath.Join(dir, marker), 0o700); err != nil {
					t.Fatal(err)
				}
			}

			args := []string{tc.delegate, "send", "juan"}
			var stdin []byte
			if tc.delegate == "beads-mail" {
				args = append(args, "-s", "hello", "-m", "body")
			} else {
				stdin = gcExecSendInput("ada", "hello", "body")
			}
			run := exec.CommandContext(ctx, bin, args...)
			run.Env = append(testCommandEnv(dir), "AWID_REGISTRY_URL="+newRegistryWithoutAddressesForTest(t), "GC_CITY="+dir)
			run.Dir = dir
			run.Stdin = bytes.NewReader(stdin)
			out, err := run.CombinedOutput()

			if tc.agentListFails {
				if err == nil || !strings.Contains(string(out), `cannot confirm recipient "juan": agent list lookup failed`) || len(posted) != 0 {
					t.Fatalf("err=%v posted=%d out=%s", err, len(posted), out)
				}
				return
			}
			if err != nil || len(posted) != 1 {
				t.Fatalf("err=%v posted=%d out=%s", err, len(posted), out)
			}
			var signed map[string]any
			if err := json.Unmarshal([]byte(posted[0]["signed_payload"].(string)), &signed); err != nil {
				t.Fatal(err)
			}
			if posted[0]["to_alias"] != "juan" || signed["to_did"] != juanDID || signed["to_stable_id"] != juanStable {
				t.Fatalf("to_alias=%v signed to_did=%v to_stable_id=%v, want juan %s %s", posted[0]["to_alias"], signed["to_did"], signed["to_stable_id"], juanDID, juanStable)
			}
			if _, ok := posted[0]["to_did"]; ok {
				t.Fatalf("the confirmed binding leaked into the routing selectors: %v", posted[0])
			}
		})
	}
}
