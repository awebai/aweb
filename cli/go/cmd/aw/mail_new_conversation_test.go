package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestAwMailSendNewConversation(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	pub, priv, _ := ed25519.GenerateKey(nil)
	peerPub, _, _ := ed25519.GenerateKey(nil)
	self, peer := awid.ComputeDIDKey(pub), awid.ComputeDIDKey(peerPub)
	stable := awid.ComputeStableID(peerPub)
	const old = "11111111-1111-4111-8111-111111111111"
	seen := map[string]bool{}
	for _, tc := range []struct {
		name, flag, target                  string
		omit, mismatch, conflict, transport bool
		status                              int
	}{
		{name: "alias", flag: "--to", target: "alice"},
		{name: "did_key", flag: "--to-did", target: peer},
		{name: "stable_id", flag: "--to-did", target: stable},
		{name: "address", flag: "--to-address", target: "test.local/alice"},
		{name: "old_server_reuses", flag: "--to", target: "alice", mismatch: true},
		{name: "old_server_rejects_field", flag: "--to", target: "alice", status: 422},
		{name: "expired_no_retry", flag: "--to", target: "alice", status: 403},
		{name: "unavailable_no_retry", flag: "--to", target: "alice", status: 503},
		{name: "lost_response_no_retry", flag: "--to", target: "alice", transport: true},
		{name: "conflicting_flags", flag: "--to", target: "alice", conflict: true},
		{name: "omitted_preserves_lookup", flag: "--to", target: "alice", omit: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var sent []awid.SendMessageRequest
			lookups, inboxes, calls := 0, 0, 0
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				defer mu.Unlock()
				calls++
				switch r.URL.Path {
				case "/v1/agents":
					_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "devteam:test.local", Agents: []awid.AgentView{{AgentID: "alice-agent", Alias: "alice", DIDKey: peer, DIDAW: stable, Address: "test.local/alice"}}})
				case "/v1/conversations":
					lookups++
					http.NotFound(w, r) // Expose the legacy inbox fallback if lookup runs.
				case "/v1/messages/inbox":
					inboxes++
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{{ConversationID: old, FromDID: peer, ToDID: self, CreatedAt: "2026-10-01T00:00:00Z"}}})
				case "/v1/messages":
					var req awid.SendMessageRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
						w.WriteHeader(400)
						return
					}
					sent = append(sent, req)
					if tc.transport {
						conn, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
						} else {
							_ = conn.Close()
						}
						return
					}
					if tc.status != 0 {
						w.WriteHeader(tc.status)
						_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Conversation is expired"})
						return
					}
					id := req.ConversationID
					if tc.mismatch {
						id = old
					}
					_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: req.MessageID, ConversationID: id, Status: "delivered"})
				case "/v1/agents/heartbeat":
					_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			home := t.TempDir()
			writeSelectionFixtureForTest(t, home, testSelectionFixture{AwebURL: server.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: self, Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: priv, CreatedAt: "2026-05-02T00:00:00Z"})
			args := []string{"mail", "send", tc.flag, tc.target, "--body", "nonce", "--json"}
			if !tc.omit {
				args = append(args, "--new-conversation")
			}
			if tc.conflict {
				args = append(args, "--conversation-id", old)
			}
			run := exec.CommandContext(ctx, bin, args...)
			run.Dir = home
			run.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL, "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
			var stdout, stderr bytes.Buffer
			run.Stdout = &stdout
			run.Stderr = &stderr
			err := run.Run()
			mu.Lock()
			defer mu.Unlock()
			wantFailure := tc.mismatch || tc.status != 0 || tc.conflict || tc.transport || tc.name == "stable_id"
			if (err != nil) != wantFailure {
				t.Fatalf("err=%v stdout=%s stderr=%s", err, &stdout, &stderr)
			}
			if tc.conflict {
				if calls != 0 || !strings.Contains(stderr.String(), "cannot be combined") {
					t.Fatalf("flag conflict had effects: calls=%d stderr=%s", calls, &stderr)
				}
				return
			}
			if !tc.omit && (lookups != 0 || inboxes != 0) {
				t.Fatalf("fresh send read conversations=%d inbox=%d", lookups, inboxes)
			}
			if tc.omit && (lookups == 0 || inboxes == 0) {
				t.Fatalf("omission lost old lookup/fallback: %d/%d", lookups, inboxes)
			}
			if tc.name == "stable_id" {
				// A fresh UUID is not evidence of a stored route. Preserve the
				// existing refusal of bare did:aw first-contact rather than using
				// the continuation-only binding exemption to force a send.
				if len(sent) != 0 || !strings.Contains(stderr.String(), "bare did:aw first-contact is unsupported") {
					t.Fatalf("stable ID authority changed: posts=%d stderr=%s", len(sent), &stderr)
				}
				return
			}
			if len(sent) != 1 {
				t.Fatalf("send count=%d, want one; stderr=%s", len(sent), &stderr)
			}
			req := sent[0]
			if req.NewConversation == tc.omit {
				t.Fatalf("new_conversation=%v omit=%v", req.NewConversation, tc.omit)
			}
			if !tc.omit {
				if req.ConversationID == "" || req.ConversationID == old || seen[req.ConversationID] {
					t.Fatalf("not fresh: %q", req.ConversationID)
				}
				seen[req.ConversationID] = true
			}
			sig, e := base64.RawStdEncoding.DecodeString(req.Signature)
			if e != nil || !ed25519.Verify(pub, []byte(req.SignedPayload), sig) {
				t.Fatal("invalid signature")
			}
			var signed map[string]any
			if e = json.Unmarshal([]byte(req.SignedPayload), &signed); e != nil {
				t.Fatal(e)
			}
			if signed["conversation_id"] != req.ConversationID || signed["body"] != "nonce" || signed["message_id"] != req.MessageID {
				t.Fatalf("signed fields lost: %+v", signed)
			}
			if _, ok := signed["new_conversation"]; ok {
				t.Fatal("wire flag changed signature format")
			}
			if tc.mismatch && !strings.Contains(stderr.String(), "server does not support new conversations") {
				t.Fatalf("no compatibility error: %s", &stderr)
			}
			if !wantFailure {
				var result awid.SendMessageResponse
				if e := json.Unmarshal(stdout.Bytes(), &result); e != nil {
					t.Fatalf("invalid JSON: %s", &stdout)
				}
				if result.MessageID != req.MessageID || result.ConversationID != req.ConversationID {
					t.Fatalf("wrong returned IDs: %+v", result)
				}
			} else if stdout.Len() != 0 {
				t.Fatalf("failure reported success: %s", &stdout)
			}
		})
	}
}
