package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// aw mail send to a recipient always starts a new thread: a fresh signed
// conversation ID with new_conversation set, and no conversation index or
// inbox read. Continuing is by --conversation-id (or aw mail reply), which
// names no recipient and keeps the conversation's title.
func TestAwMailSendToStartsANewThread(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")
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
		name, flag, target                             string
		mismatch, conflict, transport, noSubject, cont bool
		subjectOnCont, text                            bool
		status                                         int
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
		{name: "recipient_and_conversation", flag: "--to", target: "alice", conflict: true},
		{name: "recipient_without_subject", flag: "--to", target: "alice", noSubject: true},
		{name: "address_without_subject", flag: "--to-address", target: "test.local/alice", noSubject: true},
		{name: "continuation", flag: "--conversation-id", target: old, cont: true},
		{name: "continuation_with_subject", flag: "--conversation-id", target: old, cont: true, subjectOnCont: true},
		{name: "alias_text", flag: "--to", target: "alice", text: true},
		{name: "continuation_text", flag: "--conversation-id", target: old, cont: true, text: true},
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
				case "/v1/messages/conversations/" + old:
					// A continuation reads its own conversation to sign its
					// recipient; this fixture has none on record.
					http.NotFound(w, r)
				default:
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			home := t.TempDir()
			writeSelectionFixtureForTest(t, home, testSelectionFixture{AwebURL: server.URL, TeamID: "devteam:test.local", Alias: "gsk", WorkspaceID: "workspace-1", DID: self, Address: "test.local/gsk", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, SigningKey: priv, CreatedAt: "2026-05-02T00:00:00Z"})
			args := []string{"mail", "send", tc.flag, tc.target, "--body", "nonce"}
			if !tc.text {
				args = append(args, "--json")
			}
			if (!tc.cont && !tc.noSubject) || tc.subjectOnCont {
				args = append(args, "--subject", "Status")
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
			wantFailure := tc.mismatch || tc.status != 0 || tc.conflict || tc.transport || tc.noSubject || tc.subjectOnCont || tc.name == "stable_id"
			if (err != nil) != wantFailure {
				t.Fatalf("err=%v stdout=%s stderr=%s", err, &stdout, &stderr)
			}
			refusals := map[bool]string{
				tc.conflict:      "cannot be combined",
				tc.noSubject:     "A new thread needs a title: add --subject",
				tc.subjectOnCont: "A conversation's title is fixed.",
			}
			if want := refusals[true]; want != "" {
				if exitCode(err) != 2 || calls != 0 || !strings.Contains(stderr.String(), want) {
					t.Fatalf("refusal had effects or wrong text: exit=%d calls=%d stderr=%s", exitCode(err), calls, &stderr)
				}
				return
			}
			// Only a continuation reads conversations, and only its own.
			if !tc.cont && (lookups != 0 || inboxes != 0) {
				t.Fatalf("new thread read conversations=%d inbox=%d", lookups, inboxes)
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
			if req.NewConversation == tc.cont {
				t.Fatalf("new_conversation=%v for continuation=%v", req.NewConversation, tc.cont)
			}
			if tc.cont {
				if req.ConversationID != old || req.ToAlias != "" || req.ToDID != "" || req.ToStableID != "" || req.ToAddress != "" || req.Subject != "" {
					t.Fatalf("continuation must name only its conversation: %+v", req)
				}
			} else {
				if req.ConversationID == "" || req.ConversationID == old || seen[req.ConversationID] || req.Subject != "Status" {
					t.Fatalf("not a fresh titled thread: %+v", req)
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
			if tc.text {
				// The text result says whether the send started a thread.
				want := fmt.Sprintf("Started a new thread with alice: \"Status\" (conversation_id=%s, message_id=%s)\n", req.ConversationID, req.MessageID)
				if tc.cont {
					want = fmt.Sprintf("Sent mail in conversation %s (message_id=%s)\n", old, req.MessageID)
				}
				if stdout.String() != want {
					t.Fatalf("text result %q, want %q", stdout.String(), want)
				}
				return
			}
			if !wantFailure {
				var result awid.SendMessageResponse
				if e := json.Unmarshal(stdout.Bytes(), &result); e != nil {
					t.Fatalf("invalid JSON: %s", &stdout)
				}
				if result.MessageID != req.MessageID || result.ConversationID != req.ConversationID {
					t.Fatalf("wrong returned IDs: %+v", result)
				}
			} else {
				// A --json failure's stdout is its error envelope alone,
				// never a send result.
				assertOneJSONDocument(t, stdout.Bytes())
				var envelope struct {
					Error     *struct{ Code string } `json:"error"`
					MessageID string                 `json:"message_id"`
				}
				if e := json.Unmarshal(stdout.Bytes(), &envelope); e != nil || envelope.Error == nil || envelope.Error.Code == "" || envelope.MessageID != "" {
					t.Fatalf("failure reported success: %s", &stdout)
				}
			}
		})
	}
}

// sentConversationIDForTest is the conversation ID a decoded send request
// names; a fixture answers a new thread with it.
func sentConversationIDForTest(body map[string]any) string {
	id, _ := body["conversation_id"].(string)
	return id
}
