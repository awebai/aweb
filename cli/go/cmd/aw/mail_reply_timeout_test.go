package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestAwMailReplyRespectsAPITimeout(t *testing.T) {
	buildCtx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, buildCtx, bin)

	for _, tc := range []struct {
		name    string
		timeout string
		delay   time.Duration
		wantErr bool
	}{
		// Both reads exceed the old, hidden ten-second command deadline.
		{name: "default", delay: 11 * time.Second},
		{name: "configured", timeout: "15s", delay: 11 * time.Second},
		{name: "short_configured_deadline", timeout: "150ms", delay: time.Second, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			pub, priv, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			did := awid.ComputeDIDKey(pub)
			stableID := stableIDFromDidForTest(t, did)
			const conversationID = "66666666-6666-4666-8666-666666666666"
			var reads, sends, acks atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/agents/heartbeat":
					w.WriteHeader(http.StatusOK)
				case "/v1/messages/inbox":
					reads.Add(1)
					if r.URL.Query().Get("message_id") != "msg-in" {
						t.Error("reply did not fetch its exact source message")
					}
					timer := time.NewTimer(tc.delay)
					defer timer.Stop()
					select {
					case <-r.Context().Done():
						return
					case <-timer.C:
					}
					_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{{
						MessageID: "msg-in", ConversationID: conversationID,
						FromAddress: "otherco.example/bob", Subject: "hello", Body: "hi",
					}}})
				case "/v1/conversations":
					_ = json.NewEncoder(w).Encode(awid.ConversationsResponse{Conversations: []awid.ConversationItem{{
						ConversationType: "mail", ConversationID: conversationID,
						ParticipantDIDs:      []string{stableID, "did:aw:bob"},
						ParticipantAddresses: []string{"acme.com/alice", "otherco.example/bob"},
					}}})
				case "/v1/messages":
					sends.Add(1)
					var req awid.SendMessageRequest
					if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
						t.Error(err)
					}
					if req.ConversationID != conversationID || req.Body != "reply" {
						t.Error("reply lost its conversation or body")
					}
					_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-reply", ConversationID: conversationID})
				case "/v1/messages/msg-in/ack":
					acks.Add(1)
					_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: "msg-in"})
				default:
					t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
				}
			}))
			defer server.Close()
			home := t.TempDir()
			writeIdentityForTest(t, home, awconfig.WorktreeIdentity{
				DID: did, Address: "acme.com/alice", Custody: awid.CustodySelf,
				IdentityScope: awid.IdentityModeLocal, CreatedAt: "2026-05-02T00:00:00Z",
			})
			if err := awid.SaveSigningKey(filepath.Join(home, ".aw", "signing.key"), priv); err != nil {
				t.Fatal(err)
			}
			ctx, stop := context.WithTimeout(context.Background(), 25*time.Second)
			defer stop()
			cmd := exec.CommandContext(ctx, bin, "mail", "reply", "--plaintext", "msg-in", "--body", "reply")
			cmd.Dir = home
			cmd.Env = append(testCommandEnv(home), "AWEB_URL="+server.URL,
				"AWID_REGISTRY_URL=http://127.0.0.1:1", "AWEB_HTTP_TIMEOUT="+tc.timeout)
			out, err := cmd.CombinedOutput()
			if tc.wantErr {
				if err == nil || (!strings.Contains(string(out), "deadline exceeded") && !strings.Contains(string(out), "timeout")) {
					t.Fatalf("configured deadline did not refuse the slow read: err=%v output=%s", err, out)
				}
				if sends.Load() != 0 || acks.Load() != 0 {
					t.Fatal("timed-out source read must not send or acknowledge mail")
				}
			} else {
				if err != nil {
					t.Fatalf("reply must allow a source GET within its API timeout: err=%v output=%s", err, out)
				}
				if sends.Load() != 1 || acks.Load() != 1 {
					t.Fatalf("reply must send and acknowledge once: sends=%d acks=%d", sends.Load(), acks.Load())
				}
			}
			if reads.Load() != 1 {
				t.Fatalf("source reads=%d, want 1", reads.Load())
			}
		})
	}
}
