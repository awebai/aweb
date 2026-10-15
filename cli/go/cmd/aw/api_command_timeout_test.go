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

	"github.com/awebai/aw/awid"
)

func TestMessagingCommandsRespectAPITimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	bin := filepath.Join(t.TempDir(), "aw")
	buildAwBinary(t, ctx, bin)
	peerPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, operation := range []struct {
		name string
		args []string
		path string
	}{
		{"mail_send", []string{"mail", "send", "--to-did", awid.ComputeDIDKey(peerPub), "--new-conversation", "--body", "hello"}, "/v1/messages"},
		{"mail_inbox", []string{"mail", "inbox"}, "/v1/messages/inbox"},
		{"mail_ack", []string{"mail", "ack", "msg-in"}, "/v1/messages/msg-in/ack"},
		{"chat_send", []string{"chat", "send", "--session-id", "session-1", "--body", "hello"}, "/v1/chat/sessions/session-1/messages"},
	} {
		for _, budget := range []struct {
			name, timeout string
			delay         time.Duration
			wantErr       bool
		}{
			{"default", "", 11 * time.Second, false},
			{"configured", "15s", 11 * time.Second, false},
			{"short", "150ms", time.Second, true},
		} {
			t.Run(operation.name+"/"+budget.name, func(t *testing.T) {
				t.Parallel()
				var calls, completed atomic.Int32
				server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if r.URL.Path == "/v1/agents/heartbeat" {
						w.WriteHeader(http.StatusOK)
						return
					}
					if operation.name == "chat_send" && r.URL.Path == "/v1/chat/sessions" {
						_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{}})
						return
					}
					if r.URL.Path != operation.path {
						t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
						http.NotFound(w, r)
						return
					}
					calls.Add(1)
					timer := time.NewTimer(budget.delay)
					defer timer.Stop()
					select {
					case <-r.Context().Done():
						return
					case <-timer.C:
					}
					completed.Add(1)
					switch operation.name {
					case "mail_send":
						var req awid.SendMessageRequest
						if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
							t.Error(err)
						}
						_ = json.NewEncoder(w).Encode(awid.SendMessageResponse{MessageID: "msg-out", ConversationID: req.ConversationID})
					case "mail_inbox":
						_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: []awid.InboxMessage{}})
					case "mail_ack":
						_ = json.NewEncoder(w).Encode(awid.AckResponse{MessageID: "msg-in"})
					case "chat_send":
						_ = json.NewEncoder(w).Encode(awid.ChatSendMessageResponse{MessageID: "chat-out", Delivered: true})
					}
				}))
				defer server.Close()
				home := t.TempDir()
				writeDefaultWorkspaceBindingForTest(t, home, server.URL)
				runCtx, stop := context.WithTimeout(context.Background(), 25*time.Second)
				defer stop()
				command := exec.CommandContext(runCtx, bin, operation.args...)
				command.Dir = home
				command.Env = append(testCommandEnv(home), "AWEB_HTTP_TIMEOUT="+budget.timeout, "AWID_REGISTRY_URL=http://127.0.0.1:1")
				out, err := command.CombinedOutput()
				if budget.wantErr {
					if err == nil || (!strings.Contains(strings.ToLower(string(out)), "timeout") && !strings.Contains(string(out), "deadline exceeded")) {
						t.Fatalf("short API budget must reject the delayed request: err=%v output=%s", err, out)
					}
					if completed.Load() != 0 {
						t.Fatal("the short-budget request completed despite cancellation")
					}
				} else if err != nil {
					t.Fatalf("%s must allow a request within its API budget: err=%v output=%s", operation.name, err, out)
				} else if completed.Load() != 1 {
					t.Fatalf("completed=%d, want one successful operation", completed.Load())
				}
				if calls.Load() != 1 {
					t.Fatalf("calls=%d, want exactly one request, without a retry", calls.Load())
				}
			})
		}
	}
}
