package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestAwChatHistoryBySessionMessageIDJSON(t *testing.T) {
	t.Parallel()

	var sawHistory bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions/session-1/messages":
			sawHistory = true
			if r.URL.Query().Get("message_id") != "chat-1" {
				t.Fatalf("message_id query=%q, want chat-1", r.URL.Query().Get("message_id"))
			}
			if r.URL.Query().Get("limit") != "1" {
				t.Fatalf("limit query=%q, want 1", r.URL.Query().Get("limit"))
			}
			_ = json.NewEncoder(w).Encode(awid.ChatHistoryResponse{
				Messages: []awid.ChatMessage{{
					MessageID:      "chat-1",
					ConversationID: "session-1",
					FromAgent:      "athena",
					FromAddress:    "aweb.ai/athena",
					Body:           "decrypted chat body",
					Timestamp:      "2026-05-26T00:00:00Z",
				}},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "chat", "history",
		"--session-id", "session-1",
		"--message-id", "chat-1",
		"--limit", "1",
		"--json",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !sawHistory {
		t.Fatal("chat history did not query by session id")
	}
	if !strings.Contains(string(out), "decrypted chat body") {
		t.Fatalf("output missing chat body:\n%s", string(out))
	}
}
