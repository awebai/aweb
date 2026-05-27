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

func TestAwChatSendBySessionIDJSON(t *testing.T) {
	t.Parallel()

	var sawSend bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions":
			if r.Method == http.MethodGet {
				_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{{
					SessionID:            "session-1",
					Participants:         []string{"dev", "review"},
					ParticipantAddresses: []string{"acme.test/dev", "acme.test/review"},
					ParticipantDIDs:      []string{"did:aw:dev", "did:aw:review"},
					CreatedAt:            "2026-05-26T00:00:00Z",
					LastActivity:         "2026-05-26T00:00:01Z",
				}}})
				return
			}
			t.Fatalf("unexpected chat sessions method=%s; exact session send must not create or resolve sessions", r.Method)
		case "/v1/chat/sessions/session-1/messages":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s, want POST", r.Method)
			}
			var req awid.ChatSendMessageRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if req.Body != "hello exact" {
				t.Fatalf("body=%q, want hello exact", req.Body)
			}
			if !req.Leaving {
				t.Fatal("leaving=false, want true")
			}
			sawSend = true
			_ = json.NewEncoder(w).Encode(awid.ChatSendMessageResponse{MessageID: "chat-out-1", Delivered: true})
		case "/v1/chat/pending":
			t.Fatal("exact session send must not resolve by pending alias/address lookup")
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

	run := exec.CommandContext(ctx, bin, "chat", "send",
		"--session-id", "session-1",
		"--body", "hello exact",
		"--leave",
		"--plaintext",
		"--json",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !sawSend {
		t.Fatal("chat send did not call exact session messages endpoint")
	}
	if !strings.Contains(string(out), `"message_id": "chat-out-1"`) {
		t.Fatalf("output missing message id:\n%s", string(out))
	}
}

func TestAwChatSendBySessionIDRequiresSessionID(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, "http://127.0.0.1:1")

	run := exec.CommandContext(ctx, bin, "chat", "send", "--body", "hello")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected failure without --session-id, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "missing required flag: --session-id") {
		t.Fatalf("output missing session-id error:\n%s", string(out))
	}
}

func TestAwChatSendBySessionIDRejectsE2EEPlaintextTogether(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, "http://127.0.0.1:1")

	run := exec.CommandContext(ctx, bin, "chat", "send", "--session-id", "session-1", "--body", "hello", "--plaintext", "--e2ee")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected mutual-exclusion failure, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--e2ee and --plaintext are mutually exclusive") {
		t.Fatalf("output missing mutual-exclusion error:\n%s", string(out))
	}
}

func TestAwChatReadBySessionMessageIDJSON(t *testing.T) {
	t.Parallel()

	var sawRead bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/chat/sessions/session-1/read":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s, want POST", r.Method)
			}
			var req awid.ChatMarkReadRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode body: %v", err)
			}
			if req.UpToMessageID != "chat-1" {
				t.Fatalf("up_to_message_id=%q, want chat-1", req.UpToMessageID)
			}
			sawRead = true
			_ = json.NewEncoder(w).Encode(awid.ChatMarkReadResponse{Success: true, MessagesMarked: 1})
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

	run := exec.CommandContext(ctx, bin, "chat", "read",
		"--session-id", "session-1",
		"--message-id", "chat-1",
		"--json",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !sawRead {
		t.Fatal("chat read did not call mark-read endpoint")
	}
	if !strings.Contains(string(out), `"messages_marked": 1`) {
		t.Fatalf("output missing messages_marked:\n%s", string(out))
	}
}

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
