package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// People are reached by mail. The server refuses chat to an authoritative
// human with the reason recipient_human_mail_only; every chat send form says
// so in one sentence that names mail, with that code under --json. Chat to
// an agent is unchanged, and other refusals keep their own text.
func TestChatToAPersonSaysToUseMail(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	refuse := func(w http.ResponseWriter, reason string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]any{"detail": reason, "reason": reason, "retryable": false, "correlation_id": "corr-1"})
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/agents":
			_ = json.NewEncoder(w).Encode(awid.ListAgentsResponse{TeamID: "backend:demo", Agents: []awid.AgentView{{AgentID: "agent-bob", Alias: "bob", DIDKey: "did:key:z6Mkbob"}}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/pending":
			_ = json.NewEncoder(w).Encode(awid.ChatPendingResponse{Pending: []awid.ChatPendingItem{}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/chat/sessions":
			_ = json.NewEncoder(w).Encode(awid.ChatListSessionsResponse{Sessions: []awid.ChatSessionItem{
				{SessionID: "human-1", TeamID: "backend:demo", Participants: []string{"alice", "juan"}, CreatedAt: "2026-10-31T00:00:00Z"},
			}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions":
			var req awid.ChatCreateSessionRequest
			_ = json.NewDecoder(r.Body).Decode(&req)
			switch strings.Join(req.ToAliases, ",") {
			case "juan":
				refuse(w, "recipient_human_mail_only")
			case "carol":
				refuse(w, "recipient_custodial_no_e2ee")
			default:
				_ = json.NewEncoder(w).Encode(awid.ChatCreateSessionResponse{SessionID: "agent-1", MessageID: "chat-1"})
			}
		case r.Method == http.MethodPost && r.URL.Path == "/v1/chat/sessions/human-1/messages":
			refuse(w, "recipient_human_mail_only")
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := func(args ...string) (int, string, string) {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = append(testCommandEnv(tmp), "AWID_REGISTRY_URL="+server.URL)
		cmd.Dir = tmp
		var stdout, stderr bytes.Buffer
		cmd.Stdout, cmd.Stderr = &stdout, &stderr
		if err := cmd.Run(); err != nil {
			return exitCode(err), stdout.String(), stderr.String()
		}
		return 0, stdout.String(), stderr.String()
	}

	const juan = "juan is a person; aweb reaches people by mail: aw mail send --to juan"
	for _, tc := range []struct {
		name string
		args []string
		want string
	}{
		{name: "send-and-wait", args: []string{"chat", "send-and-wait", "juan", "hello", "--start-conversation", "--wait", "0"}, want: juan},
		{name: "send-and-leave", args: []string{"chat", "send-and-leave", "juan", "hello", "--start-conversation"}, want: juan},
		{name: "extend-wait", args: []string{"chat", "extend-wait", "juan", "one more minute"}, want: juan},
		{name: "send in a session", args: []string{"chat", "send", "--session-id", "human-1", "--body", "hello"}, want: "<recipient> is a person; aweb reaches people by mail: aw mail send --to <recipient>"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			exit, _, stderr := run(tc.args...)
			if exit != 1 || strings.TrimSpace(stderr) != tc.want {
				t.Fatalf("exit=%d stderr=%q, want exit 1 and %q", exit, stderr, tc.want)
			}
			exit, stdout, _ := run(append([]string{"--json"}, tc.args...)...)
			var envelope struct {
				Error map[string]any `json:"error"`
			}
			if err := json.Unmarshal([]byte(stdout), &envelope); err != nil || exit != 1 {
				t.Fatalf("--json exit=%d stdout=%q: %v", exit, stdout, err)
			}
			if envelope.Error["code"] != "recipient_human_mail_only" || envelope.Error["reason"] != "recipient_human_mail_only" || envelope.Error["message"] != tc.want {
				t.Fatalf("--json envelope %v", envelope.Error)
			}
		})
	}

	// Chat to an agent is unchanged.
	if exit, stdout, stderr := run("chat", "send-and-leave", "bob", "hello", "--start-conversation"); exit != 0 {
		t.Fatalf("chat to an agent: exit=%d %s %s", exit, stdout, stderr)
	}
	// Another refusal keeps its own text and code.
	exit, stdout, _ := run("--json", "chat", "send-and-leave", "carol", "hello", "--start-conversation")
	var other struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal([]byte(stdout), &other); err != nil || exit != 1 || other.Error["code"] == "recipient_human_mail_only" || strings.Contains(stdout, "is a person") {
		t.Fatalf("another refusal became the person refusal: exit=%d %s", exit, stdout)
	}
}
