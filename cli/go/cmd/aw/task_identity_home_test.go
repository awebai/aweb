package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestExternalIdentityHomeTaskAndWorkCommandsUseSelectedPrincipal(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	instance := filepath.Join(root, "instance")
	principalRoot := filepath.Join(root, "principal")
	if err := os.MkdirAll(instance, 0o700); err != nil {
		t.Fatal(err)
	}

	principalPub, principalKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowPub, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	principalDID := awid.ComputeDIDKey(principalPub)
	shadowDID := awid.ComputeDIDKey(shadowPub)

	var requestMu sync.Mutex
	var signedRequests []messagingSignedRequest
	task := map[string]any{
		"task_id": "task-1", "task_ref": "TASK-001", "task_number": 1,
		"title": "Principal task", "status": "open", "priority": 1, "task_type": "task",
		"created_at": "2026-07-26T00:00:00Z", "updated_at": "2026-07-26T00:00:00Z",
	}
	principalServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, readErr := io.ReadAll(r.Body)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if r.URL.Path != "/v1/agents/heartbeat" {
			requireCertificateAuthForTest(t, r)
			requestMu.Lock()
			signedRequests = append(signedRequests, messagingSignedRequest{
				authorization: r.Header.Get("Authorization"),
				timestamp:     r.Header.Get("X-AWEB-Timestamp"),
				method:        r.Method,
				path:          r.URL.Path,
				body:          body,
			})
			requestMu.Unlock()
		}
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/session-leases":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "active", "team_id": "runtime:aweb.test", "principal_agent_id": "principal-agent", "session_id": "session-a", "generation": 1, "acquired_at": "2026-07-26T00:00:00Z", "expires_at": "2026-07-26T00:05:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/session-leases/release":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "released", "session_id": "session-a"})
		case r.Method == http.MethodPost && (r.URL.Path == "/v1/session-leases" || r.URL.Path == "/v1/session-leases/renew" || r.URL.Path == "/v1/session-leases/takeover"):
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "active", "team_id": "runtime:aweb.test", "principal_agent_id": "principal-agent", "session_id": "session-a", "generation": 1, "acquired_at": "2026-07-26T00:00:00Z", "expires_at": "2026-07-26T00:05:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			_ = json.NewEncoder(w).Encode(task)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{task}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/ready":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{task}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/active":
			active := map[string]any{}
			for key, value := range task {
				active[key] = value
			}
			active["workspace_id"] = "workspace-principal"
			active["owner_alias"] = "principal"
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{active}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/blocked":
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []any{task}})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/claims":
			_ = json.NewEncoder(w).Encode(map[string]any{"claims": []any{}, "has_more": false})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/TASK-001/comments":
			_ = json.NewEncoder(w).Encode(map[string]any{"comments": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks/TASK-001/comments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"comment_id": "comment-1", "task_id": "task-1", "author_alias": "principal",
				"body": "principal comment", "created_at": "2026-07-26T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks/TASK-001/deps":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/tasks/TASK-001/deps/TASK-000":
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/TASK-001":
			_ = json.NewEncoder(w).Encode(task)
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/TASK-001":
			_ = json.NewEncoder(w).Encode(task)
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/tasks/TASK-001":
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected principal request %s %s", r.Method, r.URL.RequestURI())
		}
	}))
	var shadowRequests atomic.Int32
	shadowServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		shadowRequests.Add(1)
		http.Error(w, "shadow identity must not receive task traffic", http.StatusInternalServerError)
	}))

	writeMessagingPrincipalForTest(t, principalRoot, principalServer.URL, "principal", principalDID, principalKey)
	writeMessagingPrincipalForTest(t, instance, shadowServer.URL, "shadow", shadowDID, shadowKey)

	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	const sessionKey = "0123456789abcdef0123456789abcdef"
	commands := []struct {
		name string
		args []string
	}{
		{name: "session-lease-status", args: []string{"session", "lease", "status"}},
		{name: "session-lease-acquire", args: []string{"session", "lease", "acquire", "--session-id", "session-a", "--session-key", sessionKey}},
		{name: "session-lease-renew", args: []string{"session", "lease", "renew", "--session-id", "session-a", "--session-key", sessionKey}},
		{name: "session-lease-release", args: []string{"session", "lease", "release", "--session-id", "session-a", "--session-key", sessionKey}},
		{name: "session-lease-takeover", args: []string{"session", "lease", "takeover", "--session-id", "session-a", "--session-key", sessionKey, "--reason", "operator test"}},
		{name: "task-create", args: []string{"task", "create", "--title", "Principal task"}},
		{name: "task-list", args: []string{"task", "list"}},
		{name: "task-show", args: []string{"task", "show", "TASK-001"}},
		{name: "task-update", args: []string{"task", "update", "TASK-001", "--title", "Principal task"}},
		{name: "task-close", args: []string{"task", "close", "TASK-001"}},
		{name: "task-reopen", args: []string{"task", "reopen", "TASK-001"}},
		{name: "task-delete", args: []string{"task", "delete", "TASK-001"}},
		{name: "task-comment-add", args: []string{"task", "comment", "add", "TASK-001", "--body", "principal comment"}},
		{name: "task-comment-list", args: []string{"task", "comment", "list", "TASK-001"}},
		{name: "task-dep-add", args: []string{"task", "dep", "add", "TASK-001", "TASK-000"}},
		{name: "task-dep-remove", args: []string{"task", "dep", "remove", "TASK-001", "TASK-000"}},
		{name: "task-dep-list", args: []string{"task", "dep", "list", "TASK-001"}},
		{name: "task-stats", args: []string{"task", "stats"}},
		{name: "work-ready", args: []string{"work", "ready"}},
		{name: "work-active", args: []string{"work", "active"}},
		{name: "work-blocked", args: []string{"work", "blocked"}},
	}
	identityHome := filepath.Join(principalRoot, ".aw")
	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			args := append([]string{"--identity-home", identityHome, "--json"}, command.args...)
			cmd := exec.CommandContext(ctx, bin, args...)
			cmd.Dir = instance
			cmd.Env = testCommandEnv(filepath.Join(root, "user-home"))
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("attached-principal command failed: %v\n%s", err, out)
			}
		})
	}

	if got := shadowRequests.Load(); got != 0 {
		t.Fatalf("disposable shadow received %d task/work requests", got)
	}
	requestMu.Lock()
	requests := append([]messagingSignedRequest(nil), signedRequests...)
	requestMu.Unlock()
	verifyMessagingRequestsForTest(t, requests, principalPub, shadowPub, principalDID, shadowDID)
	wantLeaseBodies := map[string]map[string]any{
		"/v1/session-leases":          {"session_id": "session-a", "session_key": sessionKey, "ttl_seconds": float64(300)},
		"/v1/session-leases/renew":    {"session_id": "session-a", "session_key": sessionKey, "ttl_seconds": float64(300)},
		"/v1/session-leases/release":  {"session_id": "session-a", "session_key": sessionKey},
		"/v1/session-leases/takeover": {"session_id": "session-a", "session_key": sessionKey, "ttl_seconds": float64(300), "reason": "operator test"},
	}
	seen := make(map[string]bool)
	for _, request := range requests {
		want, ok := wantLeaseBodies[request.path]
		if !ok || request.method != http.MethodPost {
			continue
		}
		var got map[string]any
		if err := json.Unmarshal(request.body, &got); err != nil {
			t.Fatalf("decode %s request: %v", request.path, err)
		}
		if len(got) != len(want) {
			t.Fatalf("%s body = %#v, want %#v", request.path, got, want)
		}
		for key, value := range want {
			if got[key] != value {
				t.Fatalf("%s body[%s] = %#v, want %#v", request.path, key, got[key], value)
			}
		}
		seen[request.path] = true
	}
	for path := range wantLeaseBodies {
		if !seen[path] {
			t.Fatalf("missing exact request assertion for %s", path)
		}
	}
}
