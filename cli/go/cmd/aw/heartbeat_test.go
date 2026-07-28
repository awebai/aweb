package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os/exec"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

func TestHeartbeatRepairsWorkspaceRepoBinding(t *testing.T) {
	t.Parallel()

	var patchCalls atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/agents/me":
			patchCalls.Add(1)
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if got := payload["repo_origin"]; got != "ssh://git@ssh.github.com:443/awebai/aweb.git" {
				t.Fatalf("repo_origin=%v", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":         "agent-noor",
				"alias":            "noor",
				"repo_id":          "repo-canonical",
				"canonical_origin": "github.com/awebai/aweb",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/heartbeat":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":     "agent-noor",
				"alias":        "noor",
				"last_seen_at": "2026-07-28T15:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	initGitRepoWithOrigin(t, tmp, "ssh://git@ssh.github.com:443/awebai/aweb.git")

	state := workspaceBinding(server.URL, "aweb:juan.aweb.ai", "noor", "09db0793-3b1c-43a9-a299-36ebf2cdfd85")
	state.CanonicalOrigin = "ssh://git@ssh.github.com:443/awebai/aweb"
	state.WorkspacePath = tmp
	writeWorkspaceBindingForTest(t, tmp, state)

	runHeartbeat := func() map[string]any {
		t.Helper()
		run := exec.CommandContext(ctx, bin, "heartbeat")
		run.Env = testCommandEnv(tmp)
		run.Dir = tmp
		out, err := run.CombinedOutput()
		if err != nil {
			t.Fatalf("heartbeat failed: %v\n%s", err, string(out))
		}
		var got map[string]any
		if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
			t.Fatalf("invalid heartbeat JSON: %v\n%s", err, string(out))
		}
		return got
	}

	first := runHeartbeat()
	if first["repo_status"] != "repaired" {
		t.Fatalf("first repo_status=%v", first["repo_status"])
	}
	if first["canonical_origin"] != "github.com/awebai/aweb" {
		t.Fatalf("first canonical_origin=%v", first["canonical_origin"])
	}
	if first["repo_id"] != "repo-canonical" {
		t.Fatalf("first repo_id=%v", first["repo_id"])
	}

	repaired, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if repaired.CanonicalOrigin != "github.com/awebai/aweb" || repaired.RepoID != "repo-canonical" {
		t.Fatalf("workspace was not repaired: %#v", repaired)
	}

	second := runHeartbeat()
	if second["repo_status"] != "current" {
		t.Fatalf("second repo_status=%v", second["repo_status"])
	}
	if got := patchCalls.Load(); got != 1 {
		t.Fatalf("repo repair PATCH calls=%d want 1", got)
	}
}
