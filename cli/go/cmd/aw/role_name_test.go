package main

import (
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
)

func TestRoleNameSetPatchesCurrentWorkspace(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
					"reviewer":  map[string]any{"title": "Reviewer"},
				},
			})
		case "/v1/agents/me":
			if r.Method != http.MethodPatch {
				t.Fatalf("method=%s", r.Method)
			}
			requireCertificateAuthForTest(t, r)
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if req["role"] != "reviewer" {
				t.Fatalf("role=%v", req["role"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"agent_id":       "agent-1",
				"alias":          "alice",
				"hostname":       "devbox",
				"workspace_path": "/tmp/repo",
				"role":           "reviewer",
				"human_name":     "Alice",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	binding := workspaceBinding(server.URL, "backend:demo", "alice", "workspace-1")
	binding.Memberships[0].RoleName = "developer"
	writeWorkspaceBindingForTest(t, repo, binding)

	run := exec.CommandContext(ctx, bin, "role-name", "set", "reviewer")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Role name set to reviewer") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}

	state, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(repo, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace state: %v", err)
	}
	if activeMembershipForTest(t, state).RoleName != "reviewer" {
		t.Fatalf("role_name=%q", activeMembershipForTest(t, state).RoleName)
	}
}
