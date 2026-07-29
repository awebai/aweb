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

func TestRoleNameHelpExplainsOperatingRoleIsIndependentOfProfile(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "role-name", "set", "--help")
	run.Env = testCommandEnv(tmp)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("role-name help failed: %v\n%s", err, out)
	}
	help := string(out)
	for _, want := range []string{
		"operating responsibility on this team",
		"initialized from the materialized profile",
		"does not change which profile the workspace runs",
	} {
		if !strings.Contains(help, want) {
			t.Fatalf("role-name help missing %q:\n%s", want, help)
		}
	}
}

func TestRoleNameSetPatchesCurrentWorkspace(t *testing.T) {
	t.Parallel()

	t.Run("current server returns role_name", func(t *testing.T) {
		t.Parallel()
		runRoleNameSetPatchTest(t, map[string]any{
			"agent_id":       "agent-1",
			"alias":          "alice",
			"hostname":       "devbox",
			"workspace_path": "/tmp/repo",
			"role_name":      "reviewer",
			"human_name":     "Alice",
		})
	})

	t.Run("legacy server returns role", func(t *testing.T) {
		t.Parallel()
		runRoleNameSetPatchTest(t, map[string]any{
			"agent_id":       "agent-1",
			"alias":          "alice",
			"hostname":       "devbox",
			"workspace_path": "/tmp/repo",
			"role":           "reviewer",
			"human_name":     "Alice",
		})
	})
}

func runRoleNameSetPatchTest(t *testing.T, patchResponse map[string]any) {
	t.Helper()

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
				t.Fatalf("role=%v in request %#v", req["role"], req)
			}
			if req["role_name"] != "reviewer" {
				t.Fatalf("role_name=%v in request %#v", req["role_name"], req)
			}
			_ = json.NewEncoder(w).Encode(patchResponse)
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
	profilePinPath := filepath.Join(repo, ".aw", "profile", "ref.json")
	if err := os.MkdirAll(filepath.Dir(profilePinPath), 0o755); err != nil {
		t.Fatal(err)
	}
	profilePin := []byte(`{"profile_ref":"developer","profile_version":"0.1.0","profile_digest":"sha256:profile"}` + "\n")
	if err := os.WriteFile(profilePinPath, profilePin, 0o644); err != nil {
		t.Fatal(err)
	}

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
	profileAfter, err := os.ReadFile(profilePinPath)
	if err != nil {
		t.Fatalf("read profile provenance after role change: %v", err)
	}
	if string(profileAfter) != string(profilePin) {
		t.Fatalf("role change rewrote profile provenance:\n%s", profileAfter)
	}
}
