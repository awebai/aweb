package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"gopkg.in/yaml.v3"
)

func buildAwBinary(t *testing.T, ctx context.Context, outPath string) {
	t.Helper()
	build := exec.CommandContext(ctx, "go", "build", "-o", outPath, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}
}

func initGitRepoWithOrigin(t *testing.T, dir, origin string) {
	t.Helper()
	commands := [][]string{
		{"git", "init"},
		{"git", "remote", "add", "origin", origin},
	}
	for _, argv := range commands {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(argv, " "), err, string(out))
		}
	}
}

func initGitRepoWithOriginAndCommit(t *testing.T, dir, origin string) {
	t.Helper()
	initGitRepoWithOrigin(t, dir, origin)
	commands := [][]string{
		{"git", "config", "user.email", "test@example.com"},
		{"git", "config", "user.name", "Test User"},
	}
	for _, argv := range commands {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(argv, " "), err, string(out))
		}
	}
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# Test\n"), 0o644); err != nil {
		t.Fatalf("write README: %v", err)
	}
	commands = [][]string{
		{"git", "add", "README.md"},
		{"git", "commit", "-m", "Initial commit"},
	}
	for _, argv := range commands {
		cmd := exec.Command(argv[0], argv[1:]...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(argv, " "), err, string(out))
		}
	}
}

func TestAwWorkspaceInitWritesWorkspaceState(t *testing.T) {
	t.Parallel()

	const workspaceID = "11111111-1111-1111-1111-111111111111"
	const projectID = "22222222-2222-2222-2222-222222222222"
	const repoID = "33333333-3333-3333-3333-333333333333"
	const origin = "https://github.com/acme/repo.git"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/workspaces/register":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			if req["role"] != "developer" {
				t.Fatalf("role=%v", req["role"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     workspaceID,
				"project_id":       projectID,
				"project_slug":     "demo",
				"repo_id":          repoID,
				"canonical_origin": "github.com/acme/repo",
				"alias":            "alice",
				"human_name":       "Alice",
				"created":          true,
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
	initGitRepoWithOrigin(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     workspaceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})

	run := exec.CommandContext(ctx, bin, "workspace", "init", "--role", "developer")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Registered workspace alice") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}

	data, err := os.ReadFile(filepath.Join(repo, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("read workspace state: %v", err)
	}
	var state awconfig.WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal workspace state: %v", err)
	}
	if state.WorkspaceID != workspaceID {
		t.Fatalf("workspace_id=%s", state.WorkspaceID)
	}
	if state.ProjectID != projectID {
		t.Fatalf("project_id=%s", state.ProjectID)
	}
	if state.Alias != "alice" {
		t.Fatalf("alias=%s", state.Alias)
	}
	if state.Role != "developer" {
		t.Fatalf("role=%s", state.Role)
	}
	if state.CanonicalOrigin != "github.com/acme/repo" {
		t.Fatalf("canonical_origin=%s", state.CanonicalOrigin)
	}
}

func TestAwInitAutoAttachesRepoContext(t *testing.T) {
	t.Parallel()

	const workspaceID = "11111111-1111-1111-1111-111111111111"
	const projectID = "22222222-2222-2222-2222-222222222222"
	const repoID = "33333333-3333-3333-3333-333333333333"
	const origin = "https://github.com/acme/repo.git"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{"name_prefix": "alice", "roles": []string{}})
		case "/v1/workspaces/init":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"status":         "ok",
				"created_at":     "2026-03-10T10:00:00Z",
				"project_id":     projectID,
				"project_slug":   "demo",
				"identity_id":    workspaceID,
				"alias":          "alice",
				"api_key":        "aw_sk_test",
				"namespace_slug": "demo",
				"created":        true,
				"did":            "did:key:z6Mktest",
				"custody":        "self",
				"lifetime":       "ephemeral",
			})
		case "/v1/workspaces/register":
			if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
				t.Fatalf("auth=%q", r.Header.Get("Authorization"))
			}
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode request: %v", err)
			}
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     workspaceID,
				"project_id":       projectID,
				"project_slug":     "demo",
				"repo_id":          repoID,
				"canonical_origin": "github.com/acme/repo",
				"alias":            "alice",
				"human_name":       "Alice",
				"created":          true,
			})
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
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
	initGitRepoWithOrigin(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(ctx, bin, "init", "--alias", "alice", "--role", "developer")
	run.Stdin = strings.NewReader("")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH=",
		"AWEB_URL="+server.URL,
		"AWEB_API_KEY=aw_sk_project_test",
		"AW_DID_REGISTRY_URL=http://127.0.0.1:1",
	)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "Context:    attached github.com/acme/repo") {
		t.Fatalf("expected repo attachment summary:\n%s", text)
	}

	if _, err := os.Stat(filepath.Join(repo, ".aw", "context")); err != nil {
		t.Fatalf("expected .aw/context: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(repo, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("read workspace state: %v", err)
	}
	var state awconfig.WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal workspace state: %v", err)
	}
	if state.WorkspaceID != workspaceID {
		t.Fatalf("workspace_id=%s", state.WorkspaceID)
	}
	if state.CanonicalOrigin != "github.com/acme/repo" {
		t.Fatalf("canonical_origin=%s", state.CanonicalOrigin)
	}
}

func TestAwWorkspaceStatusShowsTeamState(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const peerID = "44444444-4444-4444-4444-444444444444"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/workspaces/team":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":     selfID,
						"alias":            "alice",
						"role":             "developer",
						"status":           "active",
						"hostname":         "devbox",
						"workspace_path":   "/tmp/repo",
						"repo":             "github.com/acme/repo",
						"branch":           "main",
						"focus_task_ref":   "aweb-aaaa",
						"focus_task_title": "Restore rich coordination status",
						"apex_id":          "AWEB-AAAA",
						"apex_title":       "Restore rich coordination status",
						"apex_type":        "epic",
						"claims": []map[string]any{
							{"task_ref": "TASK-001", "title": "Own task", "claimed_at": "2026-03-10T10:00:00Z"},
						},
					},
					{
						"workspace_id":     peerID,
						"alias":            "bob",
						"role":             "reviewer",
						"status":           "idle",
						"last_seen":        "2026-03-10T10:05:00Z",
						"hostname":         "reviewbox",
						"workspace_path":   "/Users/bob/repo-other",
						"repo":             "github.com/acme/other",
						"branch":           "review-branch",
						"focus_task_ref":   "TASK-900",
						"focus_task_title": "Review release",
						"apex_id":          "TASK-900",
						"apex_title":       "Review release",
						"apex_type":        "task",
						"claims": []map[string]any{
							{"task_ref": "TASK-002", "title": "Peer task", "claimed_at": "2026-03-10T10:01:00Z"},
						},
					},
				},
				"has_more": false,
			})
		case "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reservations": []map[string]any{
					{
						"project_id":      "proj-1",
						"resource_key":    "src/main.go",
						"holder_agent_id": selfID,
						"holder_alias":    "alice",
						"acquired_at":     "2026-03-10T10:00:00Z",
						"expires_at":      "2099-03-10T10:00:00Z",
						"metadata":        map[string]any{},
					},
					{
						"project_id":      "proj-1",
						"resource_key":    "src/review.go",
						"holder_agent_id": peerID,
						"holder_alias":    "bob",
						"acquired_at":     "2026-03-10T10:00:00Z",
						"expires_at":      "2099-03-10T10:00:00Z",
						"metadata":        map[string]any{"reason": "review follow-up"},
					},
				},
			})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 2},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{{"bead_id": "TASK-002", "claimants": []map[string]any{{"alias": "bob", "workspace_id": peerID}}}},
				"escalations_pending": 2,
				"timestamp":           "2026-03-10T10:10:00Z",
			})
		case "/v1/workspaces":
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []map[string]any{}, "has_more": false})
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
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	state := awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_test",
		IdentityID:      selfID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     selfID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		Alias:           "alice",
		Role:            "developer",
		Hostname:        "devbox",
		WorkspacePath:   tmp,
		CanonicalOrigin: "github.com/acme/repo",
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &state); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"## Self",
		"- Alias: alice",
		"- Context: repo_worktree",
		"- Repo: github.com/acme/repo",
		"- Branch: main",
		"- Focus: aweb-aaaa \"Restore rich coordination status\"",
		"- Epic: AWEB-AAAA (Restore rich coordination status)",
		"- Claims: TASK-001 \"Own task\" (",
		"[stale]",
		"- Locks: src/main.go (TTL:",
		"## Team",
		"bob (reviewer) — idle, seen ",
		"Host: reviewbox  Path: /Users/bob/repo-other",
		"Repo: github.com/acme/other  Branch: review-branch",
		"Focus: TASK-900 \"Review release\"",
		"Working on: TASK-900 (Review release)",
		"Claims: TASK-002 \"Peer task\" (",
		"Locks: src/review.go (TTL:",
		"reason: review follow-up",
		"Escalations pending: 2",
		"Claim conflicts: 1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestAwWorkspaceStatusWithoutLocalWorkspaceShowsAgentContext(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const peerID = "44444444-4444-4444-4444-444444444444"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/workspaces/team":
			if got := r.URL.Query().Get("always_include_workspace_id"); got != selfID {
				t.Fatalf("always_include_workspace_id=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id": peerID,
						"alias":        "reviewer-jane",
						"role":         "coordinator",
						"status":       "active",
						"repo":         "github.com/acme/ac",
						"branch":       "main",
						"apex_id":      "EPIC-22",
						"apex_title":   "Release coordination",
						"apex_type":    "epic",
						"claims": []map[string]any{
							{"task_ref": "TASK-100", "title": "Coordinate release", "claimed_at": "2026-03-10T10:01:00Z"},
						},
					},
					{
						"workspace_id": "55555555-5555-5555-5555-555555555555",
						"alias":        "floating",
						"status":       "idle",
						"claims":       []map[string]any{},
					},
				},
				"has_more": false,
			})
		case "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reservations": []map[string]any{},
			})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 1},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{},
				"escalations_pending": 1,
				"timestamp":           "2026-03-10T10:10:00Z",
			})
		case "/v1/workspaces":
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []map[string]any{}, "has_more": false})
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
	buildAwBinary(t, ctx, bin)
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     selfID,
		IdentityHandle: "coordinator",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"## Self",
		"- Alias: coordinator",
		"- Context: none",
		"- Status: offline",
		"- Focus: none",
		"- Claims: none",
		"- Locks: none",
		"## Team",
		"reviewer-jane (coordinator) — active",
		"Repo: github.com/acme/ac",
		"Focus: none",
		"Epic: EPIC-22 (Release coordination)",
		"Claims: TASK-100 \"Coordinate release\" (",
		"Locks: none",
		"floating — idle",
		"Escalations pending: 1",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "floating — idle\n  Repo:") {
		t.Fatalf("expected repo line to be omitted when repo/branch are empty:\n%s", text)
	}
	if strings.Contains(text, "Repo: github.com/acme/ac  Branch: main") {
		t.Fatalf("expected main branch to be hidden for team workspaces:\n%s", text)
	}
}

func TestAwWorkspaceStatusTruncatesTeamLocks(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const peerID = "44444444-4444-4444-4444-444444444444"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/workspaces/team":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id": selfID,
						"alias":        "alice",
						"status":       "active",
					},
					{
						"workspace_id": peerID,
						"alias":        "bob",
						"status":       "active",
					},
				},
				"has_more": false,
			})
		case "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reservations": []map[string]any{
					{"project_id": "proj-1", "resource_key": "src/1.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
					{"project_id": "proj-1", "resource_key": "src/2.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
					{"project_id": "proj-1", "resource_key": "src/3.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
					{"project_id": "proj-1", "resource_key": "src/4.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
				},
			})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace": map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 2},
				"agents":    []map[string]any{},
				"claims":    []map[string]any{},
				"conflicts": []map[string]any{},
				"timestamp": "2026-03-10T10:10:00Z",
			})
		case "/v1/workspaces":
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": []map[string]any{}, "has_more": false})
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
	buildAwBinary(t, ctx, bin)
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     selfID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "Locks: src/1.go (TTL:") || !strings.Contains(text, "...1 more") {
		t.Fatalf("expected truncated team lock summary:\n%s", text)
	}
	if strings.Contains(text, "src/4.go") {
		t.Fatalf("expected fourth lock to be hidden behind overflow indicator:\n%s", text)
	}
}

func TestAwWorkspaceStatusDeletesGoneEphemeralIdentity(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const goneID = "44444444-4444-4444-4444-444444444444"

	missingPath := filepath.Join(t.TempDir(), "gone-worktree")
	var deletedIdentity atomic.Bool
	var deletedWorkspace atomic.Bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch {
		case r.URL.Path == "/v1/workspaces/team":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   selfID,
						"alias":          "alice",
						"role":           "developer",
						"status":         "active",
						"hostname":       "devbox",
						"workspace_path": "/tmp/repo",
						"repo":           "github.com/acme/repo",
						"branch":         "main",
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{"reservations": []map[string]any{}})
		case r.URL.Path == "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 2},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{},
				"escalations_pending": 0,
				"timestamp":           "2026-03-10T10:10:00Z",
			})
		case r.URL.Path == "/v1/workspaces" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   goneID,
						"alias":          "bob",
						"project_slug":   "demo",
						"status":         "offline",
						"workspace_path": missingPath,
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/agents/resolve/bob" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identity_id": "agent-bob",
				"did":         "did:key:z6MkEphemeral",
				"address":     "demo/bob",
				"custody":     "custodial",
				"lifetime":    "ephemeral",
				"public_key":  "",
			})
		case r.URL.Path == "/v1/agents/demo/bob" && r.Method == http.MethodDelete:
			deletedIdentity.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/workspaces/"+goneID && r.Method == http.MethodDelete:
			deletedWorkspace.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	state := awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_test",
		IdentityID:      selfID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     selfID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		Alias:           "alice",
		Role:            "developer",
		Hostname:        "devbox",
		WorkspacePath:   tmp,
		CanonicalOrigin: "github.com/acme/repo",
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &state); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !deletedIdentity.Load() {
		t.Fatal("expected gone ephemeral identity deletion")
	}
	if !deletedWorkspace.Load() {
		t.Fatal("expected gone workspace record deletion")
	}
	if !strings.Contains(string(out), "deleted ephemeral identity") {
		t.Fatalf("expected gone-workspace cleanup output, got:\n%s", string(out))
	}
}

func TestAwWorkspaceStatusKeepsGonePermanentIdentity(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const goneID = "44444444-4444-4444-4444-444444444444"

	missingPath := filepath.Join(t.TempDir(), "gone-worktree")
	var deletedIdentity atomic.Bool
	var deletedWorkspace atomic.Bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch {
		case r.URL.Path == "/v1/workspaces/team":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   selfID,
						"alias":          "alice",
						"role":           "developer",
						"status":         "active",
						"hostname":       "devbox",
						"workspace_path": "/tmp/repo",
						"repo":           "github.com/acme/repo",
						"branch":         "main",
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{"reservations": []map[string]any{}})
		case r.URL.Path == "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 2},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{},
				"escalations_pending": 0,
				"timestamp":           "2026-03-10T10:10:00Z",
			})
		case r.URL.Path == "/v1/workspaces" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   goneID,
						"alias":          "maintainer",
						"project_slug":   "demo",
						"status":         "offline",
						"workspace_path": missingPath,
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/agents/resolve/maintainer" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identity_id": "agent-maintainer",
				"did":         "did:key:z6MkPermanent",
				"address":     "demo/maintainer",
				"custody":     "self",
				"lifetime":    "persistent",
			})
		case r.URL.Path == "/v1/agents/demo/maintainer" && r.Method == http.MethodDelete:
			deletedIdentity.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/workspaces/"+goneID && r.Method == http.MethodDelete:
			deletedWorkspace.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	state := awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_test",
		IdentityID:      selfID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     selfID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		Alias:           "alice",
		Role:            "developer",
		Hostname:        "devbox",
		WorkspacePath:   tmp,
		CanonicalOrigin: "github.com/acme/repo",
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &state); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if deletedIdentity.Load() {
		t.Fatal("did not expect permanent identity deletion")
	}
	if !deletedWorkspace.Load() {
		t.Fatal("expected gone workspace record deletion")
	}
	if !strings.Contains(string(out), "removed workspace record") {
		t.Fatalf("expected gone-workspace cleanup output, got:\n%s", string(out))
	}
}

func TestAwWorkspaceStatusDeletesGoneEphemeralIdentityByNamespaceSlug(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const goneID = "44444444-4444-4444-4444-444444444444"

	missingPath := filepath.Join(t.TempDir(), "gone-worktree")
	var deletedIdentity atomic.Bool
	var deletedWorkspace atomic.Bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch {
		case r.URL.Path == "/v1/workspaces/team":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   selfID,
						"alias":          "alice",
						"role":           "developer",
						"status":         "active",
						"hostname":       "devbox",
						"workspace_path": "/tmp/repo",
						"repo":           "github.com/acme/repo",
						"branch":         "main",
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{"reservations": []map[string]any{}})
		case r.URL.Path == "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 2},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{},
				"escalations_pending": 0,
				"timestamp":           "2026-03-10T10:10:00Z",
			})
		case r.URL.Path == "/v1/workspaces" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   goneID,
						"alias":          "bot",
						"project_slug":   "demo",
						"namespace_slug": "demo.example.com",
						"status":         "offline",
						"workspace_path": missingPath,
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/agents/resolve/demo.example.com/bot" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"identity_id": "agent-bot",
				"did":         "did:key:z6MkEphemeral",
				"address":     "demo.example.com/bot",
				"custody":     "custodial",
				"lifetime":    "ephemeral",
				"public_key":  "",
			})
		case r.URL.Path == "/v1/agents/demo.example.com/bot" && r.Method == http.MethodDelete:
			deletedIdentity.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/workspaces/"+goneID && r.Method == http.MethodDelete:
			deletedWorkspace.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	buildAwBinary(t, ctx, bin)

	state := awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_test",
		IdentityID:      selfID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     selfID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		Alias:           "alice",
		Role:            "developer",
		Hostname:        "devbox",
		WorkspacePath:   tmp,
		CanonicalOrigin: "github.com/acme/repo",
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &state); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !deletedIdentity.Load() {
		t.Fatal("expected gone ephemeral identity deletion by namespace slug")
	}
	if !deletedWorkspace.Load() {
		t.Fatal("expected gone workspace record deletion")
	}
	if !strings.Contains(string(out), "deleted ephemeral identity") {
		t.Fatalf("expected gone-workspace cleanup output, got:\n%s", string(out))
	}
}

func TestAwWorkspaceStatusLeavesWorkspaceWhenIdentityDeleteUnconfirmed(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const goneID = "44444444-4444-4444-4444-444444444444"

	missingPath := filepath.Join(t.TempDir(), "gone-worktree")
	var deletedWorkspace atomic.Bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch {
		case r.URL.Path == "/v1/workspaces/team":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   selfID,
						"alias":          "alice",
						"role":           "developer",
						"status":         "active",
						"hostname":       "devbox",
						"workspace_path": "/tmp/repo",
						"repo":           "github.com/acme/repo",
						"branch":         "main",
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/reservations":
			_ = json.NewEncoder(w).Encode(map[string]any{"reservations": []map[string]any{}})
		case r.URL.Path == "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace":           map[string]any{"project_id": "proj-1", "project_slug": "demo", "workspace_count": 2},
				"agents":              []map[string]any{},
				"claims":              []map[string]any{},
				"conflicts":           []map[string]any{},
				"escalations_pending": 0,
				"timestamp":           "2026-03-10T10:10:00Z",
			})
		case r.URL.Path == "/v1/workspaces" && r.Method == http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{
						"workspace_id":   goneID,
						"alias":          "bob",
						"project_slug":   "demo",
						"status":         "offline",
						"workspace_path": missingPath,
					},
				},
				"has_more": false,
			})
		case r.URL.Path == "/v1/agents/resolve/bob" && r.Method == http.MethodGet:
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"detail":"resolver unavailable"}`))
		case r.URL.Path == "/v1/workspaces/"+goneID && r.Method == http.MethodDelete:
			deletedWorkspace.Store(true)
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_test",
		IdentityID:     selfID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})

	state := awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_test",
		IdentityID:      selfID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     selfID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		Alias:           "alice",
		Role:            "developer",
		Hostname:        "devbox",
		WorkspacePath:   tmp,
		CanonicalOrigin: "github.com/acme/repo",
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &state); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if deletedWorkspace.Load() {
		t.Fatal("did not expect workspace record deletion when identity delete was unconfirmed")
	}
	if !strings.Contains(string(out), "left workspace record intact") {
		t.Fatalf("expected blocked cleanup output, got:\n%s", string(out))
	}
}

func TestAwWorkspaceAddWorktreeCreatesSiblingWorktree(t *testing.T) {
	t.Parallel()

	const sourceID = "11111111-1111-1111-1111-111111111111"
	const newID = "99999999-9999-9999-9999-999999999999"
	const origin = "https://github.com/acme/repo.git"

	var initAuth string
	var registerAuth string
	var registerRole string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/agents/suggest-alias-prefix":
			if r.Header.Get("Authorization") != "Bearer aw_sk_source" {
				t.Fatalf("suggest auth=%q", r.Header.Get("Authorization"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"name_prefix":  "bob",
			})
		case "/api/v1/spawn/create-invite":
			initAuth = r.Header.Get("Authorization")
			srvURL := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id":      "inv-1",
				"token":          "aw_inv_test_worktree",
				"token_prefix":   "aw_inv_test",
				"alias_hint":     "bob",
				"access_mode":    "open",
				"max_uses":       1,
				"expires_at":     "2099-01-01T00:00:00Z",
				"namespace_slug": "demo",
				"namespace":      "demo",
				"server_url":     srvURL,
			})
		case "/api/v1/spawn/accept-invite":
			srvURL := "http://" + r.Host
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode invite accept: %v", err)
			}
			if req["alias"] != "bob" {
				t.Fatalf("alias=%v", req["alias"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"namespace":      "demo",
				"identity_id":    newID,
				"alias":          "bob",
				"api_key":        "aw_sk_new",
				"address":        "demo/bob",
				"server_url":     srvURL,
				"created":        true,
				"did":            "did:key:z6Mktest",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
			})
		case "/v1/workspaces/register":
			registerAuth = r.Header.Get("Authorization")
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode workspace register request: %v", err)
			}
			registerRole, _ = req["role"].(string)
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			if got, ok := req["workspace_path"].(string); !ok || !strings.HasSuffix(got, string(filepath.Separator)+"repo-bob") {
				t.Fatalf("workspace_path=%v", req["workspace_path"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     newID,
				"project_id":       "proj-1",
				"project_slug":     "demo",
				"repo_id":          "repo-1",
				"canonical_origin": "github.com/acme/repo",
				"alias":            "bob",
				"human_name":       "Wendy",
				"created":          true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_source",
		IdentityID:     sourceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})

	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(repo, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_source",
		IdentityID:      sourceID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     sourceID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		CanonicalOrigin: "github.com/acme/repo",
		Alias:           "alice",
		HumanName:       "Wendy",
		Role:            "developer",
		WorkspacePath:   repo,
	}); err != nil {
		t.Fatalf("seed workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "New agent worktree created at") {
		t.Fatalf("unexpected output:\n%s", text)
	}
	if !strings.Contains(text, "Alias:      bob") {
		t.Fatalf("missing alias in output:\n%s", text)
	}
	if !strings.Contains(text, "this worktree is now agent bob") {
		t.Fatalf("missing agent identity guidance in output:\n%s", text)
	}
	if !strings.Contains(text, "aw run codex") {
		t.Fatalf("missing run-first guidance in output:\n%s", text)
	}

	worktreePath := filepath.Join(tmp, "repo-bob")
	if _, err := os.Stat(worktreePath); err != nil {
		t.Fatalf("expected worktree: %v", err)
	}
	if initAuth != "Bearer aw_sk_source" {
		t.Fatalf("init auth=%q", initAuth)
	}
	if registerAuth != "Bearer aw_sk_new" {
		t.Fatalf("workspace register auth=%q", registerAuth)
	}
	if registerRole != "developer" {
		t.Fatalf("workspace register role=%q", registerRole)
	}

	if _, err := os.Stat(filepath.Join(worktreePath, ".aw", "context")); err != nil {
		t.Fatalf("expected .aw/context in new worktree: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(worktreePath, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("read workspace state: %v", err)
	}
	var state awconfig.WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal workspace state: %v", err)
	}
	if state.WorkspaceID != newID {
		t.Fatalf("workspace_id=%s", state.WorkspaceID)
	}
	if state.Role != "developer" {
		t.Fatalf("role=%s", state.Role)
	}

	branchCmd := exec.Command("git", "-C", repo, "branch", "--list", "bob")
	branchOut, err := branchCmd.Output()
	if err != nil {
		t.Fatalf("git branch --list: %v", err)
	}
	if strings.TrimSpace(string(branchOut)) == "" {
		t.Fatalf("expected branch bob, got %q", string(branchOut))
	}
}

func TestAwWorkspaceAddWorktreeRequiresRoleInNonTTYMode(t *testing.T) {
	t.Parallel()

	const sourceID = "11111111-1111-1111-1111-111111111111"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"coordinator": map[string]any{"title": "Coordinator"},
					"developer":   map[string]any{"title": "Developer"},
				},
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
	initGitRepoWithOriginAndCommit(t, repo, "https://github.com/acme/repo.git")
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_source",
		IdentityID:     sourceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree")
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	text := string(out)
	if !strings.Contains(text, "no role specified") {
		t.Fatalf("expected missing role error, got:\n%s", text)
	}
	if !strings.Contains(text, "coordinator") || !strings.Contains(text, "developer") {
		t.Fatalf("expected available roles in error, got:\n%s", text)
	}
}

func TestAwWorkspaceAddWorktreeRejectsInvalidExplicitAlias(t *testing.T) {
	t.Parallel()

	const sourceID = "11111111-1111-1111-1111-111111111111"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
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
	initGitRepoWithOriginAndCommit(t, repo, "https://github.com/acme/repo.git")
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_source",
		IdentityID:     sourceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer", "--alias", "_invalid")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "invalid alias") {
		t.Fatalf("expected invalid alias error, got:\n%s", string(out))
	}
}

func TestAwWorkspaceAddWorktreeRequiresGitWorktree(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		ServerURL:      "https://example.com",
		APIKey:         "aw_sk_source",
		IdentityID:     "source-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer")
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected git worktree error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "workspace add-worktree requires a git worktree") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwWorkspaceAddWorktreeAcceptsExplicitRoleWhenNoProjectRolesExist(t *testing.T) {
	t.Parallel()

	const sourceID = "11111111-1111-1111-1111-111111111111"
	const newID = "99999999-9999-9999-9999-999999999999"
	const origin = "https://github.com/acme/repo.git"

	var registerRole string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles":            map[string]any{},
			})
		case "/api/v1/spawn/create-invite":
			srvURL := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id":      "inv-1",
				"token":          "aw_inv_test_worktree",
				"token_prefix":   "aw_inv_test",
				"alias_hint":     "bob",
				"access_mode":    "open",
				"max_uses":       1,
				"expires_at":     "2099-01-01T00:00:00Z",
				"namespace_slug": "demo",
				"namespace":      "demo",
				"server_url":     srvURL,
			})
		case "/api/v1/spawn/accept-invite":
			srvURL := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id":     "proj-1",
				"project_slug":   "demo",
				"namespace_slug": "demo",
				"namespace":      "demo",
				"identity_id":    newID,
				"alias":          "bob",
				"api_key":        "aw_sk_new",
				"address":        "demo/bob",
				"server_url":     srvURL,
				"created":        true,
				"did":            "did:key:z6Mktest",
				"custody":        "self",
				"lifetime":       "ephemeral",
				"access_mode":    "open",
			})
		case "/v1/workspaces/register":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode workspace register request: %v", err)
			}
			registerRole, _ = req["role"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     newID,
				"project_id":       "proj-1",
				"project_slug":     "demo",
				"repo_id":          "repo-1",
				"canonical_origin": "github.com/acme/repo",
				"alias":            "bob",
				"human_name":       "Wendy",
				"created":          true,
			})
		case "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_slug": "demo",
				"name_prefix":  "bob",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_source",
		IdentityID:     sourceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})

	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer", "--alias", "bob")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "New agent worktree created at") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if registerRole != "developer" {
		t.Fatalf("register role=%q", registerRole)
	}
}

func TestAwWorkspaceAddWorktreeExplicitAliasCreatesSiblingWorktree(t *testing.T) {
	t.Parallel()

	const sourceID = "11111111-1111-1111-1111-111111111111"
	const newID = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
	const origin = "https://github.com/acme/repo.git"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/spawn/create-invite":
			srvURL := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id": "inv-1", "token": "aw_inv_carol", "token_prefix": "aw_inv_c",
				"max_uses": 1, "expires_at": "2099-01-01T00:00:00Z", "namespace_slug": "demo", "namespace": "demo", "server_url": srvURL, "access_mode": "open",
			})
		case "/api/v1/spawn/accept-invite":
			srvURL := "http://" + r.Host
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			if req["alias"] != "carol" {
				t.Fatalf("alias=%v", req["alias"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_id": "proj-1", "project_slug": "demo",
				"namespace_slug": "demo", "namespace": "demo", "identity_id": newID, "alias": "carol", "api_key": "aw_sk_new",
				"address": "demo/carol", "server_url": srvURL, "created": true,
				"did": "did:key:z6Mktest", "custody": "self", "lifetime": "ephemeral", "access_mode": "open",
			})
		case "/v1/workspaces/register":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode workspace register request: %v", err)
			}
			if req["role"] != "developer" {
				t.Fatalf("role=%v", req["role"])
			}
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     newID,
				"project_id":       "proj-1",
				"project_slug":     "demo",
				"repo_id":          "repo-1",
				"canonical_origin": "github.com/acme/repo",
				"alias":            "carol",
				"human_name":       "Wendy",
				"created":          true,
			})
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/agents/suggest-alias-prefix":
			t.Fatalf("unexpected alias suggestion call for explicit --alias")
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_source",
		IdentityID:     sourceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(repo, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_source",
		IdentityID:      sourceID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     sourceID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		CanonicalOrigin: "github.com/acme/repo",
		Alias:           "alice",
		HumanName:       "Wendy",
		Role:            "developer",
		WorkspacePath:   repo,
	}); err != nil {
		t.Fatalf("seed workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer", "--alias", "carol")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Alias:      carol") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if _, err := os.Stat(filepath.Join(tmp, "repo-carol")); err != nil {
		t.Fatalf("expected worktree: %v", err)
	}
}

func TestAwWorkspaceAddWorktreeCleansUpOnInitFailure(t *testing.T) {
	t.Parallel()

	const sourceID = "11111111-1111-1111-1111-111111111111"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/api/v1/spawn/create-invite":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error": map[string]any{
					"code":    "NOT_ALIAS_RELATED",
					"message": "invite creation failed",
				},
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, "https://github.com/acme/repo.git")
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_source",
		IdentityID:     sourceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(repo, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_source",
		IdentityID:      sourceID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     sourceID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		CanonicalOrigin: "github.com/acme/repo",
		Alias:           "alice",
		HumanName:       "Wendy",
		Role:            "developer",
		WorkspacePath:   repo,
	}); err != nil {
		t.Fatalf("seed workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer", "--alias", "dave")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "Cleaning up worktree") {
		t.Fatalf("expected cleanup message, got:\n%s", string(out))
	}

	worktreePath := filepath.Join(tmp, "repo-dave")
	if _, err := os.Stat(worktreePath); !os.IsNotExist(err) {
		t.Fatalf("expected worktree cleanup, stat err=%v", err)
	}

	branchCmd := exec.Command("git", "-C", repo, "branch", "--list", "dave")
	branchOut, err := branchCmd.Output()
	if err != nil {
		t.Fatalf("git branch --list: %v", err)
	}
	if strings.TrimSpace(string(branchOut)) != "" {
		t.Fatalf("expected branch cleanup, got %q", string(branchOut))
	}
}

func TestAwWorkspaceAddWorktreeRetriesAliasTakenSuggestion(t *testing.T) {
	t.Parallel()

	const sourceID = "11111111-1111-1111-1111-111111111111"
	const newID = "bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"
	const origin = "https://github.com/acme/repo.git"

	var suggestCalls int
	var initCalls int

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"project_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/agents/suggest-alias-prefix":
			suggestCalls++
			switch suggestCalls {
			case 1:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"project_slug": "demo",
					"name_prefix":  "alice-123",
				})
			case 2:
				_ = json.NewEncoder(w).Encode(map[string]any{
					"project_slug": "demo",
					"name_prefix":  "bob-3",
				})
			default:
				t.Fatalf("unexpected suggest call %d", suggestCalls)
			}
		case "/api/v1/spawn/create-invite":
			initCalls++
			srvURL := "http://" + r.Host
			_ = json.NewEncoder(w).Encode(map[string]any{
				"invite_id": fmt.Sprintf("inv-%d", initCalls), "token": fmt.Sprintf("aw_inv_test_%d", initCalls),
				"token_prefix": "aw_inv_t", "max_uses": 1, "expires_at": "2099-01-01T00:00:00Z",
				"namespace_slug": "demo", "namespace": "demo", "server_url": srvURL, "access_mode": "open",
			})
		case "/api/v1/spawn/accept-invite":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			alias, _ := req["alias"].(string)
			srvURL := "http://" + r.Host
			switch {
			case alias == "alice-123":
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{
					"error": map[string]any{
						"code":    "ALIAS_TAKEN",
						"message": "alias already taken",
						"details": map[string]any{"attempted_alias": "alice-123"},
					},
				})
			case alias == "bob-3":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"project_id": "proj-1", "project_slug": "demo",
					"namespace_slug": "demo", "namespace": "demo", "identity_id": newID, "alias": "bob-3", "api_key": "aw_sk_new",
					"address": "demo/bob-3", "server_url": srvURL, "created": true,
					"did": "did:key:z6Mktest", "custody": "self", "lifetime": "ephemeral", "access_mode": "open",
				})
			default:
				t.Fatalf("unexpected alias in accept: %v", alias)
			}
		case "/v1/workspaces/register":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatalf("decode workspace register request: %v", err)
			}
			if req["role"] != "developer" {
				t.Fatalf("role=%v", req["role"])
			}
			if req["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", req["repo_origin"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace_id":     newID,
				"project_id":       "proj-1",
				"project_slug":     "demo",
				"repo_id":          "repo-1",
				"canonical_origin": "github.com/acme/repo",
				"alias":            "bob-3",
				"human_name":       "Wendy",
				"created":          true,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		ServerURL:      server.URL,
		APIKey:         "aw_sk_source",
		IdentityID:     sourceID,
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		ProjectSlug:    "demo",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(repo, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		ServerURL:       server.URL,
		APIKey:          "aw_sk_source",
		IdentityID:      sourceID,
		IdentityHandle:  "alice",
		NamespaceSlug:   "demo",
		WorkspaceID:     sourceID,
		ProjectID:       "proj-1",
		ProjectSlug:     "demo",
		CanonicalOrigin: "github.com/acme/repo",
		Alias:           "alice",
		HumanName:       "Wendy",
		Role:            "developer",
		WorkspacePath:   repo,
	}); err != nil {
		t.Fatalf("seed workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer")
	run.Env = testCommandEnv(tmp)
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	if suggestCalls != 2 {
		t.Fatalf("suggestCalls=%d", suggestCalls)
	}
	if initCalls != 2 {
		t.Fatalf("initCalls=%d", initCalls)
	}
	if !strings.Contains(string(out), "Alias:      bob-3") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if _, err := os.Stat(filepath.Join(tmp, "repo-bob-3")); err != nil {
		t.Fatalf("expected retried worktree: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, "repo-alice-123")); !os.IsNotExist(err) {
		t.Fatalf("expected failed first worktree cleanup, stat err=%v", err)
	}
}
