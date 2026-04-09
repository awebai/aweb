package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
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

func TestAwWorkspaceStatusShowsTeamState(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const peerID = "44444444-4444-4444-4444-444444444444"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
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
						"resource_key":    "src/main.go",
						"holder_agent_id": selfID,
						"holder_alias":    "alice",
						"acquired_at":     "2026-03-10T10:00:00Z",
						"expires_at":      "2099-03-10T10:00:00Z",
						"metadata":        map[string]any{},
					},
					{
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
				"workspace":           map[string]any{"workspace_count": 2},
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
		AwebURL:         server.URL,
		TeamAddress:     "demo/backend",
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
	writeWorkspaceBindingForTest(t, tmp, state)

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
		requireCertificateAuthForTest(t, r)
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
				"workspace":           map[string]any{"workspace_count": 1},
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
		AwebURL:        server.URL,
		TeamAddress:    "demo/backend",
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
		requireCertificateAuthForTest(t, r)
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
					{"resource_key": "src/1.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
					{"resource_key": "src/2.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
					{"resource_key": "src/3.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
					{"resource_key": "src/4.go", "holder_agent_id": peerID, "holder_alias": "bob", "acquired_at": "2026-03-10T10:00:00Z", "expires_at": "2099-03-10T10:00:00Z", "metadata": map[string]any{}},
				},
			})
		case "/v1/status":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspace": map[string]any{"workspace_count": 2},
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
		AwebURL:        server.URL,
		TeamAddress:    "demo/backend",
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
		requireCertificateAuthForTest(t, r)
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
				"workspace":           map[string]any{"workspace_count": 2},
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
		AwebURL:         server.URL,
		TeamAddress:     "demo/backend",
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
	writeWorkspaceBindingForTest(t, tmp, state)

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if deletedIdentity.Load() {
		t.Fatal("identity deletion should be skipped; lifecycle managed by team membership")
	}
	if !deletedWorkspace.Load() {
		t.Fatal("expected gone workspace record deletion")
	}
	if !strings.Contains(string(out), "removed workspace record") {
		t.Fatalf("expected gone-workspace cleanup output, got:\n%s", string(out))
	}
}

func TestAwWorkspaceStatusKeepsGonePersistentIdentity(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const goneID = "44444444-4444-4444-4444-444444444444"

	missingPath := filepath.Join(t.TempDir(), "gone-worktree")
	var deletedIdentity atomic.Bool
	var deletedWorkspace atomic.Bool

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
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
				"workspace":           map[string]any{"workspace_count": 2},
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
				"did":         "did:key:z6MkPersistent",
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
		AwebURL:         server.URL,
		TeamAddress:     "demo/backend",
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
	writeWorkspaceBindingForTest(t, tmp, state)

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if deletedIdentity.Load() {
		t.Fatal("did not expect persistent identity deletion")
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
		requireCertificateAuthForTest(t, r)
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
				"workspace":           map[string]any{"workspace_count": 2},
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
		AwebURL:         server.URL,
		TeamAddress:     "demo/backend",
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
	writeWorkspaceBindingForTest(t, tmp, state)

	run := exec.CommandContext(ctx, bin, "workspace", "status")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if deletedIdentity.Load() {
		t.Fatal("identity deletion should be skipped; lifecycle managed by team membership")
	}
	if !deletedWorkspace.Load() {
		t.Fatal("expected gone workspace record deletion")
	}
	if !strings.Contains(string(out), "removed workspace record") {
		t.Fatalf("expected gone-workspace cleanup output, got:\n%s", string(out))
	}
}

func TestAwWorkspaceAddWorktreeCreatesSiblingWorktree(t *testing.T) {
	t.Parallel()

	const origin = "https://github.com/acme/repo.git"
	const teamAddress = "source/backend"

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var registeredCert map[string]any
	var connectBody map[string]any
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/agents/suggest-alias-prefix":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_address": teamAddress,
				"name_prefix":  "charlie",
			})
		case "/v1/namespaces/source/teams/backend/certificates":
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatalf("decode registered certificate: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		case "/v1/connect":
			requireCertificateAuthForTest(t, r)
			if err := json.NewDecoder(r.Body).Decode(&connectBody); err != nil {
				t.Fatalf("decode connect request: %v", err)
			}
			if connectBody["repo_origin"] != origin {
				t.Fatalf("repo_origin=%v", connectBody["repo_origin"])
			}
			role, _ := connectBody["role"].(string)
			if role != "developer" {
				t.Fatalf("role=%q", role)
			}
			path, _ := connectBody["workspace_path"].(string)
			if !strings.HasSuffix(path, string(filepath.Separator)+"repo-charlie") {
				t.Fatalf("workspace_path=%q", path)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_address": teamAddress,
				"alias":        "charlie",
				"agent_id":     "agent-3",
				"workspace_id": "workspace-3",
				"repo_id":      "repo-3",
				"team_did_key": "did:key:z6MkTeam",
				"role":         "developer",
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	writeTeamKeyForTest(t, tmp, "source", "backend", teamKey)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(repo, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:            "did:key:z6MkParent",
		StableID:       "did:aw:parent",
		Address:        "source/alice",
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    server.URL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-08T00:00:00Z",
	}); err != nil {
		t.Fatalf("seed identity.yaml: %v", err)
	}
	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		AwebURL:        server.URL,
		TeamAddress:    teamAddress,
		IdentityID:     "source-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "source",
		ProjectSlug:    "source",
		HumanName:      "Wendy",
		AgentType:      "agent",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer")
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("expected success, got error: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "New agent worktree created at") {
		t.Fatalf("unexpected output:\n%s", text)
	}
	if registeredCert["alias"] != "charlie" {
		t.Fatalf("registered alias=%v", registeredCert["alias"])
	}
	if registeredCert["lifetime"] != awid.LifetimeEphemeral {
		t.Fatalf("registered lifetime=%v", registeredCert["lifetime"])
	}

	child := filepath.Join(tmp, "repo-charlie")
	if _, err := os.Stat(child); err != nil {
		t.Fatalf("expected sibling worktree: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(child, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("read child workspace binding: %v", err)
	}
	var state awconfig.WorktreeWorkspace
	if err := yaml.Unmarshal(data, &state); err != nil {
		t.Fatalf("unmarshal child workspace binding: %v", err)
	}
	if state.TeamAddress != teamAddress {
		t.Fatalf("child team_address=%q", state.TeamAddress)
	}
	if state.Alias != "charlie" {
		t.Fatalf("child alias=%q", state.Alias)
	}
	if state.WorkspaceID != "workspace-3" {
		t.Fatalf("child workspace_id=%q", state.WorkspaceID)
	}

	cert, err := awid.LoadTeamCertificate(filepath.Join(child, ".aw", "team-cert.pem"))
	if err != nil {
		t.Fatalf("load child team certificate: %v", err)
	}
	if cert.Alias != "charlie" {
		t.Fatalf("cert alias=%q", cert.Alias)
	}
	if cert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("cert lifetime=%q", cert.Lifetime)
	}
	if _, err := os.Stat(filepath.Join(child, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("ephemeral worktree should not create identity.yaml, stat err=%v", err)
	}
}

func TestAwWorkspaceAddWorktreeRevokesCertificateWhenConnectFails(t *testing.T) {
	t.Parallel()

	const origin = "https://github.com/acme/repo.git"
	const teamAddress = "source/backend"

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var registeredCert map[string]any
	var revokedCert map[string]any
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/agents/suggest-alias-prefix":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_address": teamAddress,
				"name_prefix":  "charlie",
			})
		case "/v1/namespaces/source/teams/backend/certificates":
			if err := json.NewDecoder(r.Body).Decode(&registeredCert); err != nil {
				t.Fatalf("decode registered certificate: %v", err)
			}
			w.WriteHeader(http.StatusCreated)
		case "/v1/namespaces/source/teams/backend/certificates/revoke":
			if err := json.NewDecoder(r.Body).Decode(&revokedCert); err != nil {
				t.Fatalf("decode revoked certificate: %v", err)
			}
			w.WriteHeader(http.StatusOK)
		case "/v1/connect":
			requireCertificateAuthForTest(t, r)
			http.Error(w, "alias conflict", http.StatusConflict)
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, origin)
	buildAwBinary(t, ctx, bin)

	writeTeamKeyForTest(t, tmp, "source", "backend", teamKey)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(repo, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:            "did:key:z6MkParent",
		StableID:       "did:aw:parent",
		Address:        "source/alice",
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    server.URL,
		RegistryStatus: "registered",
		CreatedAt:      "2026-04-08T00:00:00Z",
	}); err != nil {
		t.Fatalf("seed identity.yaml: %v", err)
	}
	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		AwebURL:        server.URL,
		TeamAddress:    teamAddress,
		IdentityID:     "source-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "source",
		ProjectSlug:    "source",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer")
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "connect new worktree") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
	if registeredCert["certificate_id"] == nil || registeredCert["certificate_id"] == "" {
		t.Fatalf("registered certificate_id=%v", registeredCert["certificate_id"])
	}
	if revokedCert["certificate_id"] != registeredCert["certificate_id"] {
		t.Fatalf("revoked certificate_id=%v want %v", revokedCert["certificate_id"], registeredCert["certificate_id"])
	}

	child := filepath.Join(tmp, "repo-charlie")
	if _, err := os.Stat(child); !os.IsNotExist(err) {
		t.Fatalf("expected failed child worktree cleanup, stat err=%v", err)
	}
}

func TestAwWorkspaceAddWorktreeRejectsAliasAlreadyInUse(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/roles/active":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "pol-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case "/v1/workspaces/team":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"workspaces": []map[string]any{
					{"workspace_id": "source-1", "alias": "alice", "status": "active"},
					{"workspace_id": "source-2", "alias": "bob", "status": "offline"},
				},
				"has_more": false,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, "https://github.com/acme/repo.git")
	buildAwBinary(t, ctx, bin)

	writeWorkspaceBindingForTest(t, repo, awconfig.WorktreeWorkspace{
		AwebURL:        server.URL,
		TeamAddress:    "source/backend",
		IdentityID:     "source-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "source",
		ProjectSlug:    "source",
	})
	if err := awconfig.SaveWorktreeContextTo(filepath.Join(repo, ".aw", "context"), &awconfig.WorktreeContext{}); err != nil {
		t.Fatalf("seed .aw/context: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer", "--alias", "bob")
	run.Env = testCommandEnv(tmp)
	run.Stdin = strings.NewReader("")
	run.Dir = repo
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), `alias "bob" is already in use by this team`) {
		t.Fatalf("unexpected output:\n%s", string(out))
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
		AwebURL:        "https://example.com",
		TeamAddress:    "source/backend",
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

func TestResolveWorkspaceTeamRegistryURLRejectsEmptyControllerRegistry(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	if err := awconfig.SaveControllerMeta("source", &awconfig.ControllerMeta{
		Domain:      "source",
		RegistryURL: "  ",
		CreatedAt:   "2026-04-08T00:00:00Z",
	}); err != nil {
		t.Fatalf("save controller meta: %v", err)
	}

	registryURL, err := resolveWorkspaceTeamRegistryURL(t.TempDir(), "https://app.aweb.ai", "source")
	if err == nil {
		t.Fatalf("expected error, got registry_url=%q", registryURL)
	}
	if registryURL != "" {
		t.Fatalf("registry_url=%q", registryURL)
	}
	if !strings.Contains(err.Error(), "missing identity registry_url") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveWorkspaceTeamRegistryURLPrefersControllerRegistryOverIdentity(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	workingDir := t.TempDir()
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(workingDir, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:         "did:key:z6MkMember",
		RegistryURL: "https://member-registry.example",
		CreatedAt:   "2026-04-08T00:00:00Z",
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	if err := awconfig.SaveControllerMeta("source", &awconfig.ControllerMeta{
		Domain:      "source",
		RegistryURL: "https://team-registry.example",
		CreatedAt:   "2026-04-08T00:00:00Z",
	}); err != nil {
		t.Fatalf("save controller meta: %v", err)
	}

	registryURL, err := resolveWorkspaceTeamRegistryURL(workingDir, "https://app.aweb.ai", "source")
	if err != nil {
		t.Fatalf("resolveWorkspaceTeamRegistryURL: %v", err)
	}
	if registryURL != "https://team-registry.example" {
		t.Fatalf("registry_url=%q", registryURL)
	}
}
