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

func TestAwRolesShowUsesWorkspaceRoleName(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/active":
			if r.URL.Query().Get("role_name") != "reviewer" {
				t.Fatalf("role_name=%q", r.URL.Query().Get("role_name"))
			}
			if r.URL.Query().Get("only_selected") != "true" {
				t.Fatalf("only_selected=%q", r.URL.Query().Get("only_selected"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id":        "roles-1",
				"active_team_roles_id": "roles-1",
				"team_address":         "proj-1",
				"version":              3,
				"updated_at":           "2026-03-10T10:00:00Z",
				"roles": map[string]any{
					"reviewer": map[string]any{"title": "Reviewer", "playbook_md": "Review before merge."},
				},
				"selected_role": map[string]any{
					"role_name":   "reviewer",
					"role":        "reviewer",
					"title":       "Reviewer",
					"playbook_md": "Review before merge.",
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
	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		AwebURL:        server.URL,
		TeamAddress:    "demo/backend",
		IdentityID:     "agent-1",
		IdentityHandle: "alice",
		NamespaceSlug:  "demo",
		WorkspaceID:    "agent-1",
		ProjectSlug:    "demo",
		Role:           "reviewer",
	}); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "roles", "show")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"Team Roles v3",
		"Role: reviewer",
		"## Role: Reviewer",
		"Review before merge.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("roles show output missing %q:\n%s", want, text)
		}
	}
}

func TestAwRolesListListsSortedRoles(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/active":
			if r.URL.Query().Get("only_selected") != "false" {
				t.Fatalf("only_selected=%q", r.URL.Query().Get("only_selected"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "roles-1",
				"team_address":  "proj-1",
				"version":       1,
				"updated_at":    "2026-03-10T10:00:00Z",
				"roles": map[string]any{
					"reviewer":  map[string]any{"title": "Reviewer", "playbook_md": ""},
					"developer": map[string]any{"title": "Developer", "playbook_md": ""},
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
	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "roles", "list")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 role lines, got %d:\n%s", len(lines), text)
	}
	if !strings.HasPrefix(lines[0], "developer") || !strings.HasPrefix(lines[1], "reviewer") {
		t.Fatalf("roles not sorted:\n%s", text)
	}
}

func TestAwRolesShowAllRolesRendersPlaybooks(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/active":
			if r.URL.Query().Get("only_selected") != "false" {
				t.Fatalf("only_selected=%q", r.URL.Query().Get("only_selected"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "roles-2",
				"team_address":  "proj-1",
				"version":       2,
				"updated_at":    "2026-03-10T10:00:00Z",
				"roles": map[string]any{
					"reviewer":  map[string]any{"title": "Reviewer", "playbook_md": "Review carefully."},
					"developer": map[string]any{"title": "Developer", "playbook_md": "Ship the change."},
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
	buildAwBinary(t, ctx, bin)
	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "roles", "show", "--all-roles")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"## Roles",
		"### Developer",
		"Ship the change.",
		"### Reviewer",
		"Review carefully.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("roles show --all-roles output missing %q:\n%s", want, text)
		}
	}
}

func TestAwRolesHistoryListsVersions(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/history":
			if got := r.URL.Query().Get("limit"); got != "5" {
				t.Fatalf("limit=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_versions": []map[string]any{
					{
						"team_roles_id":    "roles-2",
						"version":          2,
						"created_at":       "2026-03-11T10:00:00Z",
						"created_by_alias": "ivy",
						"is_active":        true,
					},
					{
						"team_roles_id":    "roles-1",
						"version":          1,
						"created_at":       "2026-03-10T10:00:00Z",
						"created_by_alias": "ivy",
						"is_active":        false,
					},
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
	buildAwBinary(t, ctx, bin)
	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "roles", "history", "--limit", "5")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"v2\tactive\t2026-03-11T10:00:00Z\troles-2\tivy",
		"v1\tinactive\t2026-03-10T10:00:00Z\troles-1\tivy",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("roles history output missing %q:\n%s", want, text)
		}
	}
}

func TestAwRolesSetCreatesAndActivatesNewVersion(t *testing.T) {
	t.Parallel()

	var createBody map[string]any
	var activatedPath string

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id":        "roles-1",
				"active_team_roles_id": "roles-1",
				"team_address":         "proj-1",
				"version":              1,
				"updated_at":           "2026-03-10T10:00:00Z",
				"roles":                map[string]any{},
				"adapters":             map[string]any{},
			})
		case "/v1/roles":
			if r.Method != http.MethodPost {
				t.Fatalf("method=%s", r.Method)
			}
			if err := json.NewDecoder(r.Body).Decode(&createBody); err != nil {
				t.Fatalf("decode create body: %v", err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "roles-2",
				"team_address":  "proj-1",
				"version":       2,
				"created":       true,
			})
		case "/v1/roles/roles-2/activate":
			activatedPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activated":            true,
				"active_team_roles_id": "roles-2",
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
	buildAwBinary(t, ctx, bin)
	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "roles", "set", "--bundle-file", "-")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	run.Stdin = strings.NewReader(`{"roles":{"reviewer":{"title":"Reviewer","playbook_md":"Review carefully."}}}`)
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if activatedPath != "/v1/roles/roles-2/activate" {
		t.Fatalf("activate path=%q", activatedPath)
	}

	bundle, ok := createBody["bundle"].(map[string]any)
	if !ok {
		t.Fatalf("bundle=%#v", createBody["bundle"])
	}
	if createBody["base_team_roles_id"] != "roles-1" {
		t.Fatalf("base_team_roles_id=%v", createBody["base_team_roles_id"])
	}
	roles, ok := bundle["roles"].(map[string]any)
	if !ok {
		t.Fatalf("roles=%#v", bundle["roles"])
	}
	reviewer, ok := roles["reviewer"].(map[string]any)
	if !ok {
		t.Fatalf("reviewer=%#v", roles["reviewer"])
	}
	if reviewer["title"] != "Reviewer" || reviewer["playbook_md"] != "Review carefully." {
		t.Fatalf("reviewer=%#v", reviewer)
	}
	if _, ok := bundle["adapters"]; ok {
		t.Fatalf("adapters should be omitted when not provided: %#v", bundle["adapters"])
	}

	if !strings.Contains(string(out), "Activated team roles v2 (roles-2)") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwRolesActivateActivatesExistingVersion(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/roles-2/activate":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"activated":            true,
				"active_team_roles_id": "roles-2",
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
	buildAwBinary(t, ctx, bin)
	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "roles", "activate", "roles-2")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Activated team roles roles-2") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwRolesResetResetsToDefault(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/reset":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"reset":                true,
				"active_team_roles_id": "roles-3",
				"version":              3,
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
	buildAwBinary(t, ctx, bin)
	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "roles", "reset")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Reset team roles to default (v3, roles-3)") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwRolesDeactivateDeactivatesToEmptyBundle(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/roles/deactivate":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"deactivated":          true,
				"active_team_roles_id": "roles-4",
				"version":              4,
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
	buildAwBinary(t, ctx, bin)
	writeTestConfig(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "roles", "deactivate")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Deactivated team roles (v4, roles-4)") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}
