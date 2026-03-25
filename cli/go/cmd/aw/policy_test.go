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

func TestAwPolicyShowUsesWorkspaceRole(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/policies/active":
			if r.URL.Query().Get("role") != "reviewer" {
				t.Fatalf("role=%q", r.URL.Query().Get("role"))
			}
			if r.URL.Query().Get("only_selected") != "true" {
				t.Fatalf("only_selected=%q", r.URL.Query().Get("only_selected"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"policy_id":  "pol-1",
				"project_id": "proj-1",
				"version":    3,
				"updated_at": "2026-03-10T10:00:00Z",
				"invariants": []map[string]any{
					{"id": "no-drift", "title": "No Drift", "body_md": "Keep the stack clean."},
				},
				"roles": map[string]any{
					"reviewer": map[string]any{"title": "Reviewer", "playbook_md": "Review before merge."},
				},
				"selected_role": map[string]any{
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    identity_id: agent-1
    identity_handle: alice
    namespace_slug: demo
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(tmp, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &awconfig.WorktreeWorkspace{
		WorkspaceID: "agent-1",
		Role:        "reviewer",
	}); err != nil {
		t.Fatalf("save workspace state: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "policy", "show")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"Policy v3",
		"Role: reviewer",
		"## Invariants",
		"No Drift",
		"Keep the stack clean.",
		"## Role: Reviewer",
		"Review before merge.",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("policy show output missing %q:\n%s", want, text)
		}
	}
}

func TestAwPolicyRolesListsSortedRoles(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer aw_sk_test" {
			t.Fatalf("auth=%q", r.Header.Get("Authorization"))
		}
		switch r.URL.Path {
		case "/v1/policies/active":
			if r.URL.Query().Get("only_selected") != "false" {
				t.Fatalf("only_selected=%q", r.URL.Query().Get("only_selected"))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"policy_id":  "pol-1",
				"project_id": "proj-1",
				"version":    1,
				"updated_at": "2026-03-10T10:00:00Z",
				"invariants": []map[string]any{},
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
	cfgPath := filepath.Join(tmp, "config.yaml")
	buildAwBinary(t, ctx, bin)

	if err := os.WriteFile(cfgPath, []byte(strings.TrimSpace(`
servers:
  local:
    url: `+server.URL+`
accounts:
  acct:
    server: local
    api_key: aw_sk_test
    identity_id: agent-1
    identity_handle: alice
    namespace_slug: demo
default_account: acct
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "policy", "roles")
	run.Env = append(os.Environ(),
		"AW_CONFIG_PATH="+cfgPath,
		"AWEB_URL=",
		"AWEB_API_KEY=",
	)
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
