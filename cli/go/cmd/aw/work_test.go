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

	"github.com/awebai/aw/awconfig"
)

func TestAwWorkReadyFiltersClaimsHeldByOthers(t *testing.T) {
	t.Parallel()

	const selfID = "11111111-1111-1111-1111-111111111111"
	const otherID = "22222222-2222-2222-2222-222222222222"

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/claims":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"claims": []map[string]any{
					{
						"bead_id":      "TASK-002",
						"workspace_id": otherID,
						"alias":        "bob",
						"human_name":   "Bob",
						"claimed_at":   "2026-03-10T10:00:00Z",
					},
				},
				"has_more": false,
			})
		case "/v1/tasks/ready":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": []map[string]any{
					{"task_ref": "TASK-001", "title": "Unclaimed ready task", "priority": 1, "task_type": "task", "status": "open"},
					{"task_ref": "TASK-002", "title": "Claimed elsewhere", "priority": 2, "task_type": "bug", "status": "open"},
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
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		AwebURL:     server.URL,
		TeamID:      "backend:demo",
		Alias:       "alice",
		WorkspaceID: selfID,
	})

	run := exec.CommandContext(ctx, bin, "work", "ready")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "TASK-001") {
		t.Fatalf("ready output missing unclaimed task:\n%s", text)
	}
	if strings.Contains(text, "TASK-002") {
		t.Fatalf("ready output should filter claimed task:\n%s", text)
	}
}

func TestAwWorkActiveGroupsByRepo(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/tasks/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": []map[string]any{
					{
						"task_ref":         "TASK-010",
						"title":            "Native task",
						"priority":         1,
						"task_type":        "task",
						"status":           "in_progress",
						"owner_alias":      "alice",
						"canonical_origin": "github.com/awebai/ac",
						"branch":           "main",
					},
					{
						"task_ref":         "TASK-020",
						"title":            "Claim-backed task",
						"priority":         2,
						"task_type":        "bug",
						"status":           "in_progress",
						"owner_alias":      "bob",
						"canonical_origin": "github.com/awebai/aweb",
						"branch":           "feat/summary",
						"claimed_at":       "2026-03-10T10:00:00Z",
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
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		AwebURL:     server.URL,
		TeamID:      "backend:demo",
		Alias:       "self",
		WorkspaceID: "agent-self",
	})

	run := exec.CommandContext(ctx, bin, "work", "active")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"Active work (2):",
		"## github.com/awebai/ac",
		"  TASK-010  P1  [task] Native task  alice",
		"## github.com/awebai/aweb",
		"  TASK-020  P2  [bug] Claim-backed task  bob  feat/summary",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("active output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "alice  main") {
		t.Fatalf("active output should hide main/master branches:\n%s", text)
	}
}
