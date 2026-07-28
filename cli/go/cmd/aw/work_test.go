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
	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "backend:demo", "alice", selfID))

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

	recentActivity := time.Now().UTC().Add(-2 * time.Hour).Format(time.RFC3339)
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
						"task_ref":           "TASK-020",
						"title":              "Claim-backed task",
						"priority":           2,
						"task_type":          "bug",
						"status":             "in_progress",
						"owner_alias":        "bob",
						"canonical_origin":   "github.com/awebai/aweb",
						"branch":             "feat/summary",
						"claimed_at":         "2026-03-10T10:00:00Z",
						"owner_last_seen_at": recentActivity,
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
	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "backend:demo", "self", "agent-self"))

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
		"  TASK-020  P2  [bug] Claim-backed task  bob  feat/summary  [claim age: months; claimant activity: under a day]",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("active output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "alice  main") {
		t.Fatalf("active output should hide main/master branches:\n%s", text)
	}
	if strings.Contains(text, "[stale]") {
		t.Fatalf("active output must report evidence without a stale-policy verdict:\n%s", text)
	}
}

func TestAwWorkActiveJSONReportsUnknownClaimantActivity(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requireCertificateAuthForTest(t, r)
		switch r.URL.Path {
		case "/v1/tasks/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": []map[string]any{
					{
						"task_ref":    "TASK-CLAIM",
						"title":       "Claim with unknown activity",
						"priority":    1,
						"task_type":   "task",
						"status":      "in_progress",
						"owner_alias": "alice",
						"claimed_at":  "2026-03-10T10:00:00Z",
					},
					{
						"task_ref":    "TASK-ASSIGNEE",
						"title":       "Assigned without a claim",
						"priority":    2,
						"task_type":   "task",
						"status":      "in_progress",
						"owner_alias": "bob",
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
	writeWorkspaceBindingForTest(t, tmp, workspaceBinding(server.URL, "backend:demo", "self", "agent-self"))

	run := exec.CommandContext(ctx, bin, "--json", "work", "active")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}

	var payload map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &payload); err != nil {
		t.Fatalf("invalid work JSON: %v\n%s", err, string(out))
	}
	items := payload["items"].([]any)
	claim := items[0].(map[string]any)
	if claim["claim_age_band"] != "months" {
		t.Fatalf("claim_age_band=%v", claim["claim_age_band"])
	}
	if claim["claimant_activity_age_band"] != "unknown" {
		t.Fatalf("claimant_activity_age_band=%v", claim["claimant_activity_age_band"])
	}
	assigneeOnly := items[1].(map[string]any)
	if _, ok := assigneeOnly["claim_age_band"]; ok {
		t.Fatalf("assignee-only item unexpectedly has claim evidence: %#v", assigneeOnly)
	}
	if _, ok := assigneeOnly["claimant_activity_age_band"]; ok {
		t.Fatalf("assignee-only item unexpectedly has claimant activity evidence: %#v", assigneeOnly)
	}
}

func TestCoordinationAgeBandAt(t *testing.T) {
	now := time.Date(2026, 7, 28, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		timestamp string
		want      string
	}{
		{name: "future clock skew", timestamp: "2026-07-28T13:00:00Z", want: "under a day"},
		{name: "under a day", timestamp: "2026-07-27T13:00:00Z", want: "under a day"},
		{name: "days at one day", timestamp: "2026-07-27T12:00:00Z", want: "days"},
		{name: "weeks at seven days", timestamp: "2026-07-21T12:00:00Z", want: "weeks"},
		{name: "months at thirty days", timestamp: "2026-06-28T12:00:00Z", want: "months"},
		{name: "unknown", timestamp: "", want: "unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := coordinationAgeBandAt(tc.timestamp, now); got != tc.want {
				t.Fatalf("coordinationAgeBandAt(%q)=%q want %q", tc.timestamp, got, tc.want)
			}
		})
	}
}
