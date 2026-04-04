package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAwTaskCreateRequiresTitle(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no API call expected, got %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "create")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for missing --title, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--title is required") {
		t.Fatalf("expected '--title is required' error, got:\n%s", string(out))
	}
}

func TestAwTaskCreateSuccess(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &gotReq)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id":     "tid-1",
				"task_ref":    "PROJ-001",
				"task_number": 1,
				"title":       gotReq["title"],
				"status":      "open",
				"priority":    gotReq["priority"],
				"task_type":   gotReq["task_type"],
				"created_at":  "2026-03-21T10:00:00Z",
				"updated_at":  "2026-03-21T10:00:00Z",
			})
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "create",
		"--title", "Fix the bug",
		"--type", "bug",
		"--priority", "P1",
		"--description", "Detailed description",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "PROJ-001") {
		t.Fatalf("output missing task ref:\n%s", text)
	}
	if !strings.Contains(text, "Fix the bug") {
		t.Fatalf("output missing title:\n%s", text)
	}

	// Verify request payload
	if gotReq["title"] != "Fix the bug" {
		t.Fatalf("title=%v", gotReq["title"])
	}
	if gotReq["task_type"] != "bug" {
		t.Fatalf("task_type=%v", gotReq["task_type"])
	}
	// JSON numbers unmarshal as float64
	if gotReq["priority"] != float64(1) {
		t.Fatalf("priority=%v", gotReq["priority"])
	}
	if gotReq["description"] != "Detailed description" {
		t.Fatalf("description=%v", gotReq["description"])
	}
}

func TestAwTaskCreateDefaultPriority(t *testing.T) {
	t.Parallel()

	var gotPriority float64
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks":
			var req map[string]any
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &req)
			gotPriority = req["priority"].(float64)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id":     "tid-1",
				"task_ref":    "PROJ-002",
				"task_number": 2,
				"title":       req["title"],
				"status":      "open",
				"priority":    req["priority"],
				"task_type":   "task",
				"created_at":  "2026-03-21T10:00:00Z",
				"updated_at":  "2026-03-21T10:00:00Z",
			})
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "create", "--title", "No priority specified")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotPriority != 2 {
		t.Fatalf("default priority should be 2, got %v", gotPriority)
	}
}

func TestAwTaskListSuccess(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": []map[string]any{
					{"task_ref": "PROJ-001", "title": "First task", "priority": 1, "task_type": "task", "status": "open"},
					{"task_ref": "PROJ-002", "title": "Second task", "priority": 3, "task_type": "bug", "status": "in_progress"},
				},
			})
		case "/v1/agents/heartbeat":
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "list")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "PROJ-001") || !strings.Contains(text, "First task") {
		t.Fatalf("output missing first task:\n%s", text)
	}
	if !strings.Contains(text, "PROJ-002") || !strings.Contains(text, "Second task") {
		t.Fatalf("output missing second task:\n%s", text)
	}
}

func TestAwTaskListBlockedUsesBlockedEndpoint(t *testing.T) {
	t.Parallel()

	var sawBlockedList bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks/blocked":
			sawBlockedList = true
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": []map[string]any{
					{"task_ref": "PROJ-009", "title": "Blocked task", "priority": 1, "task_type": "task", "status": "open"},
				},
			})
		case "/v1/agents/heartbeat":
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "list", "--status", "blocked", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !sawBlockedList {
		t.Fatal("expected /v1/tasks/blocked request")
	}
	if !strings.Contains(string(out), `"status": "blocked"`) {
		t.Fatalf("output missing blocked status:\n%s", string(out))
	}
}

func TestAwTaskListFiltersByStatus(t *testing.T) {
	t.Parallel()

	var gotStatus string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			gotStatus = r.URL.Query().Get("status")
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []map[string]any{}})
		case "/v1/agents/heartbeat":
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "list", "--status", "in_progress")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotStatus != "in_progress" {
		t.Fatalf("expected status filter 'in_progress', got %q", gotStatus)
	}
}

func TestAwTaskShowSuccess(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/tasks/PROJ-001":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id":     "tid-1",
				"task_ref":    "PROJ-001",
				"task_number": 1,
				"title":       "Fix the bug",
				"description": "A detailed description",
				"status":      "open",
				"priority":    1,
				"task_type":   "bug",
				"created_at":  "2026-03-21T10:00:00Z",
				"updated_at":  "2026-03-21T10:00:00Z",
				"blocked_by": []map[string]any{
					{"task_ref": "PROJ-000", "title": "Prerequisite", "status": "open"},
				},
			})
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "show", "PROJ-001")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{"PROJ-001", "Fix the bug", "DESCRIPTION", "A detailed description", "BLOCKED BY", "Prerequisite"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestAwTaskShowRequiresRef(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no API call expected, got %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "show")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for missing ref, got success:\n%s", string(out))
	}
}

func TestAwTaskUpdateSuccess(t *testing.T) {
	t.Parallel()

	var gotReq map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &gotReq)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id":     "tid-1",
				"task_ref":    "PROJ-001",
				"task_number": 1,
				"title":       "Updated title",
				"status":      "in_progress",
				"priority":    1,
				"task_type":   "task",
				"created_at":  "2026-03-21T10:00:00Z",
				"updated_at":  "2026-03-21T11:00:00Z",
			})
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001",
		"--status", "in_progress",
		"--title", "Updated title",
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "PROJ-001") || !strings.Contains(text, "Updated title") {
		t.Fatalf("output missing task info:\n%s", text)
	}
	if gotReq["status"] != "in_progress" {
		t.Fatalf("status=%v", gotReq["status"])
	}
	if gotReq["title"] != "Updated title" {
		t.Fatalf("title=%v", gotReq["title"])
	}
}

func TestAwTaskUpdateRequiresFields(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no API call expected, got %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for no fields, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "no fields to update") {
		t.Fatalf("expected 'no fields to update' error, got:\n%s", string(out))
	}
}

func TestAwTaskCloseSuccess(t *testing.T) {
	t.Parallel()

	var closedRefs []string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/tasks/"):
			ref := strings.TrimPrefix(r.URL.Path, "/v1/tasks/")
			closedRefs = append(closedRefs, ref)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id":     "tid-" + ref,
				"task_ref":    ref,
				"task_number": 1,
				"title":       "Task " + ref,
				"status":      "closed",
				"priority":    2,
				"task_type":   "task",
				"created_at":  "2026-03-21T10:00:00Z",
				"updated_at":  "2026-03-21T11:00:00Z",
			})
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	// Close multiple tasks at once
	run := exec.CommandContext(ctx, bin, "task", "close", "PROJ-001", "PROJ-002")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "PROJ-001") || !strings.Contains(text, "PROJ-002") {
		t.Fatalf("output missing closed refs:\n%s", text)
	}
	if len(closedRefs) != 2 {
		t.Fatalf("expected 2 close calls, got %d", len(closedRefs))
	}
}

func TestAwTaskCloseRequiresRef(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no API call expected, got %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "close")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error for missing ref, got success:\n%s", string(out))
	}
}

func TestAwTaskDeleteSuccess(t *testing.T) {
	t.Parallel()

	var gotDelete bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/tasks/PROJ-001":
			gotDelete = true
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "delete", "PROJ-001")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if !gotDelete {
		t.Fatal("DELETE was not called")
	}
	if !strings.Contains(string(out), "PROJ-001") {
		t.Fatalf("output missing ref:\n%s", string(out))
	}
}

func TestAwTaskReopenSuccess(t *testing.T) {
	t.Parallel()

	var gotStatus string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
			var req map[string]any
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &req)
			gotStatus, _ = req["status"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id":     "tid-1",
				"task_ref":    "PROJ-001",
				"task_number": 1,
				"title":       "Reopened task",
				"status":      "open",
				"priority":    2,
				"task_type":   "task",
				"created_at":  "2026-03-21T10:00:00Z",
				"updated_at":  "2026-03-21T11:00:00Z",
			})
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "reopen", "PROJ-001")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotStatus != "open" {
		t.Fatalf("expected status 'open', got %q", gotStatus)
	}
	if !strings.Contains(string(out), "Reopened") {
		t.Fatalf("output missing 'Reopened':\n%s", string(out))
	}
}

func TestAwTaskDepAddSuccess(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks/PROJ-002/deps":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &gotBody)
			w.WriteHeader(http.StatusCreated)
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "dep", "add", "PROJ-002", "PROJ-001")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotBody["depends_on"] != "PROJ-001" {
		t.Fatalf("depends_on=%v", gotBody["depends_on"])
	}
	text := string(out)
	if !strings.Contains(text, "PROJ-002") || !strings.Contains(text, "PROJ-001") {
		t.Fatalf("output missing refs:\n%s", text)
	}
}

func TestAwTaskStatsSuccess(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": []map[string]any{
					{"task_ref": "P-1", "title": "a", "priority": 1, "task_type": "task", "status": "open"},
					{"task_ref": "P-2", "title": "b", "priority": 2, "task_type": "bug", "status": "open"},
					{"task_ref": "P-3", "title": "c", "priority": 1, "task_type": "task", "status": "in_progress"},
					{"task_ref": "P-4", "title": "d", "priority": 3, "task_type": "task", "status": "closed"},
					{"task_ref": "P-5", "title": "e", "priority": 1, "task_type": "task", "status": "open"},
				},
			})
		case "/v1/tasks/blocked":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"tasks": []map[string]any{
					{"task_ref": "P-3", "title": "c", "priority": 1, "task_type": "task", "status": "in_progress"},
					{"task_ref": "P-5", "title": "e", "priority": 1, "task_type": "task", "status": "open"},
					{"task_ref": "P-6", "title": "f", "priority": 2, "task_type": "task", "status": "open"},
				},
			})
		case "/v1/agents/heartbeat":
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "stats")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{"Total: 6", "Open: 2", "In progress: 0", "Blocked: 3", "Closed: 1"} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestAwTaskUpdateRejectsBlockedStatus(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("no API call expected, got %s %s", r.Method, r.URL.Path)
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--status", "blocked")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("expected error, got success:\n%s", string(out))
	}
	if !strings.Contains(string(out), "blocked is derived from task dependencies") {
		t.Fatalf("unexpected output:\n%s", string(out))
	}
}

func TestAwTaskCommentAddSuccess(t *testing.T) {
	t.Parallel()

	var gotBody map[string]any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks/PROJ-001/comments":
			body, _ := io.ReadAll(r.Body)
			_ = json.Unmarshal(body, &gotBody)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"comment_id": "c-1",
				"task_id":    "tid-1",
				"body":       gotBody["body"],
				"created_at": "2026-03-21T10:00:00Z",
			})
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

	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "comment", "add", "PROJ-001", "This is a comment")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotBody["body"] != "This is a comment" {
		t.Fatalf("body=%v", gotBody["body"])
	}
	if !strings.Contains(string(out), "PROJ-001") {
		t.Fatalf("output missing ref:\n%s", string(out))
	}
}
