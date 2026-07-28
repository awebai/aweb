package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
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

	descriptionFile := filepath.Join(tmp, "description.md")
	description := "Run `make test` and preserve $(EXAMPLE).\n"
	if err := os.WriteFile(descriptionFile, []byte(description), 0o600); err != nil {
		t.Fatal(err)
	}
	run = exec.CommandContext(ctx, bin, "task", "create",
		"--title", "Safe file input",
		"--type", "task",
		"--description-file", descriptionFile,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("description-file run failed: %v\n%s", err, string(out))
	}
	if gotReq["description"] != description {
		t.Fatalf("description-file description=%v, want %q", gotReq["description"], description)
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
	for _, status := range []string{"[open]", "[in_progress]"} {
		if !strings.Contains(text, status) {
			t.Fatalf("output missing status %q:\n%s", status, text)
		}
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

func TestAwTaskListFiltersByParentAndPrintsJSON(t *testing.T) {
	t.Parallel()

	gotParents := make(chan string, 1)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/tasks":
			gotParents <- r.URL.Query().Get("parent_task_id")
			_ = json.NewEncoder(w).Encode(map[string]any{"tasks": []map[string]any{{
				"task_ref": "PROJ-001.1", "title": "Child", "priority": 2, "task_type": "task", "status": "open",
				"parent_task_id": "tid-root",
			}}})
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

	run := exec.CommandContext(ctx, bin, "task", "list", "--parent", "PROJ-001", "--json")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if gotParent := <-gotParents; gotParent != "PROJ-001" {
		t.Fatalf("parent_task_id query=%q", gotParent)
	}
	var response struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal(out, &response); err != nil {
		t.Fatalf("list --json returned invalid JSON: %v\n%s", err, out)
	}
	if len(response.Tasks) != 1 || response.Tasks[0]["task_ref"] != "PROJ-001.1" {
		t.Fatalf("unexpected JSON response: %+v", response.Tasks)
	}
	if response.Tasks[0]["parent_task_id"] != "tid-root" {
		t.Fatalf("JSON omitted parent_task_id: %+v", response.Tasks[0])
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
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001/comments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"comments": []map[string]any{{
					"comment_id":   "comment-1",
					"task_id":      "tid-1",
					"author_alias": "bob",
					"body":         "This matches what we agreed.",
					"created_at":   "2026-03-21T10:30:00Z",
				}},
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
	for _, want := range []string{"PROJ-001", "Fix the bug", "DESCRIPTION", "A detailed description", "BLOCKED BY", "Prerequisite", "COMMENTS", "bob:", "This matches what we agreed."} {
		if !strings.Contains(text, want) {
			t.Fatalf("output missing %q:\n%s", want, text)
		}
	}
}

func TestAwTaskShowIncludesEmptyCommentsSection(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id":     "tid-1",
				"task_ref":    "PROJ-001",
				"task_number": 1,
				"title":       "Fix the bug",
				"status":      "open",
				"priority":    1,
				"task_type":   "bug",
				"created_at":  "2026-03-21T10:00:00Z",
				"updated_at":  "2026-03-21T10:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001/comments":
			_ = json.NewEncoder(w).Encode(map[string]any{"comments": []map[string]any{}})
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
	for _, want := range []string{"COMMENTS", "No comments."} {
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

	descriptionFile := filepath.Join(tmp, "description.md")
	description := "Preserve `go test` and $(EXAMPLE).\n"
	if err := os.WriteFile(descriptionFile, []byte(description), 0o600); err != nil {
		t.Fatal(err)
	}
	run = exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--description-file", descriptionFile)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("description-file run failed: %v\n%s", err, string(out))
	}
	if gotReq["description"] != description {
		t.Fatalf("description-file description=%v, want %q", gotReq["description"], description)
	}
}

func TestAwTaskUpdateReparentsAndClearsAssignee(t *testing.T) {
	t.Parallel()

	gotRequests := make(chan map[string]any, 1)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			gotRequests <- req
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
				"title": "Moved task", "status": "open", "priority": 2, "task_type": "task",
				"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T11:00:00Z",
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

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--parent", "PROJ-ROOT", "--assignee", "")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	gotReq := <-gotRequests
	if gotReq["parent_task_id"] != "PROJ-ROOT" {
		t.Fatalf("parent_task_id=%v", gotReq["parent_task_id"])
	}
	if assignee, ok := gotReq["assignee_alias"]; !ok || assignee != "" {
		t.Fatalf("assignee_alias missing or not explicitly empty: %#v", gotReq)
	}
}

func TestAwTaskUpdateRetriesA404WhenTheTaskStillExists(t *testing.T) {
	t.Parallel()

	var patchCalls atomic.Int32
	var getCalls atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
			if patchCalls.Add(1) == 1 {
				http.Error(w, `{"detail":"Task not found"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
				"title": "Still here", "status": "closed", "priority": 2, "task_type": "task",
				"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T11:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001":
			getCalls.Add(1)
			status := "open"
			if patchCalls.Load() == 2 {
				status = "closed"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
				"title": "Still here", "status": status, "priority": 2, "task_type": "task",
				"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T10:00:00Z",
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

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--status", "closed")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("transient 404 should retry after existence check: %v\n%s", err, out)
	}
	if patchCalls.Load() != 2 || getCalls.Load() != 2 {
		t.Fatalf("patch calls=%d get calls=%d, want 2/2", patchCalls.Load(), getCalls.Load())
	}
}

func TestAwTaskUpdateDistinguishesPersistentWrite404ForExistingTask(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
			http.Error(w, `{"detail":"Task not found"}`, http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
				"title": "Still here", "status": "open", "priority": 2, "task_type": "task",
				"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T10:00:00Z",
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

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--status", "closed")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("persistent write 404 unexpectedly succeeded:\n%s", out)
	}
	for _, want := range []string{"still exists", "temporarily unavailable", "may have applied", "inspect the task"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("error missing %q:\n%s", want, out)
		}
	}
}

func TestAwTaskUpdateReportsUnknownStateWhenExistenceProbeFails(t *testing.T) {
	t.Parallel()

	var probeMode atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
			http.Error(w, `{"detail":"Task not found"}`, http.StatusNotFound)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001":
			if probeMode.Load() == 0 {
				http.Error(w, `{"detail":"temporarily unavailable"}`, http.StatusServiceUnavailable)
				return
			}
			<-r.Context().Done()
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--status", "closed")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("failed existence probe unexpectedly succeeded:\n%s", out)
	}
	for _, want := range []string{"could not establish whether task PROJ-001 exists", "may have applied", "inspect the task"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("error missing %q:\n%s", want, out)
		}
	}
	if strings.Contains(string(out), "updating task PROJ-001: aweb: http 404") {
		t.Fatalf("uncertain existence was reported as absence:\n%s", out)
	}

	probeMode.Store(1)
	run = exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--status", "closed")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err = run.CombinedOutput()
	if err == nil {
		t.Fatalf("timed-out existence probe unexpectedly succeeded:\n%s", out)
	}
	for _, want := range []string{"could not establish whether task PROJ-001 exists", "may have applied", "inspect the task"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("timeout error missing %q:\n%s", want, out)
		}
	}
}

func TestAwTaskUpdateRejectsSuccessfulRetryWithOldVerifiedState(t *testing.T) {
	t.Parallel()

	var patchCalls atomic.Int32
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
			if patchCalls.Add(1) == 1 {
				http.Error(w, `{"detail":"Task not found"}`, http.StatusNotFound)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
				"title": "Still here", "status": "closed", "priority": 2, "task_type": "task",
				"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T11:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
				"title": "Still here", "status": "open", "priority": 2, "task_type": "task",
				"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T10:00:00Z",
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

	run := exec.CommandContext(ctx, bin, "task", "update", "PROJ-001", "--status", "closed")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err == nil {
		t.Fatalf("old verified state unexpectedly accepted:\n%s", out)
	}
	for _, want := range []string{"could not be verified", `status is "open", want "closed"`, "inspect the task"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("error missing %q:\n%s", want, out)
		}
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
	var closedNotes []any
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPatch && strings.HasPrefix(r.URL.Path, "/v1/tasks/"):
			ref := strings.TrimPrefix(r.URL.Path, "/v1/tasks/")
			closedRefs = append(closedRefs, ref)
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			closedNotes = append(closedNotes, req["notes"])
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

	reasonFile := filepath.Join(tmp, "reason.md")
	reason := "Validated with `go test`; preserve $(EXAMPLE).\n"
	if err := os.WriteFile(reasonFile, []byte(reason), 0o600); err != nil {
		t.Fatal(err)
	}
	run = exec.CommandContext(ctx, bin, "task", "close", "PROJ-003", "--reason-file", reasonFile)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("reason-file run failed: %v\n%s", err, string(out))
	}
	if got := closedNotes[len(closedNotes)-1]; got != reason {
		t.Fatalf("reason-file notes=%v, want %q", got, reason)
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

func TestAwTaskCloseAndReopenShareTransientUpdatePolicy(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		command       string
		desiredStatus string
		oldStatus     string
	}{
		{name: "close", command: "close", desiredStatus: "closed", oldStatus: "open"},
		{name: "reopen", command: "reopen", desiredStatus: "open", oldStatus: "closed"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var mode atomic.Int32
			var patchCalls atomic.Int32
			server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch {
				case r.Method == http.MethodPatch && r.URL.Path == "/v1/tasks/PROJ-001":
					call := patchCalls.Add(1)
					if mode.Load() >= 2 || call == 1 {
						http.Error(w, `{"detail":"Task not found"}`, http.StatusNotFound)
						return
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
						"title": "Task", "status": tc.desiredStatus, "priority": 2, "task_type": "task",
						"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T11:00:00Z",
					})
				case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001":
					if mode.Load() == 3 {
						http.Error(w, `{"detail":"temporarily unavailable"}`, http.StatusServiceUnavailable)
						return
					}
					status := tc.oldStatus
					if mode.Load() == 0 && patchCalls.Load() == 2 {
						status = tc.desiredStatus
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"task_id": "tid-1", "task_ref": "PROJ-001", "task_number": 1,
						"title": "Task", "status": status, "priority": 2, "task_type": "task",
						"created_at": "2026-03-21T10:00:00Z", "updated_at": "2026-03-21T10:00:00Z",
					})
				case r.URL.Path == "/v1/agents/heartbeat":
					w.WriteHeader(http.StatusOK)
				default:
					t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
				}
			}))

			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			tmp := t.TempDir()
			bin := filepath.Join(tmp, "aw")
			buildAwBinary(t, ctx, bin)
			writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

			run := func() ([]byte, error) {
				command := exec.CommandContext(ctx, bin, "task", tc.command, "PROJ-001")
				command.Env = testCommandEnv(tmp)
				command.Dir = tmp
				return command.CombinedOutput()
			}

			out, err := run()
			if err != nil {
				t.Fatalf("transient first 404 should recover: %v\n%s", err, out)
			}
			if patchCalls.Load() != 2 {
				t.Fatalf("transient patch calls=%d, want 2", patchCalls.Load())
			}

			mode.Store(1)
			patchCalls.Store(0)
			out, err = run()
			if err == nil || !strings.Contains(string(out), "could not be verified") || !strings.Contains(string(out), "inspect the task") {
				t.Fatalf("old post-retry state was not refused: %v\n%s", err, out)
			}

			mode.Store(2)
			patchCalls.Store(0)
			out, err = run()
			if err == nil || !strings.Contains(string(out), "temporarily unavailable") || !strings.Contains(string(out), "may have applied") {
				t.Fatalf("persistent write 404 was misclassified: %v\n%s", err, out)
			}

			mode.Store(3)
			patchCalls.Store(0)
			out, err = run()
			if err == nil || !strings.Contains(string(out), "could not establish whether task PROJ-001 exists") || !strings.Contains(string(out), "may have applied") {
				t.Fatalf("uncertain existence probe was misclassified: %v\n%s", err, out)
			}
		})
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

	gotBodies := make(chan string, 2)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks/PROJ-001/comments":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			body, _ := req["body"].(string)
			gotBodies <- body
			_ = json.NewEncoder(w).Encode(map[string]any{
				"comment_id": "c-1",
				"task_id":    "tid-1",
				"body":       body,
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

	run := exec.CommandContext(ctx, bin, "task", "comment", "add", "PROJ-001", "--body", "This is a comment")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	if body := <-gotBodies; body != "This is a comment" {
		t.Fatalf("body=%q", body)
	}
	if !strings.Contains(string(out), "PROJ-001") {
		t.Fatalf("output missing ref:\n%s", string(out))
	}

	run = exec.CommandContext(ctx, bin, "task", "comment", "add", "PROJ-001", "Positional comment remains supported")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err = run.CombinedOutput(); err != nil {
		t.Fatalf("positional run failed: %v\n%s", err, out)
	}
	if body := <-gotBodies; body != "Positional comment remains supported" {
		t.Fatalf("positional body=%q", body)
	}
}

func TestAwTaskCommentAddReadsBodyFile(t *testing.T) {
	t.Parallel()

	gotBodies := make(chan string, 1)
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/tasks/PROJ-001/comments":
			var req map[string]any
			_ = json.NewDecoder(r.Body).Decode(&req)
			body, _ := req["body"].(string)
			gotBodies <- body
			_ = json.NewEncoder(w).Encode(map[string]any{
				"comment_id": "c-1", "task_id": "tid-1", "body": body, "created_at": "2026-03-21T10:00:00Z",
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
	bodyPath := filepath.Join(tmp, "comment.txt")
	if err := os.WriteFile(bodyPath, []byte("line one\nline two\n"), 0o600); err != nil {
		t.Fatalf("write body file: %v", err)
	}

	run := exec.CommandContext(ctx, bin, "task", "comment", "add", "PROJ-001", "--body-file", bodyPath)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run failed: %v\n%s", err, out)
	}
	if body := <-gotBodies; body != "line one\nline two\n" {
		t.Fatalf("body=%q", body)
	}
}

func TestAwTaskCommentListUsesAuthorAlias(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001/comments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"comments": []map[string]any{{
					"comment_id":   "c-1",
					"task_id":      "tid-1",
					"author_alias": "grace",
					"body":         "Ready for review.",
					"created_at":   "2026-03-21T10:00:00Z",
				}},
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

	run := exec.CommandContext(ctx, bin, "task", "comment", "list", "PROJ-001")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "grace:") {
		t.Fatalf("output missing author alias:\n%s", text)
	}
	if strings.Contains(text, "(unknown)") {
		t.Fatalf("output should not show unknown author:\n%s", text)
	}
}

func TestAwTaskCommentListFallsBackToAuthorAgentID(t *testing.T) {
	t.Parallel()

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/tasks/PROJ-001/comments":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"comments": []map[string]any{{
					"comment_id":      "c-1",
					"task_id":         "tid-1",
					"author_agent_id": "agent-123",
					"body":            "Legacy response.",
					"created_at":      "2026-03-21T10:00:00Z",
				}},
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

	run := exec.CommandContext(ctx, bin, "task", "comment", "list", "PROJ-001")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("run failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if !strings.Contains(text, "agent-123:") {
		t.Fatalf("output missing legacy author_agent_id fallback:\n%s", text)
	}
	if strings.Contains(text, "(unknown)") {
		t.Fatalf("output should not show unknown author:\n%s", text)
	}
}
