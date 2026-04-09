package aweb

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestTaskCreate(t *testing.T) {
	t.Parallel()

	var gotBody TaskCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tasks" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(Task{
			TaskID:   "task-001",
			TaskRef:  "aw-001",
			Title:    gotBody.Title,
			Status:   "open",
			Priority: gotBody.Priority,
			TaskType: gotBody.TaskType,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskCreate(context.Background(), &TaskCreateRequest{
		Title:    "Fix the bug",
		Priority: 1,
		TaskType: "bug",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.TaskID != "task-001" {
		t.Fatalf("task_id=%s", resp.TaskID)
	}
	if resp.Title != "Fix the bug" {
		t.Fatalf("title=%s", resp.Title)
	}
	if gotBody.Title != "Fix the bug" {
		t.Fatalf("sent title=%s", gotBody.Title)
	}
	if gotBody.Priority != 1 {
		t.Fatalf("sent priority=%d", gotBody.Priority)
	}
}

func TestTaskList(t *testing.T) {
	t.Parallel()

	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tasks" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(TaskListResponse{
			Tasks: []TaskSummary{
				{TaskID: "task-001", TaskRef: "aw-001", Title: "Task A", Status: "open"},
				{TaskID: "task-002", TaskRef: "aw-002", Title: "Task B", Status: "in_progress"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskList(context.Background(), TaskListParams{
		Status:   "open",
		TaskType: "bug",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Tasks) != 2 {
		t.Fatalf("tasks=%d", len(resp.Tasks))
	}
	if gotQuery != "status=open&task_type=bug" {
		t.Fatalf("query=%s", gotQuery)
	}
}

func TestTaskListReady(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tasks/ready" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(TaskListResponse{
			Tasks: []TaskSummary{
				{TaskID: "task-003", TaskRef: "aw-003", Title: "Ready task", Status: "open"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskListReady(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Tasks) != 1 {
		t.Fatalf("tasks=%d", len(resp.Tasks))
	}
	if resp.Tasks[0].Title != "Ready task" {
		t.Fatalf("title=%s", resp.Tasks[0].Title)
	}
}

func TestTaskListBlocked(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tasks/blocked" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(TaskListResponse{
			Tasks: []TaskSummary{
				{TaskID: "task-010", TaskRef: "aw-010", Title: "Blocked task", Status: "open"},
				{TaskID: "task-011", TaskRef: "aw-011", Title: "Blocked in_progress", Status: "in_progress"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskListBlocked(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Tasks) != 2 {
		t.Fatalf("tasks=%d", len(resp.Tasks))
	}
	if resp.Tasks[1].Status != "in_progress" {
		t.Fatalf("tasks[1].status=%s", resp.Tasks[1].Status)
	}
}

func TestTaskListActive(t *testing.T) {
	t.Parallel()

	ownerAlias := "eve"
	canonicalOrigin := "github.com/awebai/aweb"
	branch := "feat/summary"

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tasks/active" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(ActiveTaskListResponse{
			Tasks: []ActiveTaskSummary{
				{
					TaskID:          "task-020",
					TaskRef:         "aw-020",
					Title:           "Active task",
					Status:          "in_progress",
					Priority:        1,
					TaskType:        "task",
					OwnerAlias:      &ownerAlias,
					CanonicalOrigin: &canonicalOrigin,
					Branch:          &branch,
				},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskListActive(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Tasks) != 1 {
		t.Fatalf("tasks=%d", len(resp.Tasks))
	}
	if got := *resp.Tasks[0].CanonicalOrigin; got != "github.com/awebai/aweb" {
		t.Fatalf("canonical_origin=%s", got)
	}
	if got := *resp.Tasks[0].Branch; got != "feat/summary" {
		t.Fatalf("branch=%s", got)
	}
}

func TestTaskGet(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tasks/aw-042" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(Task{
			TaskID:      "task-042",
			TaskRef:     "aw-042",
			TaskNumber:  42,
			Title:       "Detailed task",
			Description: "Full description",
			Status:      "open",
			Priority:    2,
			TaskType:    "feature",
			BlockedBy: []TaskDepView{
				{TaskID: "task-041", TaskRef: "aw-041", Title: "Blocker", Status: "open"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskGet(context.Background(), "aw-042")
	if err != nil {
		t.Fatal(err)
	}
	if resp.TaskRef != "aw-042" {
		t.Fatalf("task_ref=%s", resp.TaskRef)
	}
	if resp.Description != "Full description" {
		t.Fatalf("description=%s", resp.Description)
	}
	if len(resp.BlockedBy) != 1 {
		t.Fatalf("blocked_by=%d", len(resp.BlockedBy))
	}
	if resp.BlockedBy[0].TaskRef != "aw-041" {
		t.Fatalf("blocked_by[0].task_ref=%s", resp.BlockedBy[0].TaskRef)
	}
}

func TestTaskUpdate(t *testing.T) {
	t.Parallel()

	var gotBody TaskUpdateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPatch || r.URL.Path != "/v1/tasks/aw-042" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(TaskUpdateResponse{
			Task: Task{
				TaskID:   "task-042",
				TaskRef:  "aw-042",
				Title:    *gotBody.Title,
				Status:   "open",
				Priority: 2,
				TaskType: "feature",
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	newTitle := "Updated title"
	resp, err := c.TaskUpdate(context.Background(), "aw-042", &TaskUpdateRequest{
		Title: &newTitle,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Title != "Updated title" {
		t.Fatalf("title=%s", resp.Title)
	}
	if *gotBody.Title != "Updated title" {
		t.Fatalf("sent title=%s", *gotBody.Title)
	}
}

func TestTaskUpdateCascadeClose(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(TaskUpdateResponse{
			Task: Task{
				TaskID:  "task-001",
				TaskRef: "aw-001",
				Title:   "Parent",
				Status:  "closed",
			},
			AutoClosed: []TaskSummary{
				{TaskID: "task-002", TaskRef: "aw-002", Title: "Child A", Status: "closed"},
				{TaskID: "task-003", TaskRef: "aw-003", Title: "Child B", Status: "closed"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	status := "closed"
	resp, err := c.TaskUpdate(context.Background(), "aw-001", &TaskUpdateRequest{
		Status: &status,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.AutoClosed) != 2 {
		t.Fatalf("auto_closed=%d", len(resp.AutoClosed))
	}
	if resp.AutoClosed[0].TaskRef != "aw-002" {
		t.Fatalf("auto_closed[0].task_ref=%s", resp.AutoClosed[0].TaskRef)
	}
}

func TestTaskUpdate409ReturnsHeldError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(TaskHeldError{
			Detail:          "task already held",
			AssigneeAlias: "agent-other",
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	status := "in_progress"
	_, err = c.TaskUpdate(context.Background(), "aw-042", &TaskUpdateRequest{
		Status: &status,
	})
	if err == nil {
		t.Fatal("expected error")
	}

	var held *TaskHeldError
	if !errors.As(err, &held) {
		t.Fatalf("expected TaskHeldError, got %T: %v", err, err)
	}
	if held.AssigneeAlias != "agent-other" {
		t.Fatalf("assignee=%s", held.AssigneeAlias)
	}
}

func TestTaskDelete(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	err = c.TaskDelete(context.Background(), "aw-042")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s", gotMethod)
	}
	if gotPath != "/v1/tasks/aw-042" {
		t.Fatalf("path=%s", gotPath)
	}
}

func TestTaskAddDep(t *testing.T) {
	t.Parallel()

	var gotBody TaskAddDepRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tasks/aw-042/deps" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	err = c.TaskAddDep(context.Background(), "aw-042", &TaskAddDepRequest{
		DependsOn: "aw-041",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotBody.DependsOn != "aw-041" {
		t.Fatalf("depends_on=%s", gotBody.DependsOn)
	}
}

func TestTaskAddDepCycleReturns422(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "dependency cycle detected"})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	err = c.TaskAddDep(context.Background(), "aw-042", &TaskAddDepRequest{
		DependsOn: "aw-001",
	})
	if err == nil {
		t.Fatal("expected error")
	}
	code, ok := awid.HTTPStatusCode(err)
	if !ok || code != 422 {
		t.Fatalf("expected 422, got ok=%v code=%d err=%v", ok, code, err)
	}
}

func TestTaskRemoveDep(t *testing.T) {
	t.Parallel()

	var gotMethod, gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	err = c.TaskRemoveDep(context.Background(), "aw-042", "aw-041")
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodDelete {
		t.Fatalf("method=%s", gotMethod)
	}
	if gotPath != "/v1/tasks/aw-042/deps/aw-041" {
		t.Fatalf("path=%s", gotPath)
	}
}

func TestTaskListQueryParams(t *testing.T) {
	t.Parallel()

	var gotQuery string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(TaskListResponse{})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	// No params — no query string.
	_, err = c.TaskList(context.Background(), TaskListParams{})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "" {
		t.Fatalf("expected empty query, got %q", gotQuery)
	}

	// All params.
	priority := 1
	_, err = c.TaskList(context.Background(), TaskListParams{
		Status:          "open",
		AssigneeAlias: "agent-1",
		TaskType:        "feature",
		Priority:        &priority,
		Labels:          []string{"urgent", "backend"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotQuery != "status=open&assignee_alias=agent-1&task_type=feature&priority=1&labels=urgent%2Cbackend" {
		t.Fatalf("query=%s", gotQuery)
	}
}

func TestTaskCommentCreate(t *testing.T) {
	t.Parallel()

	var gotBody TaskCommentCreateRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/tasks/aw-042/comments" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(TaskComment{
			CommentID: "comment-001",
			TaskID:    "task-042",
			Body:      gotBody.Body,
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskCommentCreate(context.Background(), "aw-042", &TaskCommentCreateRequest{
		Body: "This is a comment",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.CommentID != "comment-001" {
		t.Fatalf("comment_id=%s", resp.CommentID)
	}
	if resp.Body != "This is a comment" {
		t.Fatalf("body=%s", resp.Body)
	}
	if gotBody.Body != "This is a comment" {
		t.Fatalf("sent body=%s", gotBody.Body)
	}
}

func TestTaskCommentList(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/tasks/aw-042/comments" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(TaskCommentListResponse{
			Comments: []TaskComment{
				{CommentID: "c-1", Body: "First"},
				{CommentID: "c-2", Body: "Second"},
			},
		})
	}))
	t.Cleanup(server.Close)

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.TaskCommentList(context.Background(), "aw-042")
	if err != nil {
		t.Fatal(err)
	}
	if len(resp.Comments) != 2 {
		t.Fatalf("comments=%d", len(resp.Comments))
	}
	if resp.Comments[0].Body != "First" {
		t.Fatalf("comments[0].body=%s", resp.Comments[0].Body)
	}
}
