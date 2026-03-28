package aweb

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/awebai/aw/awid"
)

// Task types

type TaskDepView struct {
	TaskID  string `json:"task_id"`
	TaskRef string `json:"task_ref"`
	Title   string `json:"title"`
	Status  string `json:"status"`
}

type Task struct {
	TaskID           string        `json:"task_id"`
	TaskRef          string        `json:"task_ref"`
	TaskNumber       int           `json:"task_number"`
	Title            string        `json:"title"`
	Description      string        `json:"description,omitempty"`
	Notes            string        `json:"notes,omitempty"`
	Status           string        `json:"status"`
	Priority         int           `json:"priority"`
	TaskType         string        `json:"task_type"`
	Labels           []string      `json:"labels,omitempty"`
	ParentTaskID     *string       `json:"parent_task_id"`
	AssigneeAgentID  *string       `json:"assignee_agent_id"`
	CreatedByAgentID *string       `json:"created_by_agent_id"`
	ClosedByAgentID  *string       `json:"closed_by_agent_id"`
	BlockedBy        []TaskDepView `json:"blocked_by,omitempty"`
	Blocks           []TaskDepView `json:"blocks,omitempty"`
	CreatedAt        string        `json:"created_at"`
	UpdatedAt        string        `json:"updated_at"`
	ClosedAt         *string       `json:"closed_at"`
}

type TaskSummary struct {
	TaskID           string   `json:"task_id"`
	TaskRef          string   `json:"task_ref"`
	TaskNumber       int      `json:"task_number"`
	Title            string   `json:"title"`
	Status           string   `json:"status"`
	Priority         int      `json:"priority"`
	TaskType         string   `json:"task_type"`
	AssigneeAgentID  *string  `json:"assignee_agent_id"`
	CreatedByAgentID *string  `json:"created_by_agent_id"`
	Labels           []string `json:"labels,omitempty"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
}

// Request/response types

type TaskCreateRequest struct {
	Title           string   `json:"title"`
	Description     string   `json:"description,omitempty"`
	Notes           string   `json:"notes,omitempty"`
	Priority        int      `json:"priority"`
	TaskType        string   `json:"task_type,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	ParentTaskID    *string  `json:"parent_task_id,omitempty"`
	AssigneeAgentID *string  `json:"assignee_agent_id,omitempty"`
}

type TaskUpdateRequest struct {
	Title           *string  `json:"title,omitempty"`
	Description     *string  `json:"description,omitempty"`
	Notes           *string  `json:"notes,omitempty"`
	Status          *string  `json:"status,omitempty"`
	TaskType        *string  `json:"task_type,omitempty"`
	Priority        *int     `json:"priority,omitempty"`
	Labels          []string `json:"labels,omitempty"`
	AssigneeAgentID *string  `json:"assignee_agent_id,omitempty"`
}

type TaskListParams struct {
	Status          string
	AssigneeAgentID string
	TaskType        string
	Priority        *int
	Labels          []string
}

type TaskAddDepRequest struct {
	DependsOn string `json:"depends_on"`
}

type TaskListResponse struct {
	Tasks []TaskSummary `json:"tasks"`
}

type ActiveTaskSummary struct {
	TaskID           string   `json:"task_id"`
	TaskRef          string   `json:"task_ref"`
	TaskNumber       int      `json:"task_number"`
	Title            string   `json:"title"`
	Status           string   `json:"status"`
	Priority         int      `json:"priority"`
	TaskType         string   `json:"task_type"`
	AssigneeAgentID  *string  `json:"assignee_agent_id"`
	CreatedByAgentID *string  `json:"created_by_agent_id"`
	ParentTaskID     *string  `json:"parent_task_id"`
	Labels           []string `json:"labels,omitempty"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
	WorkspaceID      *string  `json:"workspace_id,omitempty"`
	OwnerAlias       *string  `json:"owner_alias,omitempty"`
	ClaimedAt        *string  `json:"claimed_at,omitempty"`
	CanonicalOrigin  *string  `json:"canonical_origin,omitempty"`
	Branch           *string  `json:"branch,omitempty"`
}

type ActiveTaskListResponse struct {
	Tasks []ActiveTaskSummary `json:"tasks"`
}

// TaskUpdateResponse wraps a Task with the additional auto_closed array
// returned when closing a parent task triggers cascade-close of children.
type TaskUpdateResponse struct {
	Task
	AutoClosed []TaskSummary `json:"auto_closed,omitempty"`
}

// TaskHeldError is returned when a task status transition to in_progress
// fails because another agent already holds it.
type TaskHeldError struct {
	Detail          string `json:"detail"`
	HolderAgentID   string `json:"holder_agent_id"`
	AssigneeAgentID string `json:"assignee_agent_id"`
}

func (e *TaskHeldError) Error() string {
	if e.AssigneeAgentID != "" {
		return "aweb: task already held by " + e.AssigneeAgentID
	}
	if e.Detail != "" {
		return "aweb: " + e.Detail
	}
	return "aweb: task is already held"
}

// Client methods

func (c *Client) TaskCreate(ctx context.Context, req *TaskCreateRequest) (*Task, error) {
	var out Task
	if err := c.Post(ctx, "/v1/tasks", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TaskList(ctx context.Context, params TaskListParams) (*TaskListResponse, error) {
	path := "/v1/tasks"
	sep := "?"
	if params.Status != "" {
		path += sep + "status=" + urlQueryEscape(params.Status)
		sep = "&"
	}
	if params.AssigneeAgentID != "" {
		path += sep + "assignee_agent_id=" + urlQueryEscape(params.AssigneeAgentID)
		sep = "&"
	}
	if params.TaskType != "" {
		path += sep + "task_type=" + urlQueryEscape(params.TaskType)
		sep = "&"
	}
	if params.Priority != nil {
		path += sep + "priority=" + itoa(*params.Priority)
		sep = "&"
	}
	if len(params.Labels) > 0 {
		path += sep + "labels=" + urlQueryEscape(strings.Join(params.Labels, ","))
		sep = "&"
	}
	var out TaskListResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TaskListReady(ctx context.Context) (*TaskListResponse, error) {
	var out TaskListResponse
	if err := c.Get(ctx, "/v1/tasks/ready", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TaskListBlocked(ctx context.Context) (*TaskListResponse, error) {
	var out TaskListResponse
	if err := c.Get(ctx, "/v1/tasks/blocked", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TaskListActive(ctx context.Context) (*ActiveTaskListResponse, error) {
	var out ActiveTaskListResponse
	if err := c.Get(ctx, "/v1/tasks/active", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TaskGet(ctx context.Context, ref string) (*Task, error) {
	var out Task
	if err := c.Get(ctx, "/v1/tasks/"+urlPathEscape(ref), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// TaskUpdate updates a task and returns the updated task. If the update
// sets status=in_progress and another agent already holds it, a 409 is
// returned as a *TaskHeldError. When closing a parent task, the response
// may include AutoClosed listing cascade-closed children.
func (c *Client) TaskUpdate(ctx context.Context, ref string, req *TaskUpdateRequest) (*TaskUpdateResponse, error) {
	resp, err := c.DoRaw(ctx, http.MethodPatch, "/v1/tasks/"+urlPathEscape(ref), "application/json", req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	limited := io.LimitReader(resp.Body, awid.MaxResponseSize)
	data, err := io.ReadAll(limited)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode == http.StatusConflict {
		var held TaskHeldError
		if err := json.Unmarshal(data, &held); err == nil {
			return nil, &held
		}
		return nil, &awid.APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, &awid.APIError{StatusCode: resp.StatusCode, Body: string(data)}
	}

	var out TaskUpdateResponse
	if err := json.Unmarshal(data, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TaskDelete(ctx context.Context, ref string) error {
	return c.Delete(ctx, "/v1/tasks/"+urlPathEscape(ref))
}

// TaskAddDep adds a dependency. Returns 422 if this would create a cycle.
func (c *Client) TaskAddDep(ctx context.Context, ref string, req *TaskAddDepRequest) error {
	return c.Post(ctx, "/v1/tasks/"+urlPathEscape(ref)+"/deps", req, nil)
}

func (c *Client) TaskRemoveDep(ctx context.Context, ref string, depRef string) error {
	return c.Delete(ctx, "/v1/tasks/"+urlPathEscape(ref)+"/deps/"+urlPathEscape(depRef))
}

// Comments

type TaskComment struct {
	CommentID     string  `json:"comment_id"`
	TaskID        string  `json:"task_id"`
	AuthorAgentID *string `json:"author_agent_id"`
	Body          string  `json:"body"`
	ParentID      *string `json:"parent_id"`
	CreatedAt     string  `json:"created_at"`
}

type TaskCommentCreateRequest struct {
	Body     string  `json:"body"`
	ParentID *string `json:"parent_id,omitempty"`
}

type TaskCommentListResponse struct {
	Comments []TaskComment `json:"comments"`
}

func (c *Client) TaskCommentCreate(ctx context.Context, ref string, req *TaskCommentCreateRequest) (*TaskComment, error) {
	var out TaskComment
	if err := c.Post(ctx, "/v1/tasks/"+urlPathEscape(ref)+"/comments", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TaskCommentList(ctx context.Context, ref string) (*TaskCommentListResponse, error) {
	var out TaskCommentListResponse
	if err := c.Get(ctx, "/v1/tasks/"+urlPathEscape(ref)+"/comments", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
