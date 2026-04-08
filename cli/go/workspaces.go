package aweb

import (
	"context"

	"github.com/awebai/aw/awid"
)

type WorkspaceClaim struct {
	TaskRef     string  `json:"task_ref,omitempty"`
	BeadID      string  `json:"bead_id,omitempty"`
	Title       *string `json:"title,omitempty"`
	ClaimedAt   string  `json:"claimed_at"`
	ApexTaskRef *string `json:"apex_task_ref,omitempty"`
	ApexID      *string `json:"apex_id,omitempty"`
	ApexTitle   *string `json:"apex_title,omitempty"`
	ApexType    *string `json:"apex_type,omitempty"`
}

type WorkspaceInfo struct {
	WorkspaceID       string           `json:"workspace_id"`
	Alias             string           `json:"alias"`
	HumanName         *string          `json:"human_name,omitempty"`
	ContextKind       *string          `json:"context_kind,omitempty"`
	ProjectID         *string          `json:"project_id,omitempty"`
	ProjectSlug       *string          `json:"project_slug,omitempty"`
	NamespaceSlug     *string          `json:"namespace_slug,omitempty"`
	Program           *string          `json:"program,omitempty"`
	Model             *string          `json:"model,omitempty"`
	Repo              *string          `json:"repo,omitempty"`
	Branch            *string          `json:"branch,omitempty"`
	MemberEmail       *string          `json:"member_email,omitempty"`
	Role              *string          `json:"role,omitempty"`
	Hostname          *string          `json:"hostname,omitempty"`
	WorkspacePath     *string          `json:"workspace_path,omitempty"`
	ApexID            *string          `json:"apex_id,omitempty"`
	ApexTitle         *string          `json:"apex_title,omitempty"`
	ApexType          *string          `json:"apex_type,omitempty"`
	FocusTaskRef      *string          `json:"focus_task_ref,omitempty"`
	FocusTaskTitle    *string          `json:"focus_task_title,omitempty"`
	FocusTaskType     *string          `json:"focus_task_type,omitempty"`
	FocusTaskRepoName *string          `json:"focus_task_repo_name,omitempty"`
	FocusTaskBranch   *string          `json:"focus_task_branch,omitempty"`
	FocusUpdatedAt    *string          `json:"focus_updated_at,omitempty"`
	Status            string           `json:"status"`
	LastSeen          *string          `json:"last_seen,omitempty"`
	DeletedAt         *string          `json:"deleted_at,omitempty"`
	Claims            []WorkspaceClaim `json:"claims,omitempty"`
}

type WorkspaceListResponse struct {
	Workspaces []WorkspaceInfo `json:"workspaces"`
	HasMore    bool            `json:"has_more"`
	NextCursor *string         `json:"next_cursor,omitempty"`
}

type WorkspaceTeamParams struct {
	HumanName                string
	Repo                     string
	IncludeClaims            bool
	IncludePresence          bool
	OnlyWithClaims           bool
	AlwaysIncludeWorkspaceID string
	Limit                    int
}

type PatchCurrentWorkspaceRequest struct {
	Hostname      string `json:"hostname,omitempty"`
	WorkspacePath string `json:"workspace_path,omitempty"`
	Role          string `json:"role,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
}

type PatchCurrentWorkspaceResponse struct {
	AgentID       string `json:"agent_id"`
	Alias         string `json:"alias"`
	Hostname      string `json:"hostname,omitempty"`
	WorkspacePath string `json:"workspace_path,omitempty"`
	Role          string `json:"role,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
}

func (c *Client) PatchCurrentWorkspace(ctx context.Context, req *PatchCurrentWorkspaceRequest) (*PatchCurrentWorkspaceResponse, error) {
	var out PatchCurrentWorkspaceResponse
	if err := c.Patch(ctx, "/v1/agents/me", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) WorkspaceTeam(ctx context.Context, params WorkspaceTeamParams) (*WorkspaceListResponse, error) {
	path := "/v1/workspaces/team"
	sep := "?"
	if params.HumanName != "" {
		path += sep + "human_name=" + urlQueryEscape(params.HumanName)
		sep = "&"
	}
	if params.Repo != "" {
		path += sep + "repo=" + urlQueryEscape(params.Repo)
		sep = "&"
	}
	path += sep + "include_claims=" + boolString(params.IncludeClaims)
	sep = "&"
	path += sep + "include_presence=" + boolString(params.IncludePresence)
	path += "&only_with_claims=" + boolString(params.OnlyWithClaims)
	if params.AlwaysIncludeWorkspaceID != "" {
		path += "&always_include_workspace_id=" + urlQueryEscape(params.AlwaysIncludeWorkspaceID)
	}
	if params.Limit > 0 {
		path += "&limit=" + itoa(params.Limit)
	}
	var out WorkspaceListResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// WorkspaceDelete soft-deletes a workspace by its ID.
// Returns nil if the workspace was already deleted (404).
func (c *Client) WorkspaceDelete(ctx context.Context, workspaceID string) error {
	err := c.Delete(ctx, "/v1/workspaces/"+urlPathEscape(workspaceID))
	if err != nil {
		if code, ok := awid.HTTPStatusCode(err); ok && code == 404 {
			return nil
		}
	}
	return err
}

type WorkspaceListParams struct {
	Hostname        string
	IncludePresence bool
}

// WorkspaceList lists workspaces, optionally filtered by hostname.
func (c *Client) WorkspaceList(ctx context.Context, params WorkspaceListParams) (*WorkspaceListResponse, error) {
	path := "/v1/workspaces"
	sep := "?"
	if params.Hostname != "" {
		path += sep + "hostname=" + urlQueryEscape(params.Hostname)
		sep = "&"
	}
	path += sep + "include_presence=" + boolString(params.IncludePresence)
	var out WorkspaceListResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func boolString(v bool) string {
	if v {
		return "true"
	}
	return "false"
}
