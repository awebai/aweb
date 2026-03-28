package aweb

import (
	"context"

	"github.com/awebai/aw/awid"
)

type WorkspaceRegisterRequest struct {
	RepoOrigin    string `json:"repo_origin"`
	Role          string `json:"role,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	WorkspacePath string `json:"workspace_path,omitempty"`
}

type WorkspaceRegisterResponse struct {
	WorkspaceID     string `json:"workspace_id"`
	ProjectID       string `json:"project_id"`
	ProjectSlug     string `json:"project_slug"`
	RepoID          string `json:"repo_id"`
	CanonicalOrigin string `json:"canonical_origin"`
	Alias           string `json:"alias"`
	HumanName       string `json:"human_name"`
	Created         bool   `json:"created"`
}

type WorkspaceAttachRequest struct {
	AttachmentType string `json:"attachment_type"`
	Role           string `json:"role,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	WorkspacePath  string `json:"workspace_path,omitempty"`
}

type WorkspaceAttachResponse struct {
	WorkspaceID    string `json:"workspace_id"`
	ProjectID      string `json:"project_id"`
	ProjectSlug    string `json:"project_slug"`
	Alias          string `json:"alias"`
	HumanName      string `json:"human_name"`
	AttachmentType string `json:"attachment_type"`
	Created        bool   `json:"created"`
}

type WorkspaceClaim struct {
	BeadID    string  `json:"bead_id"`
	Title     *string `json:"title,omitempty"`
	ClaimedAt string  `json:"claimed_at"`
	ApexID    *string `json:"apex_id,omitempty"`
	ApexTitle *string `json:"apex_title,omitempty"`
	ApexType  *string `json:"apex_type,omitempty"`
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

func (c *Client) WorkspaceRegister(ctx context.Context, req *WorkspaceRegisterRequest) (*WorkspaceRegisterResponse, error) {
	var out WorkspaceRegisterResponse
	if err := c.Post(ctx, "/v1/workspaces/register", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) WorkspaceAttach(ctx context.Context, req *WorkspaceAttachRequest) (*WorkspaceAttachResponse, error) {
	var out WorkspaceAttachResponse
	if err := c.Post(ctx, "/v1/workspaces/attach", req, &out); err != nil {
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
