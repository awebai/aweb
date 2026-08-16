package aweb

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

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
	WorkspaceID        string           `json:"workspace_id"`
	AgentID            string           `json:"agent_id,omitempty"`
	Alias              string           `json:"alias"`
	AgentIdentityScope *string          `json:"agent_identity_scope,omitempty"`
	HumanName          *string          `json:"human_name,omitempty"`
	ContextKind        *string          `json:"context_kind,omitempty"`
	Program            *string          `json:"program,omitempty"`
	Model              *string          `json:"model,omitempty"`
	Repo               *string          `json:"repo,omitempty"`
	Branch             *string          `json:"branch,omitempty"`
	MemberEmail        *string          `json:"member_email,omitempty"`
	Role               *string          `json:"role,omitempty"`
	Hostname           *string          `json:"hostname,omitempty"`
	WorkspacePath      *string          `json:"workspace_path,omitempty"`
	ApexID             *string          `json:"apex_id,omitempty"`
	ApexTitle          *string          `json:"apex_title,omitempty"`
	ApexType           *string          `json:"apex_type,omitempty"`
	FocusTaskRef       *string          `json:"focus_task_ref,omitempty"`
	FocusTaskTitle     *string          `json:"focus_task_title,omitempty"`
	FocusTaskType      *string          `json:"focus_task_type,omitempty"`
	FocusTaskRepoName  *string          `json:"focus_task_repo_name,omitempty"`
	FocusTaskBranch    *string          `json:"focus_task_branch,omitempty"`
	FocusUpdatedAt     *string          `json:"focus_updated_at,omitempty"`
	Status             string           `json:"status"`
	LastSeen           *string          `json:"last_seen,omitempty"`
	DeletedAt          *string          `json:"deleted_at,omitempty"`
	Claims             []WorkspaceClaim `json:"claims,omitempty"`
}

type WorkspaceListResponse struct {
	Workspaces []WorkspaceInfo `json:"workspaces"`
	HasMore    bool            `json:"has_more"`
	NextCursor *string         `json:"next_cursor,omitempty"`
}

type DeleteWorkspaceResponse struct {
	WorkspaceID     string `json:"workspace_id"`
	Alias           string `json:"alias"`
	DeletedAt       string `json:"deleted_at"`
	IdentityDeleted bool   `json:"identity_deleted"`
	// ClaimsReleased is nil when the server did not report a count, which is what
	// a server older than the field does. Absent is not zero: reporting "released
	// 0 claims" for a delete that released three would assert a number nobody
	// sent.
	ClaimsReleased *int `json:"claims_released"`
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
	RoleName      string `json:"role_name,omitempty"`
	Role          string `json:"role,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
	RepoOrigin    string `json:"repo_origin,omitempty"`
}

type PatchCurrentWorkspaceResponse struct {
	AgentID         string `json:"agent_id"`
	Alias           string `json:"alias"`
	Hostname        string `json:"hostname,omitempty"`
	WorkspacePath   string `json:"workspace_path,omitempty"`
	RoleName        string `json:"role_name,omitempty"`
	Role            string `json:"role,omitempty"`
	HumanName       string `json:"human_name,omitempty"`
	RepoID          string `json:"repo_id,omitempty"`
	CanonicalOrigin string `json:"canonical_origin,omitempty"`
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

// The two 404s a workspace delete can produce say different things, and a caller
// that collapses them reports an outcome it did not observe. The server carries a
// structured code for exactly this reason; keying on it rather than on the message
// text means rewording the message cannot silently reclassify the result.
var (
	// ErrWorkspaceAlreadyDeleted establishes two facts: the workspace row is
	// deleted, and its bound identity is NOT - that is why the server refused.
	ErrWorkspaceAlreadyDeleted = errors.New("workspace already deleted; its identity was not cleaned")
	// ErrWorkspaceNotFound establishes neither. The workspace may never have
	// existed, or may belong to a team this caller cannot see.
	ErrWorkspaceNotFound = errors.New("workspace not found")
)

// WorkspaceDelete soft-deletes a workspace by its ID.
//
// A 404 is returned as ErrWorkspaceAlreadyDeleted or ErrWorkspaceNotFound rather
// than as a nil response. It used to return nil, nil - which the server
// anticipated and warned against in coordination/routes/workspaces.py: "Re-enter
// the idempotent post-commit step instead of turning 404 into false terminal
// success at the client."
func (c *Client) WorkspaceDelete(ctx context.Context, workspaceID string) (*DeleteWorkspaceResponse, error) {
	var out DeleteWorkspaceResponse
	err := c.Do(ctx, "DELETE", "/v1/workspaces/"+urlPathEscape(workspaceID), nil, &out)
	if err != nil {
		if code, ok := awid.HTTPStatusCode(err); ok && code == 404 {
			switch workspaceDeleteRefusalCode(err) {
			case "workspace_already_deleted":
				return nil, fmt.Errorf("%w: %s", ErrWorkspaceAlreadyDeleted, workspaceID)
			case "workspace_not_found":
				return nil, fmt.Errorf("%w: %s", ErrWorkspaceNotFound, workspaceID)
			}
			// An unrecognised 404 establishes nothing, so it must not be reported
			// as either outcome. A server too old to carry the code lands here.
			return nil, fmt.Errorf("workspace %s: delete refused with an unrecognised 404: %w", workspaceID, err)
		}
		return nil, err
	}
	return &out, nil
}

// workspaceDeleteRefusalCode reads the structured refusal code, or "" when the
// response does not carry one.
func workspaceDeleteRefusalCode(err error) string {
	body, ok := awid.HTTPErrorBody(err)
	if !ok || strings.TrimSpace(body) == "" {
		return ""
	}
	var envelope struct {
		Detail struct {
			Code string `json:"code"`
		} `json:"detail"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil {
		return ""
	}
	return strings.TrimSpace(envelope.Detail.Code)
}

type WorkspaceListParams struct {
	Hostname        string
	Alias           string
	IncludePresence bool
	Limit           int
}

// WorkspaceList lists workspaces, optionally filtered by hostname or alias.
func (c *Client) WorkspaceList(ctx context.Context, params WorkspaceListParams) (*WorkspaceListResponse, error) {
	path := "/v1/workspaces"
	sep := "?"
	if params.Hostname != "" {
		path += sep + "hostname=" + urlQueryEscape(params.Hostname)
		sep = "&"
	}
	if params.Alias != "" {
		path += sep + "alias=" + urlQueryEscape(params.Alias)
		sep = "&"
	}
	path += sep + "include_presence=" + boolString(params.IncludePresence)
	if params.Limit > 0 {
		path += "&limit=" + itoa(params.Limit)
	}
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
