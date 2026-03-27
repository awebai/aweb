package aweb

import "context"

type CoordinationWorkspace struct {
	WorkspaceID    string `json:"workspace_id,omitempty"`
	ProjectID      string `json:"project_id,omitempty"`
	ProjectSlug    string `json:"project_slug,omitempty"`
	RepoID         string `json:"repo_id,omitempty"`
	WorkspaceCount int    `json:"workspace_count,omitempty"`
}

type CoordinationAgent struct {
	WorkspaceID     string                    `json:"workspace_id"`
	Alias           string                    `json:"alias"`
	Member          *string                   `json:"member,omitempty"`
	HumanName       *string                   `json:"human_name,omitempty"`
	Program         *string                   `json:"program,omitempty"`
	Role            *string                   `json:"role,omitempty"`
	Status          string                    `json:"status"`
	CurrentBranch   *string                   `json:"current_branch,omitempty"`
	CanonicalOrigin *string                   `json:"canonical_origin,omitempty"`
	Hostname        *string                   `json:"hostname,omitempty"`
	WorkspacePath   *string                   `json:"workspace_path,omitempty"`
	Timezone        *string                   `json:"timezone,omitempty"`
	CurrentTaskRef  *string                   `json:"current_task_ref,omitempty"`
	FocusTaskRef    *string                   `json:"focus_task_ref,omitempty"`
	FocusTaskTitle  *string                   `json:"focus_task_title,omitempty"`
	FocusTaskType   *string                   `json:"focus_task_type,omitempty"`
	FocusUpdatedAt  *string                   `json:"focus_updated_at,omitempty"`
	ApexTaskRef     *string                   `json:"apex_task_ref,omitempty"`
	ApexTitle       *string                   `json:"apex_title,omitempty"`
	ApexType        *string                   `json:"apex_type,omitempty"`
	Claims          []CoordinationClaim       `json:"claims,omitempty"`
	Reservations    []CoordinationReservation `json:"reservations,omitempty"`
	LastSeen        *string                   `json:"last_seen,omitempty"`
}

type CoordinationClaim struct {
	TaskRef       string  `json:"task_ref"`
	WorkspaceID   string  `json:"workspace_id"`
	Alias         string  `json:"alias"`
	HumanName     *string `json:"human_name,omitempty"`
	ClaimedAt     string  `json:"claimed_at"`
	ClaimantCount int     `json:"claimant_count"`
	Title         *string `json:"title,omitempty"`
	ProjectID     string  `json:"project_id"`
	ApexTaskRef   *string `json:"apex_task_ref,omitempty"`
	ApexTitle     *string `json:"apex_title,omitempty"`
	ApexType      *string `json:"apex_type,omitempty"`
}

type CoordinationConflictClaimant struct {
	Alias       string  `json:"alias"`
	HumanName   *string `json:"human_name,omitempty"`
	WorkspaceID string  `json:"workspace_id"`
}

type CoordinationConflict struct {
	TaskRef   string                         `json:"task_ref"`
	Claimants []CoordinationConflictClaimant `json:"claimants"`
}

type CoordinationReservation struct {
	ProjectID           string         `json:"project_id"`
	ResourceKey         string         `json:"resource_key"`
	HolderAgentID       string         `json:"holder_agent_id"`
	HolderAlias         string         `json:"holder_alias"`
	AcquiredAt          string         `json:"acquired_at"`
	ExpiresAt           string         `json:"expires_at"`
	TTLRemainingSeconds int            `json:"ttl_remaining_seconds"`
	Reason              *string        `json:"reason,omitempty"`
	Metadata            map[string]any `json:"metadata,omitempty"`
}

type CoordinationStatusResponse struct {
	Workspace          CoordinationWorkspace     `json:"workspace"`
	Agents             []CoordinationAgent       `json:"agents"`
	Claims             []CoordinationClaim       `json:"claims"`
	Conflicts          []CoordinationConflict    `json:"conflicts"`
	Locks              []CoordinationReservation `json:"locks,omitempty"`
	EscalationsPending int                       `json:"escalations_pending"`
	Timestamp          string                    `json:"timestamp"`
}

func (c *Client) CoordinationStatus(ctx context.Context, workspaceID string) (*CoordinationStatusResponse, error) {
	path := "/v1/status"
	if workspaceID != "" {
		path += "?workspace_id=" + urlQueryEscape(workspaceID)
	}
	var out CoordinationStatusResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
