package aweb

import (
	"context"
	"encoding/json"
)

type ProjectInstructionsDocument struct {
	BodyMD string `json:"body_md"`
	Format string `json:"format"`
}

type ActiveProjectInstructionsResponse struct {
	ProjectInstructionsID       string                      `json:"project_instructions_id"`
	ActiveProjectInstructionsID string                      `json:"active_project_instructions_id,omitempty"`
	ProjectID                   string                      `json:"project_id"`
	Version                     int                         `json:"version"`
	UpdatedAt                   string                      `json:"updated_at"`
	Document                    ProjectInstructionsDocument `json:"document"`
}

type CreateProjectInstructionsRequest struct {
	Document                  ProjectInstructionsDocument `json:"document"`
	BaseProjectInstructionsID string                      `json:"base_project_instructions_id,omitempty"`
	CreatedByWorkspaceID      string                      `json:"created_by_workspace_id,omitempty"`
}

type CreateProjectInstructionsResponse struct {
	ProjectInstructionsID string `json:"project_instructions_id"`
	ProjectID             string `json:"project_id"`
	Version               int    `json:"version"`
	Created               bool   `json:"created"`
}

type ActivateProjectInstructionsResponse struct {
	Activated                   bool   `json:"activated"`
	ActiveProjectInstructionsID string `json:"active_project_instructions_id"`
}

type ResetProjectInstructionsResponse struct {
	Reset                       bool   `json:"reset"`
	ActiveProjectInstructionsID string `json:"active_project_instructions_id"`
	Version                     int    `json:"version"`
}

type ProjectInstructionsHistoryItem struct {
	ProjectInstructionsID string  `json:"project_instructions_id"`
	Version               int     `json:"version"`
	CreatedAt             string  `json:"created_at"`
	CreatedByWorkspaceID  *string `json:"created_by_workspace_id"`
	IsActive              bool    `json:"is_active"`
}

type ProjectInstructionsHistoryResponse struct {
	ProjectInstructionsVersions []ProjectInstructionsHistoryItem `json:"project_instructions_versions"`
}

func (r *ProjectInstructionsHistoryResponse) UnmarshalJSON(data []byte) error {
	type rawHistoryResponse struct {
		ProjectInstructionsVersions []ProjectInstructionsHistoryItem `json:"project_instructions_versions"`
		LegacyVersions              []ProjectInstructionsHistoryItem `json:"project_instruction_versions"`
	}

	var raw rawHistoryResponse
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	r.ProjectInstructionsVersions = raw.ProjectInstructionsVersions
	if len(r.ProjectInstructionsVersions) == 0 {
		r.ProjectInstructionsVersions = raw.LegacyVersions
	}
	return nil
}

func (c *Client) ActiveProjectInstructions(ctx context.Context) (*ActiveProjectInstructionsResponse, error) {
	var out ActiveProjectInstructionsResponse
	if err := c.Get(ctx, "/v1/instructions/active", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ProjectInstructionsHistory(ctx context.Context, limit int) (*ProjectInstructionsHistoryResponse, error) {
	path := "/v1/instructions/history"
	if limit > 0 {
		path += "?limit=" + itoa(limit)
	}
	var out ProjectInstructionsHistoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetProjectInstructions(ctx context.Context, projectInstructionsID string) (*ActiveProjectInstructionsResponse, error) {
	var out ActiveProjectInstructionsResponse
	if err := c.Get(ctx, "/v1/instructions/"+urlPathEscape(projectInstructionsID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateProjectInstructions(ctx context.Context, req *CreateProjectInstructionsRequest) (*CreateProjectInstructionsResponse, error) {
	var out CreateProjectInstructionsResponse
	if err := c.Post(ctx, "/v1/instructions", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ActivateProjectInstructions(ctx context.Context, projectInstructionsID string) (*ActivateProjectInstructionsResponse, error) {
	var out ActivateProjectInstructionsResponse
	if err := c.Post(ctx, "/v1/instructions/"+urlPathEscape(projectInstructionsID)+"/activate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ResetProjectInstructions(ctx context.Context) (*ResetProjectInstructionsResponse, error) {
	var out ResetProjectInstructionsResponse
	if err := c.Post(ctx, "/v1/instructions/reset", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
