package aweb

import "context"

type TeamInstructionsDocument struct {
	BodyMD string `json:"body_md"`
	Format string `json:"format"`
}

type ActiveTeamInstructionsResponse struct {
	TeamInstructionsID       string                   `json:"team_instructions_id"`
	ActiveTeamInstructionsID string                   `json:"active_team_instructions_id,omitempty"`
	TeamID                   string                   `json:"team_id"`
	Version                  int                      `json:"version"`
	UpdatedAt                string                   `json:"updated_at"`
	Document                 TeamInstructionsDocument `json:"document"`
}

type CreateTeamInstructionsRequest struct {
	Document               TeamInstructionsDocument `json:"document"`
	BaseTeamInstructionsID string                   `json:"base_team_instructions_id,omitempty"`
	CreatedByAlias         string                   `json:"created_by_alias,omitempty"`
}

type CreateTeamInstructionsResponse struct {
	TeamInstructionsID string `json:"team_instructions_id"`
	TeamID             string `json:"team_id"`
	Version            int    `json:"version"`
	Created            bool   `json:"created"`
}

type ActivateTeamInstructionsResponse struct {
	Activated                bool   `json:"activated"`
	ActiveTeamInstructionsID string `json:"active_team_instructions_id"`
}

type ResetTeamInstructionsResponse struct {
	Reset                    bool   `json:"reset"`
	ActiveTeamInstructionsID string `json:"active_team_instructions_id"`
	Version                  int    `json:"version"`
}

type TeamInstructionsHistoryItem struct {
	TeamInstructionsID string  `json:"team_instructions_id"`
	Version            int     `json:"version"`
	CreatedAt          string  `json:"created_at"`
	CreatedByAlias     *string `json:"created_by_alias"`
	IsActive           bool    `json:"is_active"`
}

type TeamInstructionsHistoryResponse struct {
	TeamInstructionsVersions []TeamInstructionsHistoryItem `json:"team_instructions_versions"`
}

func (c *Client) ActiveTeamInstructions(ctx context.Context) (*ActiveTeamInstructionsResponse, error) {
	var out ActiveTeamInstructionsResponse
	if err := c.Get(ctx, "/v1/instructions/active", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) TeamInstructionsHistory(ctx context.Context, limit int) (*TeamInstructionsHistoryResponse, error) {
	path := "/v1/instructions/history"
	if limit > 0 {
		path += "?limit=" + itoa(limit)
	}
	var out TeamInstructionsHistoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) GetTeamInstructions(ctx context.Context, teamInstructionsID string) (*ActiveTeamInstructionsResponse, error) {
	var out ActiveTeamInstructionsResponse
	if err := c.Get(ctx, "/v1/instructions/"+urlPathEscape(teamInstructionsID), &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) CreateTeamInstructions(ctx context.Context, req *CreateTeamInstructionsRequest) (*CreateTeamInstructionsResponse, error) {
	var out CreateTeamInstructionsResponse
	if err := c.Post(ctx, "/v1/instructions", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ActivateTeamInstructions(ctx context.Context, teamInstructionsID string) (*ActivateTeamInstructionsResponse, error) {
	var out ActivateTeamInstructionsResponse
	if err := c.Post(ctx, "/v1/instructions/"+urlPathEscape(teamInstructionsID)+"/activate", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) ResetTeamInstructions(ctx context.Context) (*ResetTeamInstructionsResponse, error) {
	var out ResetTeamInstructionsResponse
	if err := c.Post(ctx, "/v1/instructions/reset", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
