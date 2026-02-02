package aweb

import "context"

// InitRequest is sent to POST /v1/init.
//
// This endpoint is an OSS convenience for clean-start deployments.
// It typically does not require an API key.
type InitRequest struct {
	ProjectSlug string `json:"project_slug"`
	ProjectName string `json:"project_name,omitempty"`
	Alias       *string `json:"alias,omitempty"`
	HumanName   string `json:"human_name,omitempty"`
	AgentType   string `json:"agent_type,omitempty"`
}

// InitResponse is returned by POST /v1/init.
type InitResponse struct {
	Status      string `json:"status"`
	CreatedAt   string `json:"created_at"`
	ProjectID   string `json:"project_id"`
	ProjectSlug string `json:"project_slug"`
	AgentID     string `json:"agent_id"`
	Alias       string `json:"alias"`
	APIKey      string `json:"api_key"`
	Created     bool   `json:"created"`
}

// Init bootstraps a project, agent, and API key.
func (c *Client) Init(ctx context.Context, req *InitRequest) (*InitResponse, error) {
	var out InitResponse
	if err := c.post(ctx, "/v1/init", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
