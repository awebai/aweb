package aweb

import "context"

// AgentView is returned by GET /v1/agents.
type AgentView struct {
	AgentID   string `json:"agent_id"`
	Alias     string `json:"alias"`
	HumanName string `json:"human_name,omitempty"`
	AgentType string `json:"agent_type,omitempty"`
	Status    string `json:"status,omitempty"`
	LastSeen  string `json:"last_seen,omitempty"`
	Online    bool   `json:"online"`
}

type ListAgentsResponse struct {
	ProjectID string     `json:"project_id"`
	Agents    []AgentView `json:"agents"`
}

func (c *Client) ListAgents(ctx context.Context) (*ListAgentsResponse, error) {
	var out ListAgentsResponse
	if err := c.get(ctx, "/v1/agents", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

