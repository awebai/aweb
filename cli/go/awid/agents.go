package awid

import "context"

// HeartbeatResponse is returned by POST /v1/agents/heartbeat.
type HeartbeatResponse struct {
	AgentID    string `json:"agent_id"`
	Alias      string `json:"alias"`
	LastSeenAt string `json:"last_seen_at"`
}

type AgentView struct {
	AgentID       string `json:"agent_id"`
	Alias         string `json:"alias"`
	DIDKey        string `json:"did_key"`
	DIDAW         string `json:"did_aw,omitempty"`
	Address       string `json:"address,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
	AgentType     string `json:"agent_type,omitempty"`
	WorkspaceType string `json:"workspace_type,omitempty"`
	Role          string `json:"role,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	WorkspacePath string `json:"workspace_path,omitempty"`
	Repo          string `json:"repo,omitempty"`
	Status        string `json:"status,omitempty"`
	LastSeen      string `json:"last_seen,omitempty"`
	Online        bool   `json:"online,omitempty"`
	Lifetime      string `json:"lifetime,omitempty"`
}

type ListAgentsResponse struct {
	TeamID string      `json:"team_id"`
	Agents []AgentView `json:"agents"`
}

// Heartbeat reports agent liveness to the aweb server.
func (c *Client) Heartbeat(ctx context.Context) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.Post(ctx, "/v1/agents/heartbeat", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAgents lists agents visible in the authenticated team.
func (c *Client) ListAgents(ctx context.Context) (*ListAgentsResponse, error) {
	var out ListAgentsResponse
	if err := c.Get(ctx, "/v1/agents", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
