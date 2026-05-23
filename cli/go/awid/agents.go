package awid

import (
	"context"
	"strings"
)

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
	IdentityScope string `json:"identity_scope,omitempty"`
	InboundMode   string `json:"inbound_mode,omitempty"`
	Lifetime      string `json:"lifetime,omitempty"`
}

type ListAgentsResponse struct {
	TeamID string      `json:"team_id"`
	Agents []AgentView `json:"agents"`
}

type AgentInboundModeResponse struct {
	AgentID       string `json:"agent_id"`
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	InboundMode   string `json:"inbound_mode"`
	Configurable  bool   `json:"configurable"`
}

type UpdateAgentInboundModeRequest struct {
	InboundMode string `json:"inbound_mode"`
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

func (c *Client) GetMyInboundMode(ctx context.Context) (*AgentInboundModeResponse, error) {
	var out AgentInboundModeResponse
	if err := c.Get(ctx, "/v1/agents/me/inbound-mode", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateMyInboundMode(ctx context.Context, mode string) (*AgentInboundModeResponse, error) {
	var out AgentInboundModeResponse
	req := UpdateAgentInboundModeRequest{InboundMode: strings.TrimSpace(mode)}
	if err := c.Patch(ctx, "/v1/agents/me/inbound-mode", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
