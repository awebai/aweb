package awid

import "context"

// HeartbeatResponse is returned by POST /v1/agents/heartbeat.
type HeartbeatResponse struct {
	AgentID    string `json:"agent_id"`
	Alias      string `json:"alias"`
	LastSeenAt string `json:"last_seen_at"`
}

// Heartbeat reports agent liveness to the aweb server.
func (c *Client) Heartbeat(ctx context.Context) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.Post(ctx, "/v1/agents/heartbeat", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
