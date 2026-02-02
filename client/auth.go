package aweb

import "context"

// IntrospectResponse is returned by GET /v1/auth/introspect.
type IntrospectResponse struct {
	ProjectID string `json:"project_id"`
	APIKeyID  string `json:"api_key_id,omitempty"`
	AgentID   string `json:"agent_id,omitempty"`
	Alias     string `json:"alias,omitempty"`
	HumanName string `json:"human_name,omitempty"`
	AgentType string `json:"agent_type,omitempty"`
	UserID    string `json:"user_id,omitempty"`
}

// Introspect validates the client's Bearer token and returns the scoped project_id.
func (c *Client) Introspect(ctx context.Context) (*IntrospectResponse, error) {
	var out IntrospectResponse
	if err := c.get(ctx, "/v1/auth/introspect", &out); err != nil {
		return nil, err
	}
	return &out, nil
}
