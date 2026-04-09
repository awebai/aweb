package awid

import "context"

// Deregister deregisters the authenticated agent (self).
// Server destroys the keypair, marks agent as deregistered, frees the
// alias for reuse.
func (c *Client) Deregister(ctx context.Context) error {
	return c.Delete(ctx, "/v1/agents/me")
}

// DeregisterAgent deregisters a peer agent by address. Used by team
// controllers to clean up ephemeral agents.
func (c *Client) DeregisterAgent(ctx context.Context, namespace, alias string) error {
	return c.Delete(ctx, "/v1/agents/"+urlPathEscape(namespace)+"/"+urlPathEscape(alias))
}
