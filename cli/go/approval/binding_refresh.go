package approval

import (
	"context"

	proof "github.com/awebai/approval-service/verify"
)

// BindingRefreshInput carries the holder packet unchanged as a JSON value.
// Signature and answer policy stay in the shared binding-refresh-v1 owner.
type BindingRefreshInput struct {
	Packet map[string]any
}

// BindingRefreshResponse is transport data; the shared answer reader must check it before storage.
type BindingRefreshResponse struct {
	Status int
	Body   map[string]any
}

// RefreshBinding transports the unchanged holder packet. Call the shared
// ReadBindingRefreshAnswer before storing its returned binding as live authority.
func (c *Client) RefreshBinding(ctx context.Context, in BindingRefreshInput) (*BindingRefreshResponse, error) {
	raw, status, err := c.exchange(ctx, PurposeBindingRefresh, in.Packet)
	if err != nil {
		return nil, err
	}
	body, err := proof.Parse(raw)
	if err != nil {
		return nil, err
	}
	return &BindingRefreshResponse{Status: status, Body: body}, nil
}
