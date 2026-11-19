package awid

import (
	"context"
	"errors"
)

// ErrBootstrapTokensUnsupported names the recovery path for obsolete bootstrap tokens.
var ErrBootstrapTokensUnsupported = errors.New("Bootstrap tokens are not supported; use a setup key from the dashboard or run `aw init --join-from`.")

// BootstrapRedeemRequest is retained for source compatibility with the retired token flow.
type BootstrapRedeemRequest struct {
	Token  string `json:"token"`
	DIDKey string `json:"did_key"`
	DIDAW  string `json:"did_aw,omitempty"`
}

// BootstrapRedeemResponse is retained for source compatibility; BootstrapRedeem always refuses.
type BootstrapRedeemResponse struct {
	Certificate   string `json:"certificate"`
	TeamID        string `json:"team_id"`
	IdentityScope string `json:"identity_scope,omitempty"`
	Alias         string `json:"alias"`
	DIDAW         string `json:"did_aw,omitempty"`
	MemberAddress string `json:"member_address,omitempty"`
}

// BootstrapRedeem retains source compatibility for callers of the retired token flow.
// No server serves that route. Use a dashboard setup key or aw init --join-from.
func (c *Client) BootstrapRedeem(_ context.Context, _ *BootstrapRedeemRequest) (*BootstrapRedeemResponse, error) {
	return nil, ErrBootstrapTokensUnsupported
}
