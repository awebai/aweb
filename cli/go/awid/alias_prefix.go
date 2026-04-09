package awid

import "context"

type SuggestAliasPrefixResponse struct {
	TeamID     string `json:"team_id"`
	NamePrefix string `json:"name_prefix"`
}

// SuggestAliasPrefix suggests the next available classic alias prefix for the
// authenticated team.
//
// POST /v1/agents/suggest-alias-prefix
func (c *Client) SuggestAliasPrefix(ctx context.Context) (*SuggestAliasPrefixResponse, error) {
	var out SuggestAliasPrefixResponse
	if err := c.Post(ctx, "/v1/agents/suggest-alias-prefix", struct{}{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
