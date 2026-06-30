package awid

import "context"

type SuggestAliasPrefixResponse struct {
	TeamID     string               `json:"team_id"`
	NamePrefix string               `json:"name_prefix"`
	Names      []SuggestedAgentName `json:"names,omitempty"`
}

type SuggestedAgentName struct {
	Name string `json:"name"`
}

type SuggestAgentNamesRequest struct {
	Scope   string   `json:"scope,omitempty"`
	Exclude []string `json:"exclude,omitempty"`
	Count   int      `json:"count,omitempty"`
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

// SuggestAgentNames asks the server for one or more concrete available names.
// Unlike SuggestAliasPrefix, this sends the v2 request body and expects the
// response's ordered names[] list to be authoritative for the requested scope.
func (c *Client) SuggestAgentNames(ctx context.Context, req SuggestAgentNamesRequest) (*SuggestAliasPrefixResponse, error) {
	var out SuggestAliasPrefixResponse
	if err := c.Post(ctx, "/v1/agents/suggest-alias-prefix", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
