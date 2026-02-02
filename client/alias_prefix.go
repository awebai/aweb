package aweb

import "context"

type SuggestAliasPrefixRequest struct {
	ProjectSlug string `json:"project_slug"`
}

type SuggestAliasPrefixResponse struct {
	ProjectSlug string  `json:"project_slug"`
	ProjectID   *string `json:"project_id"`
	NamePrefix  string  `json:"name_prefix"`
}

// SuggestAliasPrefix suggests the next available classic alias prefix for a project.
//
// POST /v1/agents/suggest-alias-prefix
func (c *Client) SuggestAliasPrefix(ctx context.Context, projectSlug string) (*SuggestAliasPrefixResponse, error) {
	var out SuggestAliasPrefixResponse
	if err := c.post(ctx, "/v1/agents/suggest-alias-prefix", &SuggestAliasPrefixRequest{ProjectSlug: projectSlug}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

