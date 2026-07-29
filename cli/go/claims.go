package aweb

import "context"

type ClaimView struct {
	BeadID      string `json:"bead_id"`
	WorkspaceID string `json:"workspace_id"`
	Alias       string `json:"alias"`
	HumanName   string `json:"human_name"`
	ClaimedAt   string `json:"claimed_at"`
}

type ClaimsResponse struct {
	Claims     []ClaimView `json:"claims"`
	HasMore    bool        `json:"has_more"`
	NextCursor *string     `json:"next_cursor,omitempty"`
}

func (c *Client) ClaimsList(ctx context.Context, workspaceID string, limit int) (*ClaimsResponse, error) {
	path := "/v1/claims"
	sep := "?"
	if workspaceID != "" {
		path += sep + "workspace_id=" + urlQueryEscape(workspaceID)
		sep = "&"
	}
	if limit > 0 {
		path += sep + "limit=" + itoa(limit)
	}
	var out ClaimsResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
