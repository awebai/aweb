package awid

import "context"

// --- Directory ---

type NetworkDirectoryAgent struct {
	OrgName      string   `json:"org_name"`
	Domain       string   `json:"org_slug"`
	Alias        string   `json:"alias"`
	Name         string   `json:"name,omitempty"`
	Capabilities []string `json:"capabilities"`
	Description  string   `json:"description"`
}

type NetworkDirectoryResponse struct {
	Agents []NetworkDirectoryAgent `json:"agents"`
	Total  int                     `json:"total"`
}

type NetworkDirectoryParams struct {
	Capability string
	Domain     string
	Query      string
	Limit      int
}

func (c *Client) NetworkDirectorySearch(ctx context.Context, p NetworkDirectoryParams) (*NetworkDirectoryResponse, error) {
	path := "/v1/network/directory"
	sep := "?"
	if p.Capability != "" {
		path += sep + "capability=" + urlQueryEscape(p.Capability)
		sep = "&"
	}
	if p.Domain != "" {
		path += sep + "org_slug=" + urlQueryEscape(p.Domain)
		sep = "&"
	}
	if p.Query != "" {
		path += sep + "q=" + urlQueryEscape(p.Query)
		sep = "&"
	}
	if p.Limit > 0 {
		path += sep + "limit=" + itoa(p.Limit)
	}
	var out NetworkDirectoryResponse
	if err := c.Get(ctx, path, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) NetworkDirectoryGet(ctx context.Context, domain, handle string) (*NetworkDirectoryAgent, error) {
	var out NetworkDirectoryAgent
	if err := c.Get(ctx, "/v1/network/directory/"+urlPathEscape(domain)+"/"+urlPathEscape(handle), &out); err != nil {
		return nil, err
	}
	return &out, nil
}
