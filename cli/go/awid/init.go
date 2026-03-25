package awid

import "context"

// BootstrapIdentityResponse is returned by identity-creation routes that create
// a workspace-bound identity and API key in one call.
type BootstrapIdentityResponse struct {
	Status              string `json:"status"`
	CreatedAt           string `json:"created_at"`
	ProjectID           string `json:"project_id"`
	ProjectSlug         string `json:"project_slug"`
	NamespaceSlug       string `json:"namespace_slug,omitempty"`
	Namespace           string `json:"namespace,omitempty"`
	IdentityID          string `json:"identity_id"`
	Alias               string `json:"alias,omitempty"`
	Name                string `json:"name,omitempty"`
	Address             string `json:"address,omitempty"`
	AddressReachability string `json:"address_reachability,omitempty"`
	APIKey              string `json:"api_key"`
	ServerURL           string `json:"server_url,omitempty"`
	Created             bool   `json:"created"`
	DID                 string `json:"did,omitempty"`
	StableID            string `json:"stable_id,omitempty"`
	Custody             string `json:"custody,omitempty"`
	Lifetime            string `json:"lifetime,omitempty"`
}

func (r *BootstrapIdentityResponse) IdentityHandle() string {
	if r == nil {
		return ""
	}
	if r.Name != "" {
		return r.Name
	}
	return r.Alias
}

// WorkspaceInitRequest is sent to POST /v1/workspaces/init.
type WorkspaceInitRequest struct {
	ProjectSlug         string  `json:"project_slug,omitempty"`
	NamespaceSlug       string  `json:"namespace_slug,omitempty"`
	Alias               *string `json:"alias,omitempty"`
	Name                *string `json:"name,omitempty"`
	AddressReachability string  `json:"address_reachability,omitempty"`
	HumanName           string  `json:"human_name,omitempty"`
	AgentType           string  `json:"agent_type,omitempty"`
	DID                 string  `json:"did,omitempty"`
	PublicKey           string  `json:"public_key,omitempty"`
	Custody             string  `json:"custody,omitempty"`
	Lifetime            string  `json:"lifetime,omitempty"`
}

// InitWorkspace initializes a local workspace into an existing project using
// project authority.
func (c *Client) InitWorkspace(ctx context.Context, req *WorkspaceInitRequest) (*BootstrapIdentityResponse, error) {
	var out BootstrapIdentityResponse
	if err := c.Post(ctx, "/v1/workspaces/init", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
