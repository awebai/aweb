package awid

import (
	"context"
	"fmt"
)

// CreateProjectRequest is sent to POST /api/v1/create-project.
type CreateProjectRequest struct {
	ProjectSlug         string  `json:"project_slug"`
	NamespaceSlug       string  `json:"namespace_slug,omitempty"`
	Alias               *string `json:"alias,omitempty"`
	Name                *string `json:"name,omitempty"`
	AddressReachability string  `json:"address_reachability,omitempty"`
	AgentType           string  `json:"agent_type,omitempty"`
	HumanName           string  `json:"human_name,omitempty"`
	DID                 string  `json:"did,omitempty"`
	PublicKey           string  `json:"public_key,omitempty"`
	Custody             string  `json:"custody,omitempty"`
	Lifetime            string  `json:"lifetime,omitempty"`
}

// CreateProject creates a project, its attached namespace, first workspace, and
// first identity in one unauthenticated rate-limited call.
func (c *Client) CreateProject(ctx context.Context, req *CreateProjectRequest) (*BootstrapIdentityResponse, error) {
	if req.ProjectSlug == "" {
		return nil, fmt.Errorf("aweb: project_slug is required for create-project")
	}
	if req.Alias == nil && req.Name == nil {
		return nil, fmt.Errorf("aweb: either alias or name is required for create-project")
	}
	var out BootstrapIdentityResponse
	if err := c.Post(ctx, "/api/v1/create-project", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
