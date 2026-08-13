package aweb

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/awebai/aw/awid"
)

type IdentityGrantMintRequest struct {
	GrantDIDKey string   `json:"grant_did_key"`
	Scopes      []string `json:"scopes"`
	TTLSeconds  int      `json:"ttl_seconds"`
	Label       string   `json:"label,omitempty"`
}

type IdentityGrantView struct {
	GrantID      string   `json:"grant_id"`
	TeamID       string   `json:"team_id"`
	SubjectAlias string   `json:"subject_alias"`
	SubjectDIDAW string   `json:"subject_did_aw"`
	GrantDIDKey  string   `json:"grant_did_key"`
	Scopes       []string `json:"scopes"`
	Label        string   `json:"label,omitempty"`
	Status       string   `json:"status,omitempty"`
	IssuedAt     string   `json:"issued_at"`
	ExpiresAt    string   `json:"expires_at"`
}

type IdentityGrantListResponse struct {
	Grants []IdentityGrantView `json:"grants"`
}

func (c *Client) MintIdentityGrant(ctx context.Context, req *IdentityGrantMintRequest) (*IdentityGrantView, error) {
	var out IdentityGrantView
	if err := c.Post(ctx, "/v1/identity-grants", req, &out); err != nil {
		return nil, identityGrantCompatibilityError(err)
	}
	return &out, nil
}

func (c *Client) ListIdentityGrants(ctx context.Context) (*IdentityGrantListResponse, error) {
	var out IdentityGrantListResponse
	if err := c.Get(ctx, "/v1/identity-grants", &out); err != nil {
		return nil, identityGrantCompatibilityError(err)
	}
	return &out, nil
}

func (c *Client) RevokeIdentityGrant(ctx context.Context, grantID string) error {
	return identityGrantCompatibilityError(c.Post(ctx, "/v1/identity-grants/"+url.PathEscape(grantID)+"/revoke", nil, nil))
}

func identityGrantCompatibilityError(err error) error {
	if err == nil {
		return nil
	}
	if status, ok := awid.HTTPStatusCode(err); ok && status == http.StatusNotFound {
		return fmt.Errorf("identity grants require aweb server 1.27.2 or later: %w", err)
	}
	return err
}
