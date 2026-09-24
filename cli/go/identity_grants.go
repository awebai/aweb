package aweb

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

type IdentityGrantMintRequest struct {
	GrantDIDKey string   `json:"grant_did_key"`
	Scopes      []string `json:"scopes"`
	TTLSeconds  int      `json:"ttl_seconds"`
	Label       string   `json:"label,omitempty"`
}

type IdentityGrantView struct {
	GrantID         string   `json:"grant_id"`
	TeamID          string   `json:"team_id"`
	SubjectAlias    string   `json:"subject_alias"`
	SubjectDIDAW    string   `json:"subject_did_aw"`
	GrantDIDKey     string   `json:"grant_did_key"`
	Scopes          []string `json:"scopes"`
	Label           string   `json:"label,omitempty"`
	Status          string   `json:"status,omitempty"`
	EffectiveStatus string   `json:"effective_status,omitempty"`
	StatusDetail    string   `json:"status_detail,omitempty"`
	IssuedAt        string   `json:"issued_at"`
	ExpiresAt       string   `json:"expires_at"`
	RevokedAt       string   `json:"revoked_at,omitempty"`
	LastCheckedAt   string   `json:"last_checked_at,omitempty"`
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

func (c *Client) IdentityGrantStatus(ctx context.Context, grantID string) (*IdentityGrantView, error) {
	var out IdentityGrantView
	if err := c.Get(ctx, "/v1/identity-grants/"+url.PathEscape(grantID)+"/status", &out); err != nil {
		return nil, identityGrantCompatibilityError(err)
	}
	if strings.TrimSpace(out.EffectiveStatus) == "" || strings.TrimSpace(out.ExpiresAt) == "" || strings.TrimSpace(out.LastCheckedAt) == "" {
		return nil, fmt.Errorf("identity grant status endpoint is incompatible: missing effective status contract")
	}
	return &out, nil
}

func (c *Client) ProbeIdentityGrantStatus(ctx context.Context) (string, error) {
	var ignored IdentityGrantView
	err := c.Get(ctx, "/v1/identity-grants/00000000-0000-0000-0000-000000000000/status", &ignored)
	if err == nil {
		return "", fmt.Errorf("identity grant status probe unexpectedly found nil grant")
	}
	status, ok := awid.HTTPStatusCode(err)
	if !ok || status != http.StatusNotFound {
		return "", identityGrantCompatibilityError(err)
	}
	body, _ := awid.HTTPErrorBody(err)
	var typed struct {
		Code     string `json:"code"`
		Contract string `json:"contract"`
	}
	if json.Unmarshal([]byte(body), &typed) != nil || typed.Code != "grant_not_found" || typed.Contract != "identity-grant-status.v1" {
		return "", fmt.Errorf("identity grant status endpoint is incompatible")
	}
	return time.Now().UTC().Format(time.RFC3339), nil
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
