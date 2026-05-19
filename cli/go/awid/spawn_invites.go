package awid

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

const spawnAcceptInvitePath = "/api/v1/spawn/accept-invite"

type SpawnCreateInviteRequest struct {
	AliasHint        string `json:"alias_hint,omitempty"`
	AccessMode       string `json:"access_mode,omitempty"`
	MaxUses          int    `json:"max_uses,omitempty"`
	ExpiresInSeconds int    `json:"expires_in_seconds,omitempty"`
}

type SpawnCreateInviteResponse struct {
	InviteID      string `json:"invite_id"`
	Token         string `json:"token"`
	TokenPrefix   string `json:"token_prefix"`
	AliasHint     string `json:"alias_hint,omitempty"`
	AccessMode    string `json:"access_mode"`
	MaxUses       int    `json:"max_uses"`
	ExpiresAt     string `json:"expires_at"`
	NamespaceSlug string `json:"namespace_slug"`
	Namespace     string `json:"namespace"`
	ServerURL     string `json:"server_url"`
}

type SpawnAcceptInviteRequest struct {
	Token     string `json:"token"`
	Alias     string `json:"alias,omitempty"`
	Name      string `json:"name,omitempty"`
	HumanName string `json:"human_name,omitempty"`
	AgentType string `json:"agent_type,omitempty"`
	DID       string `json:"did,omitempty"`
	PublicKey string `json:"public_key,omitempty"`
	Custody   string `json:"custody,omitempty"`
	Lifetime  string `json:"lifetime,omitempty"`
}

type SpawnAcceptInviteResponse struct {
	OrgID               string `json:"org_id,omitempty"`
	OrgSlug             string `json:"org_slug,omitempty"`
	TeamID              string `json:"team_id"`
	TeamSlug            string `json:"team_slug"`
	NamespaceSlug       string `json:"namespace_slug"`
	Namespace           string `json:"namespace"`
	IdentityID          string `json:"identity_id"`
	Alias               string `json:"alias,omitempty"`
	Name                string `json:"name,omitempty"`
	Address             string `json:"address,omitempty"`
	APIKey              string `json:"api_key,omitempty"`
	ServerURL           string `json:"server_url"`
	DID                 string `json:"did,omitempty"`
	StableID            string `json:"stable_id,omitempty"`
	Custody             string `json:"custody,omitempty"`
	Lifetime            string `json:"lifetime,omitempty"`
	AccessMode          string `json:"access_mode"`
	Created             bool   `json:"created"`
	AddressReachability string `json:"address_reachability,omitempty"`
	TeamCert            string `json:"team_cert,omitempty"`
}

func IsHostedSpawnInviteToken(token string) bool {
	return strings.HasPrefix(strings.TrimSpace(token), "aw_inv_")
}

func (c *Client) CreateSpawnInvite(ctx context.Context, req *SpawnCreateInviteRequest) (*SpawnCreateInviteResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("aweb: client is required")
	}
	if req == nil {
		req = &SpawnCreateInviteRequest{}
	}
	var out SpawnCreateInviteResponse
	if err := c.Post(ctx, "/api/v1/spawn/create-invite", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) AcceptSpawnInvite(ctx context.Context, req *SpawnAcceptInviteRequest) (*SpawnAcceptInviteResponse, error) {
	if c == nil {
		return nil, fmt.Errorf("aweb: client is required")
	}
	if req == nil {
		return nil, fmt.Errorf("aweb: spawn accept-invite request is required")
	}
	if strings.TrimSpace(req.Token) == "" {
		return nil, fmt.Errorf("aweb: token is required for spawn accept-invite")
	}
	if strings.TrimSpace(req.DID) == "" {
		return nil, fmt.Errorf("aweb: did is required for spawn accept-invite")
	}
	if c.signingKey == nil {
		return nil, fmt.Errorf("aweb: spawn accept-invite requires a signing key")
	}
	if c.did == "" {
		return nil, fmt.Errorf("aweb: spawn accept-invite requires a did:key identity")
	}
	if strings.TrimSpace(req.DID) != c.did {
		return nil, fmt.Errorf("aweb: did %q does not match client did:key %q", req.DID, c.did)
	}

	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	headers := onboardingDIDKeyHeaders(http.MethodPost, spawnAcceptInvitePath, bodyBytes, c.signingKey)

	var out SpawnAcceptInviteResponse
	if err := postJSONWithHeaders(ctx, c.baseURL, spawnAcceptInvitePath, bodyBytes, headers, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
