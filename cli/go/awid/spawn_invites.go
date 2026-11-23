package awid

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

const spawnAcceptInvitePath = "/api/v1/spawn/accept-invite"

// SpawnCreateInviteRequest selects a hosted invitation's human condition,
// issuer chain and lifetime; the service still checks the authenticated issuer.
type SpawnCreateInviteRequest struct {
	ForHuman         *string        `json:"for_human,omitempty"`
	IDChain          map[string]any `json:"id_chain,omitempty"`
	AliasHint        string         `json:"alias_hint,omitempty"`
	AccessMode       string         `json:"access_mode,omitempty"`
	MaxUses          int            `json:"max_uses,omitempty"`
	ExpiresInSeconds int            `json:"expires_in_seconds,omitempty"`
}

// SpawnCreateInviteResponse includes the enrollment bearer and pinned issuer
// selection. Token is secret; IDTree alone does not prove current ancestry.
type SpawnCreateInviteResponse struct {
	ForHuman      *string            `json:"for_human"`
	IDTree        *SpawnInviteIDTree `json:"id_tree"`
	InviteID      string             `json:"invite_id"`
	Token         string             `json:"token"`
	TokenPrefix   string             `json:"token_prefix"`
	AliasHint     string             `json:"alias_hint,omitempty"`
	AccessMode    string             `json:"access_mode"`
	MaxUses       int                `json:"max_uses"`
	ExpiresAt     string             `json:"expires_at"`
	NamespaceSlug string             `json:"namespace_slug"`
	Namespace     string             `json:"namespace"`
	ServerURL     string             `json:"server_url"`
}

// SpawnInviteIDTree is pinned at invitation issue, before the child's key is
// selected. Mode describes issuer signing custody, independent of child scope.
type SpawnInviteIDTree struct {
	V         int    `json:"v"`
	IssuerID  string `json:"issuer_id"`
	Domain    string `json:"domain"`
	ChildKind string `json:"child_kind"`
	Mode      string `json:"mode"`
}

// SpawnInvitePreviewResponse carries public selection metadata, not a signature
// or authorization to issue a child certificate.
type SpawnInvitePreviewResponse struct {
	ForHuman           *string               `json:"for_human"`
	CreationInvitation *IDCreationInvitation `json:"creation_invitation,omitempty"`
	IDTreePresent      bool                  `json:"-"`
	InviteID           string                `json:"invite_id"`
	IDTree             *SpawnInviteIDTree    `json:"id_tree"`
	CanonicalTeamID    string                `json:"canonical_team_id"`
	IdentityScope      string                `json:"identity_scope"`
	ServerURL          string                `json:"server_url"`
	ExpiresAt          *string               `json:"expires_at"`
	Status             string                `json:"status"`
}

// SpawnAcceptInviteRequest binds an invitation to the joining key and any
// supplied child chain. Membership admission and ancestry are separate checks.
type SpawnAcceptInviteRequest struct {
	// Keep the request comparable, as in aw-v1.36.58. A nil pointer omits the chain.
	IDChain            *map[string]any                  `json:"id_chain,omitempty"`
	IDTree             *IDTreeCreationRequest           `json:"id_tree,omitempty"`
	Token              string                           `json:"token"`
	Alias              string                           `json:"alias,omitempty"`
	Name               string                           `json:"name,omitempty"`
	HumanName          string                           `json:"human_name,omitempty"`
	AgentType          string                           `json:"agent_type,omitempty"`
	DID                string                           `json:"did,omitempty"`
	StableID           string                           `json:"stable_id,omitempty"`
	PublicKey          string                           `json:"public_key,omitempty"`
	Custody            string                           `json:"custody,omitempty"`
	IdentityScope      string                           `json:"identity_scope,omitempty"`
	AtomicAddressClaim *AtomicAddressClaimIdentityProof `json:"atomic_address_claim,omitempty"`
}

// SpawnAcceptInviteResponse carries membership installation and attribution
// results. A caller must verify them against its selected team/registry before
// installation. APIKey is a released field; identity-key recovery must omit an
// unused credential from its journal.
type SpawnAcceptInviteResponse struct {
	IDTreeCreationResponse
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
	IdentityScope       string `json:"identity_scope,omitempty"`
	AccessMode          string `json:"access_mode"`
	Created             bool   `json:"created"`
	AddressReachability string `json:"address_reachability,omitempty"`
	TeamCert            string `json:"team_cert,omitempty"`
}

// IsHostedSpawnInviteToken recognizes the hosted bearer prefix for routing.
// It does not establish that the token exists, is valid or is unused.
func IsHostedSpawnInviteToken(token string) bool {
	return strings.HasPrefix(strings.TrimSpace(token), "aw_inv_")
}

// CreateSpawnInvite submits the selected issuance request using the client's
// authenticated team authority; nil selects the service's default request.
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

// AcceptSpawnInvite signs acceptance with the joining key, independently of
// any workspace API credential. A transport failure can follow a committed
// acceptance, so retain the same key and request for reconciliation.
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
		// A rejected token can be echoed by a service. Preserve status/diagnostics
		// without exposing the submitted credential to CLI errors or callers.
		var registryErr *RegistryError
		if errors.As(err, &registryErr) {
			redacted := *registryErr
			redacted.Detail = strings.ReplaceAll(redacted.Detail, req.Token, "<redacted>")
			return nil, &redacted
		}
		return nil, err
	}
	return &out, nil
}

// UnmarshalJSON preserves explicit ID-tree nulls versus released omission.
// Decoding a response does not verify its chain or membership authority.
func (response *SpawnAcceptInviteResponse) UnmarshalJSON(raw []byte) error {
	type plain SpawnAcceptInviteResponse
	if err := json.Unmarshal(raw, (*plain)(response)); err != nil {
		return err
	}
	tree, err := DecodeIDTreeCreationResponse(raw)
	if err != nil {
		return err
	}
	response.IDTreeCreationResponse = tree
	return nil
}

// MarshalJSON preserves legacy omission when a response is retained for resume.
func (response SpawnAcceptInviteResponse) MarshalJSON() ([]byte, error) {
	type plain SpawnAcceptInviteResponse
	raw, err := json.Marshal(plain(response))
	if err != nil || response.FieldsPresent || response.IDChain != nil || response.RegistrationRequest != nil {
		return raw, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	delete(fields, "id_chain")
	delete(fields, "registration_request")
	return json.Marshal(fields)
}

// UnmarshalJSON keeps ID-tree presence and validates the optional creation
// invitation's shape without treating a preview as current issuer authority.
func (response *SpawnInvitePreviewResponse) UnmarshalJSON(raw []byte) error {
	type plain SpawnInvitePreviewResponse
	if err := json.Unmarshal(raw, (*plain)(response)); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return err
	}
	_, response.IDTreePresent = fields["id_tree"]
	inv, err := DecodeIDCreationInvitation(raw)
	response.CreationInvitation = inv
	return err
}
