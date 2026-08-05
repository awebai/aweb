package awid

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"
)

// HeartbeatResponse is returned by POST /v1/agents/heartbeat.
type HeartbeatResponse struct {
	AgentID         string `json:"agent_id"`
	Alias           string `json:"alias"`
	LastSeenAt      string `json:"last_seen_at"`
	RepoStatus      string `json:"repo_status,omitempty"`
	CanonicalOrigin string `json:"canonical_origin,omitempty"`
	RepoID          string `json:"repo_id,omitempty"`
	RepoError       string `json:"repo_error,omitempty"`
}

type AgentView struct {
	AgentID       string                  `json:"agent_id"`
	Alias         string                  `json:"alias"`
	DIDKey        string                  `json:"did_key"`
	DIDAW         string                  `json:"did_aw,omitempty"`
	Address       string                  `json:"address,omitempty"`
	HumanName     string                  `json:"human_name,omitempty"`
	AgentType     string                  `json:"agent_type,omitempty"`
	WorkspaceType string                  `json:"workspace_type,omitempty"`
	Role          string                  `json:"role,omitempty"`
	Hostname      string                  `json:"hostname,omitempty"`
	WorkspacePath string                  `json:"workspace_path,omitempty"`
	Repo          string                  `json:"repo,omitempty"`
	Status        string                  `json:"status,omitempty"`
	LastSeen      string                  `json:"last_seen,omitempty"`
	Online        bool                    `json:"online,omitempty"`
	IdentityScope string                  `json:"identity_scope,omitempty"`
	InboundMode   string                  `json:"inbound_mode,omitempty"`
	EncryptionKey *EncryptionKeyAssertion `json:"encryption_key,omitempty"`
}

func (a AgentView) VerifyEncryptionKey(now time.Time) error {
	if a.EncryptionKey == nil {
		return nil
	}
	return VerifyEncryptionKeyAssertion(
		a.EncryptionKey,
		strings.TrimSpace(a.DIDKey),
		strings.TrimSpace(a.DIDAW),
		now,
	)
}

func (a AgentView) RequireEncryptionKey(now time.Time) (*EncryptionKeyAssertion, error) {
	if a.EncryptionKey == nil {
		return nil, fmt.Errorf("agent %s has no E2E encryption key; ask them to upgrade aw/Pi/channel and publish one, or explicitly send a server-readable upgrade note with --plaintext", a.Alias)
	}
	if err := a.VerifyEncryptionKey(now); err != nil {
		return nil, err
	}
	return a.EncryptionKey, nil
}

func (c *Client) e2eeRecipientFromAgent(ctx context.Context, agent AgentView) (E2EERecipientKey, error) {
	if strings.TrimSpace(agent.DIDAW) != "" {
		return c.e2eeGlobalRecipientFromAgent(ctx, agent)
	}
	if assertion, err := agent.RequireEncryptionKey(time.Now().UTC()); err == nil {
		return E2EERecipientKey{
			Address:       strings.TrimSpace(agent.Address),
			DID:           strings.TrimSpace(agent.DIDKey),
			EncryptionKey: assertion,
			InboundMode:   strings.TrimSpace(agent.InboundMode),
		}, nil
	} else if agent.EncryptionKey != nil {
		return E2EERecipientKey{}, err
	}

	return E2EERecipientKey{}, fmt.Errorf("agent %s has no E2E encryption key; local-only recipients cannot be resolved through AWID, ask them to upgrade aw/Pi/channel and publish one, or explicitly send a server-readable upgrade note with --plaintext", agent.Alias)
}

func (c *Client) e2eeGlobalRecipientFromAgent(ctx context.Context, agent AgentView) (E2EERecipientKey, error) {
	address := strings.TrimSpace(agent.Address)
	if address == "" {
		return E2EERecipientKey{}, fmt.Errorf("agent %s is global but has no address for AWID E2E key discovery; send by address or repair the roster entry", agent.Alias)
	}
	identity, err := c.ResolveIdentity(ctx, address)
	if err != nil {
		return E2EERecipientKey{}, fmt.Errorf("agent %s AWID E2E key discovery for %s failed: %w", agent.Alias, address, err)
	}
	if strings.TrimSpace(identity.StableID) != strings.TrimSpace(agent.DIDAW) {
		return E2EERecipientKey{}, fmt.Errorf("agent %s AWID key discovery stable id mismatch: roster has %s, address %s resolved to %s", agent.Alias, strings.TrimSpace(agent.DIDAW), address, strings.TrimSpace(identity.StableID))
	}
	if identity.EncryptionKey == nil {
		return E2EERecipientKey{}, fmt.Errorf("agent %s has no AWID-published E2E encryption key; ask them to upgrade aw/Pi/channel and publish one, or explicitly send a server-readable upgrade note with --plaintext", agent.Alias)
	}
	return E2EERecipientKey{
		Address:        strings.TrimSpace(identity.Address),
		DID:            strings.TrimSpace(identity.DID),
		StableID:       strings.TrimSpace(identity.StableID),
		EncryptionKey:  identity.EncryptionKey,
		DeliveryOrigin: strings.TrimSpace(identity.DeliveryOrigin),
		InboundMode:    strings.TrimSpace(agent.InboundMode),
	}, nil
}

func (c *Client) learnedE2EERecipientFromEnvelope(envelope *E2EEMessageEnvelope) (E2EERecipientKey, bool, error) {
	if envelope == nil {
		return E2EERecipientKey{}, false, nil
	}
	from := envelope.From
	if strings.TrimSpace(from.DID) == "" {
		return E2EERecipientKey{}, false, nil
	}
	for _, self := range []string{c.did, c.stableID, c.address} {
		self = strings.TrimSpace(self)
		if self == "" {
			continue
		}
		for _, candidate := range []string{from.DID, from.StableID, from.Address} {
			if strings.EqualFold(strings.TrimSpace(candidate), self) {
				return E2EERecipientKey{}, false, nil
			}
		}
	}
	if strings.TrimSpace(from.Address) != "" {
		return E2EERecipientKey{}, false, nil
	}
	if !strings.HasPrefix(strings.TrimSpace(from.DID), "did:key:") {
		return E2EERecipientKey{}, false, nil
	}
	recipient, err := E2EERecipientFromEnvelopeSender(envelope, time.Now().UTC())
	if err != nil {
		return E2EERecipientKey{}, true, fmt.Errorf("local-only E2E reply target %s cannot be used: %w", strings.TrimSpace(from.DID), err)
	}
	return recipient, true, nil
}

type ListAgentsResponse struct {
	TeamID string      `json:"team_id"`
	Agents []AgentView `json:"agents"`
}

// TeamRosterResolver resolves team-local identities only through the
// certificate-authenticated current roster on the connected aweb service.
type TeamRosterResolver struct {
	Client *Client
	TeamID string
}

func (r *TeamRosterResolver) Resolve(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	return r.resolve(ctx, identifier, false)
}

func (r *TeamRosterResolver) ResolveFresh(ctx context.Context, identifier string) (*ResolvedIdentity, error) {
	return r.resolve(ctx, identifier, true)
}

func (r *TeamRosterResolver) reference(identifier string) (teamID, alias string, ok bool) {
	configuredTeamID := strings.TrimSpace(r.TeamID)
	if teamID, alias, ok = splitTeamMemberReference(identifier); ok {
		return teamID, alias, teamID == configuredTeamID
	}
	domain, alias, ok := splitRegistryAddress(identifier)
	teamDomain, _, err := ParseTeamID(configuredTeamID)
	if !ok || err != nil || domain != teamDomain {
		return "", "", false
	}
	return configuredTeamID, alias, true
}

func (r *TeamRosterResolver) resolve(ctx context.Context, identifier string, forceRefresh bool) (*ResolvedIdentity, error) {
	teamID, alias, ok := r.reference(identifier)
	if !ok || r.Client == nil {
		return nil, fmt.Errorf("TeamRosterResolver: unsupported team member reference %q", identifier)
	}
	if strings.TrimSpace(r.Client.teamID) != teamID || strings.TrimSpace(r.Client.teamCertHeader) == "" || len(r.Client.signingKey) == 0 {
		return nil, errors.New("TeamRosterResolver: team-certificate authentication is required")
	}
	var out ListAgentsResponse
	headers := map[string]string(nil)
	if forceRefresh {
		headers = map[string]string{"Cache-Control": "no-cache"}
	}
	if err := r.Client.DoWithHeaders(ctx, "GET", "/v1/agents", nil, &out, headers); err != nil {
		return nil, err
	}
	if strings.TrimSpace(out.TeamID) != teamID {
		return nil, errors.New("TeamRosterResolver: roster response does not match the authenticated team")
	}
	for _, agent := range out.Agents {
		if strings.TrimSpace(agent.Alias) != alias {
			continue
		}
		did := strings.TrimSpace(agent.DIDKey)
		var publicKey ed25519.PublicKey
		if did != "" {
			raw, err := ExtractPublicKey(did)
			if err != nil {
				return nil, fmt.Errorf("TeamRosterResolver: invalid roster did:key: %w", err)
			}
			publicKey = ed25519.PublicKey(raw)
		}
		return &ResolvedIdentity{
			DID:           did,
			StableID:      strings.TrimSpace(agent.DIDAW),
			Address:       firstNonEmpty(strings.TrimSpace(agent.Address), identifier),
			Handle:        alias,
			PublicKey:     publicKey,
			Custody:       CustodySelf,
			IdentityScope: NormalizeIdentityScope(agent.IdentityScope),
			ResolvedAt:    time.Now().UTC(),
			ResolvedVia:   "team_roster",
		}, nil
	}
	return nil, &APIError{StatusCode: 404, Body: "local alias not found in authenticated team roster"}
}

type AgentInboundModeResponse struct {
	AgentID       string `json:"agent_id"`
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	IdentityScope string `json:"identity_scope"`
	InboundMode   string `json:"inbound_mode"`
	Configurable  bool   `json:"configurable"`
}

type UpdateAgentInboundModeRequest struct {
	InboundMode string `json:"inbound_mode"`
}

type PublishAgentEncryptionKeyResponse struct {
	AgentID       string                  `json:"agent_id"`
	TeamID        string                  `json:"team_id"`
	Alias         string                  `json:"alias"`
	EncryptionKey *EncryptionKeyAssertion `json:"encryption_key,omitempty"`
}

// Heartbeat reports agent liveness to the aweb server.
func (c *Client) Heartbeat(ctx context.Context) (*HeartbeatResponse, error) {
	var out HeartbeatResponse
	if err := c.Post(ctx, "/v1/agents/heartbeat", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListAgents lists agents visible in the authenticated team.
func (c *Client) ListAgents(ctx context.Context) (*ListAgentsResponse, error) {
	var out ListAgentsResponse
	if err := c.Get(ctx, "/v1/agents", &out); err != nil {
		return nil, err
	}
	for _, agent := range out.Agents {
		if agent.EncryptionKey == nil {
			continue
		}
		if err := agent.VerifyEncryptionKey(time.Now().UTC()); err != nil {
			return nil, fmt.Errorf("ListAgents: invalid encryption key assertion for %s: %w", agent.Alias, err)
		}
	}
	return &out, nil
}

func (c *Client) GetMyInboundMode(ctx context.Context) (*AgentInboundModeResponse, error) {
	var out AgentInboundModeResponse
	if err := c.Get(ctx, "/v1/agents/me/inbound-mode", &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) UpdateMyInboundMode(ctx context.Context, mode string) (*AgentInboundModeResponse, error) {
	var out AgentInboundModeResponse
	req := UpdateAgentInboundModeRequest{InboundMode: strings.TrimSpace(mode)}
	if err := c.Patch(ctx, "/v1/agents/me/inbound-mode", req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) PublishMyEncryptionKey(ctx context.Context, assertion *EncryptionKeyAssertion) (*PublishAgentEncryptionKeyResponse, error) {
	var out PublishAgentEncryptionKeyResponse
	if err := c.Put(ctx, "/v1/agents/me/encryption-key", assertion, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
