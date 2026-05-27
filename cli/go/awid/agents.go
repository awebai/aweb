package awid

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// HeartbeatResponse is returned by POST /v1/agents/heartbeat.
type HeartbeatResponse struct {
	AgentID    string `json:"agent_id"`
	Alias      string `json:"alias"`
	LastSeenAt string `json:"last_seen_at"`
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
	Lifetime      string                  `json:"lifetime,omitempty"`
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
