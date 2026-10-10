package awid

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// SenderMembership is delivery-server attestation, not a signed-envelope claim.
// Only participant-authorized reads supply it, using the stored sender and team.
type SenderMembership struct {
	TeamID      string `json:"team_id"`
	MemberDIDAW string `json:"member_did_aw"`
	State       string `json:"state"`
}

// receivedRegistry isolates key/log caches by the delivery team's registry.
// The caller's authenticated team selects authority; no message hint or alias
// is an input to registry discovery.
func (r *RegistryResolver) receivedRegistry(ctx context.Context, teamID string) (string, *RegistryResolver, error) {
	domain, _, err := ParseTeamID(teamID)
	if err != nil {
		return "", nil, err
	}
	authority, err := r.discoverAuthority(ctx, domain)
	if err != nil {
		return "", nil, err
	}
	registryURL := strings.TrimRight(authority.RegistryURL, "/")
	if registryURL == "" {
		return "", nil, fmt.Errorf("delivery team registry unavailable")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.receivedRegistries == nil {
		r.receivedRegistries = make(map[string]*RegistryResolver)
	}
	scoped := r.receivedRegistries[registryURL]
	if scoped == nil {
		scoped = NewRegistryResolver(r.HTTPClient, r.DNSResolver)
		scoped.Now = r.Now
		r.receivedRegistries[registryURL] = scoped
	}
	return registryURL, scoped, nil
}

// NormalizeReceivedSenderTrust keeps display aliases out of no-address global
// verification. It cannot promote a failed signature or recipient mismatch.
func (c *Client) NormalizeReceivedSenderTrust(ctx context.Context, status VerificationStatus, address, alias, did, stableID string, membership *SenderMembership, ra *RotationAnnouncement, repl *ReplacementAnnouncement, contact *bool) (VerificationStatus, *bool) {
	if strings.TrimSpace(address) != "" || !strings.HasPrefix(strings.TrimSpace(stableID), "did:aw:") {
		reference := address
		if reference == "" {
			reference = alias
		}
		return c.NormalizeSenderTrust(ctx, status, reference, did, stableID, ra, repl, contact)
	}
	if status != Verified && status != VerifiedLegacy && status != VerifiedCustodial {
		return status, nil
	}
	if membership == nil || membership.State == "unknown" {
		return VerificationStale, nil
	}
	chain, ok := c.resolver.(*ChainResolver)
	if !ok || chain.Registry == nil || chain.Team == nil {
		return VerificationStale, nil
	}
	// Team is configured from the selected authenticated membership, while
	// identity-only HTTP clients intentionally leave c.teamID empty.
	teamID := strings.TrimSpace(chain.Team.TeamID)
	if membership.State != "active" || teamID == "" || membership.TeamID != teamID || membership.MemberDIDAW != stableID {
		return IdentityMismatch, nil
	}
	registryURL, registry, err := chain.Registry.receivedRegistry(ctx, teamID)
	if err != nil {
		return VerificationStale, nil
	}
	checkpoint, err := c.receivedCheckpoint(registryURL, stableID)
	if err != nil {
		return VerificationStale, nil
	}
	registry.SeedVerifiedHead(stableID, checkpoint)
	result := registry.verifyStableIdentityAtRegistry(ctx, registryURL, stableID, did)
	if result == nil {
		return VerificationStale, nil
	}
	switch result.Outcome {
	case StableIdentityHardError:
		return IdentityMismatch, nil
	case StableIdentityVerified:
		if result.CurrentDIDKey != did {
			return IdentityMismatch, nil
		}
		if result.VerifiedHead == nil {
			return VerificationStale, nil
		}
		if err := c.saveReceivedCheckpoint(registryURL, stableID, result.VerifiedHead); err != nil {
			return VerificationStale, nil
		}
		return Verified, nil
	default:
		return VerificationStale, nil
	}
}

// Stored in the pin store's forward-compatible root metadata, never as an
// address pin. Older clients preserve these checkpoints without inventing an
// address for this identity. Both levels are authority-scoped.
const receivedHeadsField = "received_identity_heads"

func (c *Client) receivedCheckpoint(registryURL, stableID string) (*VerifiedLogHead, error) {
	if c.pinStore == nil {
		return nil, nil
	}
	c.pinStore.mu.Lock()
	defer c.pinStore.mu.Unlock()
	if c.pinStore.undurable.Load() {
		return nil, fmt.Errorf("trust store is not durable")
	}
	raw, ok := c.pinStore.unknown[receivedHeadsField]
	if !ok {
		return nil, nil
	}
	data, err := json.Marshal(raw)
	if err != nil {
		return nil, err
	}
	var heads map[string]map[string]*VerifiedLogHead
	if err := json.Unmarshal(data, &heads); err != nil {
		return nil, err
	}
	head, ok := heads[registryURL][stableID]
	if !ok {
		return nil, nil
	}
	if head == nil || head.Seq < 1 || head.EntryHash == "" || head.CurrentDIDKey == "" {
		return nil, fmt.Errorf("invalid received identity checkpoint")
	}
	return head, nil
}

func (c *Client) saveReceivedCheckpoint(registryURL, stableID string, head *VerifiedLogHead) error {
	if c.pinStore == nil {
		return nil
	}
	c.pinStore.mu.Lock()
	if c.pinStore.unknown == nil {
		c.pinStore.unknown = make(map[string]any)
	}
	heads := map[string]map[string]*VerifiedLogHead{}
	if raw, ok := c.pinStore.unknown[receivedHeadsField]; ok {
		data, err := json.Marshal(raw)
		if err != nil {
			c.pinStore.mu.Unlock()
			return err
		}
		if err := json.Unmarshal(data, &heads); err != nil {
			c.pinStore.mu.Unlock()
			return err
		}
	}
	if heads[registryURL] == nil {
		heads[registryURL] = map[string]*VerifiedLogHead{}
	}
	old := heads[registryURL][stableID]
	if old != nil && old.Seq > head.Seq {
		c.pinStore.mu.Unlock()
		return fmt.Errorf("received identity checkpoint rollback")
	}
	if old != nil && old.Seq == head.Seq && old.EntryHash != head.EntryHash {
		c.pinStore.mu.Unlock()
		return fmt.Errorf("received identity checkpoint fork")
	}
	heads[registryURL][stableID] = head
	// Plain values are required by the pin store's unknown-field serializer.
	data, err := json.Marshal(heads)
	if err != nil {
		c.pinStore.mu.Unlock()
		return err
	}
	var plain map[string]any
	err = json.Unmarshal(data, &plain)
	if err == nil {
		c.pinStore.unknown[receivedHeadsField] = plain
	}
	c.pinStore.mu.Unlock()
	if err != nil {
		return err
	}
	return c.savePinStore()
}
