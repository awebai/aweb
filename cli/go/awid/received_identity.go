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

// NormalizeReceivedSenderTrust keeps display labels out of cross-team local
// and no-address global verification. It cannot promote a failed signature or recipient mismatch.
func (c *Client) NormalizeReceivedSenderTrust(ctx context.Context, status VerificationStatus, address, alias, did, stableID string, membership *SenderMembership, ra *RotationAnnouncement, repl *ReplacementAnnouncement, contact *bool, binding ...ReceivedSenderBinding) (VerificationStatus, *bool) {
	if len(binding) > 0 && strings.TrimSpace(stableID) == "" {
		if localStatus, handled := c.receivedLocalSenderTrust(status, address, did, membership, binding[0]); handled {
			return localStatus, nil
		}
	}
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
	if !ok || chain.DeliveryTeamRegistry == nil || chain.Team == nil {
		return VerificationStale, nil
	}
	// Team is configured from the selected authenticated membership, while
	// identity-only HTTP clients intentionally leave c.teamID empty.
	teamID := strings.TrimSpace(chain.Team.TeamID)
	if membership.State != "active" || membership.MemberDIDAW != stableID {
		return IdentityMismatch, nil
	}
	if teamID == "" || membership.TeamID != teamID {
		return VerificationStale, nil
	}
	registryURL, registry, err := chain.DeliveryTeamRegistry.receivedRegistry(ctx, teamID)
	if err != nil {
		return VerificationStale, nil
	}
	checkpoint, err := c.receivedCheckpoint(registryURL, stableID)
	if err != nil {
		return VerificationStale, nil
	}
	registry.SeedVerifiedHead(stableID, checkpoint)
	result := registry.verifyStableIdentityAtRegistry(ctx, registryURL, stableID, did, true)
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
	if heads == nil {
		return nil, fmt.Errorf("invalid received identity checkpoints")
	}
	head, ok := heads[registryURL][stableID]
	if !ok {
		return nil, nil
	}
	if head == nil || head.Seq < 1 || len(head.EntryHash) != 64 || !isLowerHex(head.EntryHash) || head.CurrentDIDKey == "" {
		return nil, fmt.Errorf("invalid received identity checkpoint")
	}
	if _, err := ExtractPublicKey(head.CurrentDIDKey); err != nil {
		return nil, err
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
	if heads == nil {
		c.pinStore.mu.Unlock()
		return fmt.Errorf("invalid received identity checkpoints")
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
	err = c.savePinStore()
	if err != nil {
		c.pinStore.undurable.Store(true)
	}
	return err
}

// ReceivedSenderBinding keeps the participant-authorized projection separate
// from the sender's signed claims during read normalization.
type ReceivedSenderBinding struct {
	ProjectedDID string
	TeamID       string
}

func (c *Client) receivedLocalSenderTrust(status VerificationStatus, address, did string, member *SenderMembership, binding ReceivedSenderBinding) (VerificationStatus, bool) {
	chain, ok := c.resolver.(*ChainResolver)
	if !ok || chain.Team == nil || chain.Team.TeamID == "" {
		return status, false
	}
	selected := chain.Team.TeamID
	namespace := func(team string) string {
		domain, _, err := ParseTeamID(team)
		if err != nil {
			return ""
		}
		return domain
	}
	addressNamespace := ""
	if before, _, found := strings.Cut(strings.TrimSpace(address), "/"); found {
		addressNamespace = before
	}
	referenceMatches := func(team string) bool { return addressNamespace == team || addressNamespace == namespace(team) }
	crossTeam := (member != nil && member.TeamID != "" && member.TeamID != selected) ||
		(binding.TeamID != "" && binding.TeamID != selected) ||
		(addressNamespace != "" && !referenceMatches(selected))
	if !crossTeam {
		return status, false
	}
	if status != Verified && status != VerifiedLegacy && status != VerifiedCustodial {
		return status, true
	}
	if member == nil {
		return VerificationStale, true
	}
	if member.MemberDIDAW != "" || member.State == "inactive" ||
		(binding.TeamID != "" && member.TeamID != "" && binding.TeamID != member.TeamID) ||
		(addressNamespace != "" && member.TeamID != "" && !referenceMatches(member.TeamID)) ||
		(binding.ProjectedDID != "" && binding.ProjectedDID != did) {
		return IdentityMismatch, true
	}
	if member.State != "active" || namespace(member.TeamID) == "" || binding.ProjectedDID == "" || did == "" {
		return VerificationStale, true
	}
	if _, err := ExtractPublicKey(did); err != nil {
		return IdentityMismatch, true
	}
	if c.pinStore != nil && strings.Contains(address, "/") {
		c.pinStore.mu.Lock()
		removed := c.pinStore.RemoveAddress(address)
		c.pinStore.mu.Unlock()
		if removed {
			if err := c.savePinStore(); err != nil {
				return VerificationStale, true
			}
		}
	}
	return Verified, true
}

// ReceivedIDTreeEnrollment reuses the selected delivery registry's coherent
// key snapshot after ordinary sender verification, without inventing an address.
func (c *Client) ReceivedIDTreeEnrollment(ctx context.Context, stableID, didKey string) IDTreeEnrollmentResult {
	unknown := IDTreeEnrollmentResult{State: "unknown"}
	chain, ok := c.resolver.(*ChainResolver)
	if !ok || chain.Team == nil || chain.DeliveryTeamRegistry == nil {
		return unknown
	}
	_, registry, err := chain.DeliveryTeamRegistry.receivedRegistry(ctx, chain.Team.TeamID)
	if err != nil {
		return unknown
	}
	key, ok := registry.loadKeyCache(stableID)
	if !ok {
		return unknown
	}
	return key.IDTreeEnrollmentOf(stableID, didKey, registry.now())
}
