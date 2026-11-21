package awid

import (
	"context"
	"fmt"
	"strings"
	"time"
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
		scoped.inheritRegistryPolicy(r)
		r.receivedRegistries[registryURL] = scoped
	}
	return registryURL, scoped, nil
}

// ReceivedSender is what a received message says about its sender, as trust
// normalisation reads it.
type ReceivedSender struct {
	// Address is the sender's address; Alias names it when there is none.
	Address     string
	Alias       string
	DID         string
	StableID    string
	Membership  *SenderMembership
	Rotation    *RotationAnnouncement
	Replacement *ReplacementAnnouncement
	IsContact   *bool
	// Binding is the delivery server's projection of the sender for a
	// received read; nil when the read carries none.
	Binding *ReceivedSenderBinding
}

// NormalizeReceivedSenderTrust is the released form of
// NormalizeReceivedSender (aw-v1.36.58), kept for Go callers of this public
// package: binding, when given, is the receiver-side sender binding.
func (c *Client) NormalizeReceivedSenderTrust(ctx context.Context, status VerificationStatus, address, alias, did, stableID string, membership *SenderMembership, ra *RotationAnnouncement, repl *ReplacementAnnouncement, contact *bool, binding ...ReceivedSenderBinding) (VerificationStatus, *bool) {
	sender := ReceivedSender{Address: address, Alias: alias, DID: did, StableID: stableID, Membership: membership,
		Rotation: ra, Replacement: repl, IsContact: contact}
	if len(binding) > 0 {
		sender.Binding = &binding[0]
	}
	return c.NormalizeReceivedSender(ctx, status, sender)
}

// NormalizeReceivedSender keeps display labels out of cross-team local
// and no-address global verification. It cannot promote a failed signature or recipient mismatch.
func (c *Client) NormalizeReceivedSender(ctx context.Context, status VerificationStatus, sender ReceivedSender) (VerificationStatus, *bool) {
	return checkedAsVerified(status, func(status VerificationStatus) (VerificationStatus, *bool) {
		return c.normalizeReceivedSender(ctx, status, sender)
	})
}

// checkedAsVerified runs a sender's trust checks for a legacy-format
// signature exactly as for a current one. VerifiedLegacy names the signed
// envelope's format (it has no conversation claim), not a trust result, so
// the message keeps it only when the checks pass; a failed check gives the
// same outcome as for a current-format message.
func checkedAsVerified(status VerificationStatus, check func(VerificationStatus) (VerificationStatus, *bool)) (VerificationStatus, *bool) {
	if status != VerifiedLegacy {
		return check(status)
	}
	checked, contact := check(Verified)
	if checked == Verified {
		checked = VerifiedLegacy
	}
	return checked, contact
}

func (c *Client) normalizeReceivedSender(ctx context.Context, status VerificationStatus, sender ReceivedSender) (VerificationStatus, *bool) {
	address, alias, did, stableID := sender.Address, sender.Alias, sender.DID, sender.StableID
	membership := sender.Membership
	if sender.Binding != nil && strings.TrimSpace(stableID) == "" {
		if localStatus, handled := c.receivedLocalSenderTrust(status, address, did, membership, *sender.Binding); handled {
			return localStatus, nil
		}
	}
	if strings.TrimSpace(address) != "" || !strings.HasPrefix(strings.TrimSpace(stableID), "did:aw:") {
		reference := address
		if reference == "" {
			reference = alias
		}
		return c.normalizeSenderTrust(ctx, status, reference, did, stableID, sender.Rotation, sender.Replacement, sender.IsContact)
	}
	if !status.Trusted() {
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
	checkpoint, err := c.identityCheckpoint(registryURL, stableID)
	if err != nil {
		return VerificationStale, nil
	}
	registry.SeedVerifiedHeadAt(registryURL, stableID, checkpoint)
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
		if err := c.saveIdentityCheckpoint(identityCheckpointWrite{RegistryURL: registryURL, StableID: stableID, Head: result.VerifiedHead}); err != nil {
			return VerificationStale, nil
		}
		return Verified, nil
	default:
		return VerificationStale, nil
	}
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
	if !status.Trusted() {
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
	// The server's membership attestation never deletes a pin (Antares
	// 2e8881d7): a team-scoped name's previous holder is retired with its
	// anchor, and a pin at a real address is left untouched.
	c.releaseTeamNamePin(address, address)
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

// ReceivedAddressIDTreeEnrollment reads enrollment at the addressed sender's
// registry after ordinary sender verification. The address selects the key
// registry; only its fresh, subject-bound key response selects an ID domain.
func (c *Client) ReceivedAddressIDTreeEnrollment(ctx context.Context, address, stableID, didKey string) IDTreeEnrollmentResult {
	unknown := IDTreeEnrollmentResult{State: "unknown"}
	chain, ok := c.resolver.(*ChainResolver)
	if !ok || chain.Registry == nil {
		return unknown
	}
	domain, name, ok := splitRegistryAddress(address)
	if !ok {
		return unknown
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	registry := chain.Registry
	resolved, err := registry.resolveAddress(ctx, domain, name)
	if err != nil || resolved.response.DIDAW != stableID {
		return unknown
	}
	reader := NewAWIDRegistryClient(registry.HTTPClient, registry.DNSResolver)
	reader.Now = registry.Now
	reader.Resolver.inheritRegistryPolicy(registry)
	key, err := reader.ResolveKeyAt(ctx, resolved.authority.RegistryURL, stableID)
	if err != nil {
		return unknown
	}
	return key.IDTreeEnrollmentOf(stableID, didKey, registry.now())
}
