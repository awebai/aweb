package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// createControllerTeamInvite binds the local bearer to the issuer's saved
// lifetime and routing (docs/identity.md). The token contains no expiry authority.
func createControllerTeamInvite(request teamInviteMintRequest) (mintedTeamInvite, error) {
	if err := validateInviteMemberScope(request.Scope); err != nil {
		return mintedTeamInvite{}, err
	}
	source := request.Plan.Source
	domain := awconfig.NormalizeDomain(source.Domain)
	team := strings.ToLower(strings.TrimSpace(source.Team))
	registryURL := strings.TrimSpace(source.RegistryURL)
	if domain == "" {
		return mintedTeamInvite{}, fmt.Errorf("domain is required")
	}
	if team == "" {
		return mintedTeamInvite{}, fmt.Errorf("team is required")
	}

	exists, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return mintedTeamInvite{}, err
	}
	if !exists {
		return mintedTeamInvite{}, withErrorCode(codeControllerKeyMissing, usageError("no team key for %s/%s; run `aw id team create` first", domain, team))
	}

	requested := request.ForHuman
	if requested != nil {
		if err := validateInviteHuman(*requested); err != nil {
			return mintedTeamInvite{}, err
		}
	}
	lifetime, err := resolveControllerInviteLifetime(awconfig.TeamInviteLifetimeRequest{Now: time.Now(), Duration: request.ExpiresAfter})
	if err != nil {
		return mintedTeamInvite{}, err
	}
	childPolicy := inviteMembershipOnly
	if request.Scope == inviteMemberLocal {
		childPolicy = inviteCreatesChild
	}
	link, issuerHuman, err := prepareTeamInviteAuthority(context.Background(), teamInviteAuthorityRequest{
		Issuer: idChildOptions{WorkingDir: source.WorkingDir, IdentityHome: source.Home.Root, TeamRegistryURL: registryURL, TeamRegistryDomain: domain, Now: time.Now},
		Child:  childPolicy, ForHuman: requested, ExpiresAt: lifetime.ExpiresAt,
	})
	if err != nil {
		return mintedTeamInvite{}, err
	}
	required := issuerHuman
	if requested != nil {
		required = requested
	}
	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		return mintedTeamInvite{}, err
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		return mintedTeamInvite{}, err
	}
	identityScope := awid.IdentityModeGlobal
	if request.Scope == inviteMemberLocal {
		identityScope = awid.IdentityModeLocal
	}
	invite := &awconfig.TeamInvite{
		ForHuman:      required,
		InviteID:      inviteID,
		Domain:        domain,
		TeamName:      team,
		IdentityScope: identityScope,
		Secret:        secret,
		RegistryURL:   registryURL,
		AwebURL:       source.AwebURL,
		CreatedAt:     lifetime.CreatedAt.Format(time.RFC3339Nano),
		ExpiresAt:     lifetime.ExpiresAt.Format(time.RFC3339Nano),
	}
	invite.IDChild = link
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		return mintedTeamInvite{}, err
	}
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		return mintedTeamInvite{}, err
	}
	return mintedTeamInvite{InviteID: inviteID, Token: token, ExpiresAt: invite.ExpiresAt, ForHuman: required}, nil
}

// The awconfig owner decides duration; this boundary supplies its CLI remedy.
func resolveControllerInviteLifetime(input awconfig.TeamInviteLifetimeRequest) (awconfig.TeamInviteLifetime, error) {
	lifetime, err := awconfig.ResolveTeamInviteLifetime(input)
	if err != nil {
		return lifetime, fmt.Errorf("%w; use --expires between 0 and %s (0 selects %s), then retry", err, awconfig.MaximumTeamInviteLifetime, awconfig.DefaultTeamInviteLifetime)
	}
	return lifetime, nil
}
