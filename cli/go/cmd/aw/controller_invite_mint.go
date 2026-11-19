package main

import (
	"context"
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"strings"
	"time"
)

// createControllerTeamInvite binds the local bearer to the issuer's saved
// lifetime and routing (docs/identity.md). The token contains no expiry authority.
func createControllerTeamInvite(request teamInviteMintRequest) (mintedTeamInvite, error) {
	if err := request.Scope.validate(); err != nil {
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
	lifetime, err := awconfig.ResolveTeamInviteLifetime(awconfig.TeamInviteLifetimeRequest{Now: time.Now(), Duration: request.ExpiresAfter})
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

func createTeamInviteTokenAt(domain, team, registryURL, awebURL string, local bool, workingDir, identityHome string, forHuman ...string) (string, string, error) {
	requested, err := requestedInviteHuman(forHuman)
	if err != nil {
		return "", "", err
	}
	home, err := identityHomeForTarget(workingDir, identityHome)
	if err != nil {
		return "", "", err
	}
	scope := inviteMemberGlobal
	if local {
		scope = inviteMemberLocal
	}
	created, err := createControllerTeamInvite(teamInviteMintRequest{Plan: teamInvitePlan{Kind: inviteAuthorityController, Source: teamInviteSource{
		WorkingDir: workingDir, Home: home, Domain: domain, Team: team, RegistryURL: registryURL, AwebURL: awebURL,
	}}, Scope: scope, ForHuman: requested})
	if err != nil {
		return "", "", err
	}
	return created.InviteID, created.Token, nil
}
