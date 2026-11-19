package main

import (
	"context"
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"strings"
	"time"
)

func createTeamInviteTokenAt(domain, team, registryURL, awebURL string, local bool, operationID, workingDir, identityHome string, forHuman ...string) (string, string, error) {
	domain = awconfig.NormalizeDomain(domain)
	team = strings.ToLower(strings.TrimSpace(team))
	registryURL = strings.TrimSpace(registryURL)
	if domain == "" {
		return "", "", fmt.Errorf("domain is required")
	}
	if team == "" {
		return "", "", fmt.Errorf("team is required")
	}

	exists, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return "", "", err
	}
	if !exists {
		return "", "", withErrorCode(codeControllerKeyMissing, usageError("no team key for %s/%s; run `aw id team create` first", domain, team))
	}

	requested, err := requestedInviteHuman(forHuman)
	if err != nil {
		return "", "", err
	}
	link, issuerHuman, err := prepareTeamInviteAuthority(context.Background(), idChildOptions{WorkingDir: workingDir, IdentityHome: identityHome, TeamRegistryURL: registryURL, TeamRegistryDomain: domain, Now: time.Now}, local, requested)
	if err != nil {
		return "", "", err
	}
	required := issuerHuman
	if requested != nil {
		required = requested
	}
	inviteID, err := awid.GenerateUUID4()
	if err != nil {
		return "", "", err
	}
	secret, err := awconfig.GenerateInviteSecret()
	if err != nil {
		return "", "", err
	}
	identityScope := awid.IdentityModeGlobal
	if local {
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
		AwebURL:       awebURL,
		OperationID:   operationID,
		CreatedAt:     time.Now().UTC().Format(time.RFC3339),
	}
	invite.IDChild = link
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		return "", "", err
	}
	token, err := awconfig.EncodeInviteToken(invite)
	if err != nil {
		return "", "", err
	}
	return inviteID, token, nil
}
