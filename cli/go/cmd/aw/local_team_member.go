package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"strings"
)

func bootstrapFirstLocalTeamMember(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, teamName, displayName string,
	controllerKey, memberKey ed25519.PrivateKey,
	memberDIDAW, memberAddress, alias string,
) (*localTeamBootstrapResult, error) {
	return bootstrapLocalTeamMemberWithScope(
		ctx,
		registry,
		registryURL,
		domain,
		teamName,
		displayName,
		controllerKey,
		memberKey,
		memberDIDAW,
		memberAddress,
		alias,
		awid.IdentityModeGlobal,
	)
}

func bootstrapLocalTeamMemberWithScope(
	ctx context.Context,
	registry *awid.RegistryClient,
	registryURL, domain, teamName, displayName string,
	controllerKey, memberKey ed25519.PrivateKey,
	memberDIDAW, memberAddress, alias, identityScope string,
) (*localTeamBootstrapResult, error) {
	if memberKey == nil {
		return nil, fmt.Errorf("member signing key is required")
	}
	resolvedRegistryURL := strings.TrimSpace(registryURL)
	if resolvedRegistryURL == "" && registry != nil {
		resolvedRegistryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	identityScope = awid.NormalizeIdentityScope(identityScope)
	if identityScope != awid.IdentityModeLocal && identityScope != awid.IdentityModeGlobal {
		return nil, fmt.Errorf("identity scope must be local or global")
	}
	registration, err := ensureLocalTeamRegistered(ctx, registry, resolvedRegistryURL, domain, teamName, displayName, controllerKey)
	if err != nil {
		return nil, err
	}
	memberDIDKey := awid.ComputeDIDKey(memberKey.Public().(ed25519.PublicKey))
	cert, err := awid.SignTeamCertificate(registration.TeamKey, awid.TeamCertificateFields{
		Team:          registration.TeamID,
		MemberDIDKey:  memberDIDKey,
		MemberDIDAW:   strings.TrimSpace(memberDIDAW),
		MemberAddress: strings.TrimSpace(memberAddress),
		Alias:         strings.TrimSpace(alias),
		IdentityScope: identityScope,
	})
	if err != nil {
		return nil, err
	}
	if err := registry.RegisterCertificate(ctx, resolvedRegistryURL, awconfig.NormalizeDomain(domain), strings.ToLower(strings.TrimSpace(teamName)), cert, registration.TeamKey); err != nil {
		if isAliasConflict(err) {
			// aw init's local and guided paths call this, and --name sets
			// their name.
			return nil, &plainRefusal{text: nameTakenText(strings.TrimSpace(alias), registration.TeamID, "--name"), err: err}
		}
		return nil, fmt.Errorf("register certificate at registry: %w", err)
	}
	return &localTeamBootstrapResult{
		TeamID:      registration.TeamID,
		TeamDIDKey:  registration.TeamDIDKey,
		TeamKeyPath: registration.TeamKeyPath,
		Certificate: cert,
	}, nil
}
