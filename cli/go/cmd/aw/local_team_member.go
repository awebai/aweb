package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"strings"

	"github.com/awebai/aw/awid"
)

// localTeamMemberBootstrap names the controller and member independently.
// Namespace/team registration is controller-authorized; the signed certificate
// grants only the requested membership (docs/identity.md#team-membership-and-authentication).
type localTeamMemberBootstrap struct {
	Registry      *awid.RegistryClient
	RegistryURL   string
	Domain        string
	TeamName      string
	DisplayName   string
	ControllerKey ed25519.PrivateKey
	MemberKey     ed25519.PrivateKey
	MemberDIDAW   string
	MemberAddress string
	Alias         string
	NameFlag      string
	Scope         awid.IdentityScope
}

func bootstrapLocalTeamMember(ctx context.Context, input localTeamMemberBootstrap) (*localTeamBootstrapResult, error) {
	registry, registryURL := input.Registry, input.RegistryURL
	domain, teamName, displayName := input.Domain, input.TeamName, input.DisplayName
	controllerKey, memberKey := input.ControllerKey, input.MemberKey
	memberDIDAW, memberAddress, alias := input.MemberDIDAW, input.MemberAddress, input.Alias
	if len(memberKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("member signing key is malformed")
	}
	if len(controllerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("controller signing key is malformed")
	}
	resolvedRegistryURL := strings.TrimSpace(registryURL)
	if resolvedRegistryURL == "" && registry != nil {
		resolvedRegistryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	if input.Scope != awid.IdentityScopeLocal && input.Scope != awid.IdentityScopeGlobal {
		return nil, fmt.Errorf("identity scope must be local or global")
	}
	registration, err := ensureLocalTeamRegistered(ctx, registry, resolvedRegistryURL, domain, teamName, displayName, controllerKey)
	if err != nil {
		return nil, err
	}
	memberDIDKey := awid.ComputeDIDKey(memberKey.Public().(ed25519.PublicKey))
	issuer := teamMembershipIssuer{TeamID: registration.TeamID, Key: registration.TeamKey, Registry: registry, RegistryURL: resolvedRegistryURL}
	cert, err := issuer.sign(awid.TeamCertificateFields{
		MemberDIDKey:  memberDIDKey,
		MemberDIDAW:   strings.TrimSpace(memberDIDAW),
		MemberAddress: strings.TrimSpace(memberAddress),
		Alias:         strings.TrimSpace(alias),
		IdentityScope: string(input.Scope),
	})
	if err != nil {
		return nil, err
	}
	if err := issuer.register(ctx, cert); err != nil {
		if isAliasConflict(err) {
			return nil, &plainRefusal{text: nameTakenText(strings.TrimSpace(alias), registration.TeamID, firstNonEmpty(input.NameFlag, "--name")), err: err}
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
