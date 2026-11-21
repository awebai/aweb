package main

import (
	"context"
	"crypto/ed25519"
	"errors"
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
	Scope         awid.IdentityScope
}

func bootstrapLocalTeamMember(ctx context.Context, input localTeamMemberBootstrap) (*localTeamBootstrapResult, error) {
	if len(input.MemberKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("member signing key is malformed")
	}
	return bootstrapTeamMembership(ctx, teamMembershipBootstrap{
		Registry: input.Registry, RegistryURL: input.RegistryURL, Domain: input.Domain,
		TeamName: input.TeamName, DisplayName: input.DisplayName, ControllerKey: input.ControllerKey,
		Member: awid.TeamCertificateFields{
			MemberDIDKey: awid.ComputeDIDKey(input.MemberKey.Public().(ed25519.PublicKey)),
			MemberDIDAW:  strings.TrimSpace(input.MemberDIDAW), MemberAddress: strings.TrimSpace(input.MemberAddress),
			Alias: strings.TrimSpace(input.Alias), IdentityScope: string(input.Scope),
		},
		NameFlag: "--name",
	})
}

type teamMembershipBootstrap struct {
	Registry      *awid.RegistryClient
	RegistryURL   string
	Domain        string
	TeamName      string
	DisplayName   string
	ControllerKey ed25519.PrivateKey
	Member        awid.TeamCertificateFields
	NameFlag      string
}

func bootstrapTeamMembership(ctx context.Context, input teamMembershipBootstrap) (*localTeamBootstrapResult, error) {
	if len(input.ControllerKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("controller signing key is malformed")
	}
	registryURL := strings.TrimSpace(input.RegistryURL)
	if registryURL == "" && input.Registry != nil {
		registryURL = strings.TrimSpace(input.Registry.DefaultRegistryURL)
	}
	if input.Member.IdentityScope != awid.IdentityModeLocal && input.Member.IdentityScope != awid.IdentityModeGlobal {
		return nil, fmt.Errorf("identity scope must be local or global")
	}
	registration, err := ensureLocalTeamRegistered(ctx, input.Registry, registryURL, input.Domain, input.TeamName, input.DisplayName, input.ControllerKey)
	if err != nil {
		return nil, err
	}
	issuer := teamMembershipIssuer{TeamID: registration.TeamID, Key: registration.TeamKey, Registry: input.Registry, RegistryURL: registryURL}
	cert, err := issuer.issue(ctx, input.Member)
	if err != nil {
		var refused *teamMembershipRegistrationError
		if errors.As(err, &refused) {
			if isAliasConflict(refused.cause) {
				return nil, &plainRefusal{text: nameTakenText(input.Member.Alias, registration.TeamID, input.NameFlag), err: refused.cause}
			}
			return nil, fmt.Errorf("register certificate at registry: %w", refused.cause)
		}
		return nil, err
	}
	return &localTeamBootstrapResult{
		TeamID:      registration.TeamID,
		TeamDIDKey:  registration.TeamDIDKey,
		TeamKeyPath: registration.TeamKeyPath,
		Certificate: cert,
	}, nil
}
