package main

import (
	"crypto/ed25519"
	"errors"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type hostedIdentityScope uint8

const (
	localHostedIdentity hostedIdentityScope = iota + 1
	globalHostedIdentity
)

type hostedRegistryStatus string

const registeredHostedIdentity hostedRegistryStatus = "registered"

type hostedStatePersistence struct {
	WorkingDir    string
	IdentityHome  awconfig.IdentityHome
	RegistryURL   string
	SigningKey    ed25519.PrivateKey
	Certificate   *awid.TeamCertificate
	DIDKey        string
	DIDAW         string
	MemberAddress string
	Scope         hostedIdentityScope
}

// persistHostedIdentityState implements docs/cli-identity-selection.md:23-27.
// Creation and membership callers supply their destination explicitly; writing
// credentials never falls back to the checkout when that destination is absent.
func persistHostedIdentityState(request hostedStatePersistence) error {
	if strings.TrimSpace(request.IdentityHome.Root) == "" {
		return errors.New("identity home is required. Select an identity home and retry")
	}
	if request.Scope != localHostedIdentity && request.Scope != globalHostedIdentity {
		return errors.New("identity scope is required. Select local or global identity scope and retry")
	}
	if err := persistLocalSigningKeyAndCertificateAt(request.WorkingDir, request.IdentityHome.Root, request.SigningKey, request.Certificate); err != nil {
		return err
	}
	if request.Scope == localHostedIdentity {
		return nil
	}
	path, err := awconfig.IdentityHomePath(request.IdentityHome, "identity.yaml")
	if err != nil {
		return err
	}
	return awconfig.SaveWorktreeIdentityTo(path, &awconfig.WorktreeIdentity{
		DID:            request.DIDKey,
		StableID:       request.DIDAW,
		Address:        request.MemberAddress,
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryURL:    strings.TrimSpace(request.RegistryURL),
		RegistryStatus: string(registeredHostedIdentity),
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	})
}
