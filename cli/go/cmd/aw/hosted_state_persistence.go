package main

import (
	"crypto/ed25519"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type hostedIdentityScope uint8

const (
	localHostedIdentity hostedIdentityScope = iota + 1
	globalHostedIdentity
)

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

func persistHostedIdentityState(request hostedStatePersistence) error {
	return persistGuidedHostedState(request.WorkingDir, request.RegistryURL, request.SigningKey, request.Certificate, request.DIDKey, request.DIDAW, request.MemberAddress, request.Scope == globalHostedIdentity, request.IdentityHome.Root)
}
