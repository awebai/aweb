package main

import (
	"context"
	"crypto/ed25519"
	"fmt"

	"github.com/awebai/aw/awid"
)

// teamMembershipIssuer binds signing and registration to the same controller
// and team. Callers can retain the signed certificate before registration or
// include it in an atomic key rotation.
type teamMembershipIssuer struct {
	TeamID      string
	Key         ed25519.PrivateKey
	Registry    *awid.RegistryClient
	RegistryURL string
}

func (issuer teamMembershipIssuer) sign(member awid.TeamCertificateFields) (*awid.TeamCertificate, error) {
	if len(issuer.Key) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("team signing key is required and must be valid")
	}
	member.Team = issuer.TeamID
	return awid.SignTeamCertificate(issuer.Key, member)
}

func (issuer teamMembershipIssuer) register(ctx context.Context, cert *awid.TeamCertificate) error {
	domain, team, err := awid.ParseTeamID(issuer.TeamID)
	if err != nil {
		return err
	}
	if len(issuer.Key) != ed25519.PrivateKeySize || cert == nil || cert.Team != issuer.TeamID ||
		cert.TeamDIDKey != awid.ComputeDIDKey(issuer.Key.Public().(ed25519.PublicKey)) {
		return fmt.Errorf("certificate does not match the signing authority for %s", issuer.TeamID)
	}
	return issuer.Registry.RegisterCertificate(ctx, issuer.RegistryURL, domain, team, cert, issuer.Key)
}
