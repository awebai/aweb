package awid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// CurrentTeamCertificateCode identifies why a certificate cannot be admitted.
// These codes preserve the install command's released refusal vocabulary.
type CurrentTeamCertificateCode string

const (
	CurrentCertificateInvalid      CurrentTeamCertificateCode = "certificate_invalid"
	CurrentCertificateUnregistered CurrentTeamCertificateCode = "certificate_unregistered"
	CurrentCertificateUnavailable  CurrentTeamCertificateCode = "registry_unavailable"
	CurrentCertificateKeyChanged   CurrentTeamCertificateCode = "team_key_not_current"
	CurrentCertificateBadSignature CurrentTeamCertificateCode = "certificate_bad_signature"
	CurrentCertificateRevoked      CurrentTeamCertificateCode = "certificate_revoked"
)

// CurrentTeamCertificateError retains a named admission failure and its cause.
type CurrentTeamCertificateError struct {
	Code  CurrentTeamCertificateCode
	cause error
}

// Error describes why current membership could not be established.
func (e *CurrentTeamCertificateError) Error() string { return e.cause.Error() }

// Unwrap retains the underlying registry or artifact failure.
func (e *CurrentTeamCertificateError) Unwrap() error { return e.cause }

func currentCertificateRefusal(code CurrentTeamCertificateCode, cause error) error {
	return &CurrentTeamCertificateError{Code: code, cause: cause}
}

type registryCertificateState string

const (
	registryCertificateActive  registryCertificateState = "active"
	registryCertificateRevoked registryCertificateState = "revoked"
)

// CurrentTeamCertificateCheck names the artifact and selected registry to read.
type CurrentTeamCertificateCheck struct {
	RegistryURL string
	Certificate *TeamCertificate
}

// CheckCurrentTeamCertificate requires the registered, unrevoked certificate
// under the team's current key (docs/team-auth-envelope-v2.md:69). The public
// certificate-status read also works when a revoked member cannot read its
// private team; that refusal must not be confused with registry unavailability.
func (c *RegistryClient) CheckCurrentTeamCertificate(ctx context.Context, check CurrentTeamCertificateCheck) error {
	cert := check.Certificate
	if cert == nil {
		return currentCertificateRefusal(CurrentCertificateInvalid, errors.New("the team certificate is missing; ask the team's owner for its current certificate"))
	}
	domain, name, err := ParseTeamID(cert.Team)
	if err != nil {
		return currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("the certificate's team %q: %w; ask the team's owner for a corrected certificate", cert.Team, err))
	}
	if check.RegistryURL == "" {
		check.RegistryURL, err = c.Resolver.DiscoverRegistry(ctx, domain)
		if err != nil {
			return currentCertificateRefusal(CurrentCertificateUnavailable, fmt.Errorf("membership is unknown: discover the registry for %s: %w; retry when the registry is available", domain, err))
		}
	}
	status, err := c.GetTeamCertificateStatus(ctx, check.RegistryURL, domain, name, cert.CertificateID)
	if err != nil {
		var registryErr *RegistryError
		if errors.As(err, &registryErr) && registryErr.StatusCode == http.StatusNotFound {
			return currentCertificateRefusal(CurrentCertificateUnregistered, fmt.Errorf("the registry at %s holds no certificate %s of %s; ask the team's owner to register its current certificate", check.RegistryURL, cert.CertificateID, cert.Team))
		}
		return currentCertificateRefusal(CurrentCertificateUnavailable, fmt.Errorf("read certificate %s of %s at %s: %w; retry when the registry is available", cert.CertificateID, cert.Team, check.RegistryURL, err))
	}
	if status.TeamID != cert.Team {
		return currentCertificateRefusal(CurrentCertificateUnregistered, fmt.Errorf("the registry holds certificate %s for %s, not %s; ask the team's owner for the correct certificate", cert.CertificateID, status.TeamID, cert.Team))
	}
	if err := checkCertificateCurrentKey(cert, status.TeamDIDKey); err != nil {
		return err
	}

	switch status.Status {
	case string(registryCertificateActive):
		return nil
	case string(registryCertificateRevoked):
		revokedAt := ""
		if status.RevokedAt != nil {
			revokedAt = " at " + *status.RevokedAt
		}
		return currentCertificateRefusal(CurrentCertificateRevoked, fmt.Errorf("certificate %s of %s was revoked%s; ask the team's owner for a current certificate", cert.CertificateID, cert.Team, revokedAt))
	default:
		return currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("the registry reports status %q for certificate %s, which aw does not know; ask the team's owner to check its registry status", status.Status, cert.CertificateID))
	}
}
