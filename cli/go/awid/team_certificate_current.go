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

func (e *CurrentTeamCertificateError) Error() string { return e.cause.Error() }
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
		return currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("the team certificate is missing"))
	}
	domain, name, err := ParseTeamID(cert.Team)
	if err != nil {
		return currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("the certificate's team %q: %w", cert.Team, err))
	}
	status, err := c.GetTeamCertificateStatus(ctx, check.RegistryURL, domain, name, cert.CertificateID)
	if err != nil {
		var registryErr *RegistryError
		if errors.As(err, &registryErr) && registryErr.StatusCode == http.StatusNotFound {
			return currentCertificateRefusal(CurrentCertificateUnregistered, fmt.Errorf("the registry at %s holds no certificate %s of %s", check.RegistryURL, cert.CertificateID, cert.Team))
		}
		return currentCertificateRefusal(CurrentCertificateUnavailable, fmt.Errorf("read certificate %s of %s at %s: %w", cert.CertificateID, cert.Team, check.RegistryURL, err))
	}
	if status.TeamID != cert.Team {
		return currentCertificateRefusal(CurrentCertificateUnregistered, fmt.Errorf("the registry holds certificate %s for %s, not %s", cert.CertificateID, status.TeamID, cert.Team))
	}
	if cert.TeamDIDKey != status.TeamDIDKey {
		return currentCertificateRefusal(CurrentCertificateKeyChanged, fmt.Errorf("the certificate is signed by %s, not %s's current key %s", cert.TeamDIDKey, cert.Team, status.TeamDIDKey))
	}
	header, err := EncodeTeamCertificateHeader(cert)
	if err != nil {
		return currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("encode the certificate: %w", err))
	}
	if _, err := CheckTeamCertificate(header, TeamCertificateFacts{
		SubjectDIDKey: cert.MemberDIDKey, TeamDIDKey: status.TeamDIDKey, Registered: RegistrationNotRequired(),
	}); err != nil {
		var refused *TeamCertificateError
		if errors.As(err, &refused) && refused.Reason == "bad_signature" {
			return currentCertificateRefusal(CurrentCertificateBadSignature, fmt.Errorf("the certificate's signature does not verify under %s", status.TeamDIDKey))
		}
		return currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("the certificate does not check: %w", err))
	}
	switch status.Status {
	case string(registryCertificateActive):
		return nil
	case string(registryCertificateRevoked):
		revokedAt := ""
		if status.RevokedAt != nil {
			revokedAt = " at " + *status.RevokedAt
		}
		return currentCertificateRefusal(CurrentCertificateRevoked, fmt.Errorf("certificate %s of %s was revoked%s", cert.CertificateID, cert.Team, revokedAt))
	default:
		return currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("the registry reports status %q for certificate %s, which aw does not know", status.Status, cert.CertificateID))
	}
}
