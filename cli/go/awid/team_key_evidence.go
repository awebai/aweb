package awid

import (
	"context"
	"errors"
	"fmt"
	"net/http"
)

// TeamKeyConfirmation distinguishes independent registry evidence from a
// creation response's unconfirmed claim (Antares245fb075).
type TeamKeyConfirmation string

const (
	TeamKeyUnconfirmed TeamKeyConfirmation = "unconfirmed"
	TeamKeyConfirmed   TeamKeyConfirmation = "confirmed"
)

// TeamKeyEvidence is persisted beside membership state. Unconfirmed material
// is never evidence that the registry agrees with the supplied team key.
type TeamKeyEvidence struct {
	DIDKey string              `json:"did_key" yaml:"did_key"`
	State  TeamKeyConfirmation `json:"state" yaml:"state"`
}

// Validate rejects malformed local or decoded evidence; a named state alone
// never verifies a key or promotes an unconfirmed claim.
func (e TeamKeyEvidence) Validate() error {
	if e.State != TeamKeyConfirmed && e.State != TeamKeyUnconfirmed {
		return errors.New("invalid team-key confirmation state; repair the membership evidence")
	}
	if _, err := ExtractPublicKey(e.DIDKey); err != nil {
		return fmt.Errorf("invalid stored team key: %w; repair the membership evidence", err)
	}
	return nil
}

// TeamCertificateKeyObservation retains the selected registry and unavailable
// cause without serializing transport errors into the local authority record.
type TeamCertificateKeyObservation struct {
	Evidence         TeamKeyEvidence
	RegistryURL      string
	UnavailableCause error
}

// CheckTeamCertificateCurrentKey checks independent current-key evidence when
// existing registry reads can supply it. Pending private-team material remains
// explicitly unconfirmed; it does not acquire a new registration prerequisite
// (Antares245fb075; docs/identity.md, pending private-team key confirmation).
func (c *RegistryClient) CheckTeamCertificateCurrentKey(ctx context.Context, check CurrentTeamCertificateCheck) (*TeamCertificateKeyObservation, error) {
	cert := check.Certificate
	if cert == nil {
		return nil, currentCertificateRefusal(CurrentCertificateInvalid, errors.New("the team certificate is missing; ask the team's owner for the correct certificate"))
	}
	if err := CheckDecodedTeamCertificate(cert, cert.TeamDIDKey); err != nil {
		return nil, currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("check the supplied certificate artifact: %w; ask the team's owner for the correct certificate", err))
	}
	domain, name, err := ParseTeamID(cert.Team)
	if err != nil || BuildTeamID(domain, name) != cert.Team {
		return nil, currentCertificateRefusal(CurrentCertificateInvalid, fmt.Errorf("the certificate names a noncanonical team; ask the team's owner for a corrected certificate"))
	}
	observed := &TeamCertificateKeyObservation{
		Evidence:    TeamKeyEvidence{DIDKey: cert.TeamDIDKey, State: TeamKeyUnconfirmed},
		RegistryURL: check.RegistryURL,
	}
	if observed.RegistryURL == "" {
		observed.RegistryURL, err = c.Resolver.DiscoverRegistry(ctx, domain)
		if err != nil {
			observed.UnavailableCause = err
			return observed, nil
		}
	}
	status, err := c.GetTeamCertificateStatus(ctx, observed.RegistryURL, domain, name, cert.CertificateID)
	if err == nil {
		if status.TeamID != cert.Team {
			return nil, currentCertificateRefusal(CurrentCertificateInvalid, errors.New("the registry certificate belongs to another team; ask the team's owner for the correct certificate"))
		}
		if status.Status == string(registryCertificateRevoked) {
			return nil, currentCertificateRefusal(CurrentCertificateRevoked, errors.New("the registry says this certificate is revoked; ask the team's owner for a current certificate"))
		}
		if status.Status != string(registryCertificateActive) {
			return nil, currentCertificateRefusal(CurrentCertificateInvalid, errors.New("the registry returned an unknown certificate status; ask the team's owner to check it"))
		}
		if err := checkCertificateCurrentKey(cert, status.TeamDIDKey); err != nil {
			return nil, err
		}
		observed.Evidence.State = TeamKeyConfirmed
		return observed, nil
	}
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) || (registryErr.StatusCode != http.StatusNotFound && registryErr.StatusCode != http.StatusForbidden) {
		observed.UnavailableCause = err
		return observed, nil
	}
	// Public team metadata can confirm the key before registration completes.
	// Private metadata's403 and an absent status's404 grant no key agreement.
	team, err := c.GetTeam(ctx, observed.RegistryURL, domain, name, nil)
	if err != nil {
		observed.UnavailableCause = err
		return observed, nil
	}
	if team.TeamID != cert.Team {
		return nil, currentCertificateRefusal(CurrentCertificateInvalid, errors.New("the registry team response names another team; ask the team's owner to check the selected registry"))
	}
	if err := checkCertificateCurrentKey(cert, team.TeamDIDKey); err != nil {
		return nil, err
	}
	observed.Evidence.State = TeamKeyConfirmed
	return observed, nil
}

func checkCertificateCurrentKey(cert *TeamCertificate, currentKey string) error {
	if cert.TeamDIDKey != currentKey {
		return currentCertificateRefusal(CurrentCertificateKeyChanged, errors.New("the team key this agent was given does not match the registry's; ask the team's owner for the correct current certificate"))
	}
	if err := CheckDecodedTeamCertificate(cert, currentKey); err != nil {
		code := CurrentCertificateInvalid
		var primitive *TeamCertificateError
		if errors.As(err, &primitive) && primitive.Reason == "bad_signature" {
			code = CurrentCertificateBadSignature
		}
		return currentCertificateRefusal(code, fmt.Errorf("the certificate does not verify under the registry's current team key: %w; ask the team's owner for a current certificate", err))
	}
	return nil
}
