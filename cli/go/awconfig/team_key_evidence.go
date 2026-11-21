package awconfig

import (
	"errors"
	"github.com/awebai/aw/awid"
)

// TeamKeyEvidenceUpdate binds a confirmation write to the exact installed
// certificate, so a delayed registry read cannot confirm a replacement.
type TeamKeyEvidenceUpdate struct {
	IdentityHome  string
	TeamID        string
	CertificateID string
	Evidence      awid.TeamKeyEvidence
}

// RecordTeamKeyEvidence writes the common membership field within the same
// credential generation/lock protocol used by certificate updates.
func RecordTeamKeyEvidence(update TeamKeyEvidenceUpdate) error {
	if err := update.Evidence.Validate(); err != nil {
		return err
	}
	operation := CredentialOperation{Command: "confirm-team-key", Intent: CredentialIntent(map[string]any{"team_id": update.TeamID})}
	return UpdateCredentials(update.IdentityHome, operation, func(begin func() error) error {
		state, err := LoadTeamStateFromIdentityHome(update.IdentityHome)
		if err != nil {
			return err
		}
		membership := state.Membership(update.TeamID)
		if membership == nil {
			return errors.New("team membership changed; select the intended team and retry confirmation")
		}
		certificatePath, err := IdentityHomeStoredPath(IdentityHome{Root: update.IdentityHome}, membership.CertPath)
		if err != nil {
			return err
		}
		cert, err := awid.LoadTeamCertificate(certificatePath)
		if err != nil {
			return err
		}
		if cert.Team != update.TeamID || cert.CertificateID != update.CertificateID || cert.TeamDIDKey != update.Evidence.DIDKey {
			return errors.New("team certificate changed during confirmation; retry with the installed certificate")
		}
		if membership.TeamKey != nil && *membership.TeamKey == update.Evidence {
			return nil
		}
		if err := begin(); err != nil {
			return err
		}
		evidence := update.Evidence
		membership.TeamKey = &evidence
		return SaveTeamStateToIdentityHome(update.IdentityHome, state)
	})
}
