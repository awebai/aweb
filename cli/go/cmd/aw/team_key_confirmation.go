package main

import (
	"errors"
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"os"
)

func teamKeyEvidence(observation *awid.TeamCertificateKeyObservation) *awid.TeamKeyEvidence {
	if observation == nil {
		return nil
	}
	result := observation.Evidence
	return &result
}

func teamKeyConfirmationText(evidence *awid.TeamKeyEvidence) string {
	if evidence == nil {
		return ""
	}
	if evidence.State == awid.TeamKeyUnconfirmed {
		return "Team key is unconfirmed. Registration and a successful registry read will confirm it; run aw doctor --online after registration."
	}
	return fmt.Sprintf("Team key is %s by an independent registry read.", evidence.State)
}

// recheckUnconfirmedTeamKey runs before an ordinary certificate-authenticated
// command. It never turns an unavailable read into a confirmed local key.
func recheckUnconfirmedTeamKey(selection *awconfig.Selection, cert *awid.TeamCertificate) error {
	home := selection.IdentityHome
	if home == "" {
		home = awconfig.WorktreeIdentityHome(selection.WorkingDir)
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	} // Released workspace-only homes have no evidence record.
	if err != nil {
		return fmt.Errorf("read team-key confirmation: %w; repair this identity home's team state", err)
	}
	membership := state.Membership(cert.Team)
	if membership == nil || membership.TeamKey == nil {
		return nil
	}
	// A supported certificate update can change the team key. A confirmation
	// for the preceding key grants no fact about this certificate's key.
	if membership.TeamKey.State == awid.TeamKeyConfirmed && membership.TeamKey.DIDKey == cert.TeamDIDKey {
		return nil
	}
	registry, err := newRegistryClientWithPreferredBaseURL(membership.RegistryURL)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	observation, err := registry.CheckTeamCertificateCurrentKey(ctx, awid.CurrentTeamCertificateCheck{
		RegistryURL: membership.RegistryURL, Certificate: cert,
	})
	if err != nil {
		return err
	}
	if observation.Evidence.State == awid.TeamKeyUnconfirmed {
		debugLog("team-key confirmation remains unknown at %s: %v", observation.RegistryURL, observation.UnavailableCause)
		if membership.TeamKey.DIDKey == cert.TeamDIDKey {
			return nil
		}
	}
	return awconfig.RecordTeamKeyEvidence(awconfig.TeamKeyEvidenceUpdate{
		IdentityHome: home, TeamID: cert.Team, CertificateID: cert.CertificateID,
		Evidence: observation.Evidence,
	})
}
