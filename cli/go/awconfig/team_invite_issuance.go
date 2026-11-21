package awconfig

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
)

// TeamInviteIssuanceContext freezes routing and recipient custody selection.
// It grants no network trust and contains no recipient signing key.
type TeamInviteIssuanceContext struct {
	IdentityHome   string `json:"identity_home"`
	RegistryURL    string `json:"registry_url"`
	AwebURL        string `json:"aweb_url,omitempty"`
	ParentInviteID string `json:"parent_invite_id,omitempty"`
}

// TeamInviteIssuance embeds the shared recovery header in the existing invite.
// Its prepared effect is public membership proof, unlike identity-custody
// recovery payloads (docs/cli-integration-contract.md:161-198).
type TeamInviteIssuance struct {
	RecoveryProgress
	Context        TeamInviteIssuanceContext `json:"context"`
	PreparedEffect awid.TeamCertificate      `json:"prepared_effect"`
}

// ErrInviteIssuanceUnknown preserves uncertain records without reflecting their
// private contents or interpreting an unknown format as an unused invitation.
var ErrInviteIssuanceUnknown = errors.New("invite issuance is unknown; retain the record and check its exact certificate online before cancelling or resuming")

// InspectTeamInviteIssuance validates pending progress before lifetime readers
// can classify the invite as unused or expired (docs/cli-integration-contract.md:161-198).
// A nil result is the released record shape without an issuance fence.
func InspectTeamInviteIssuance(invite *TeamInvite) (*TeamInviteIssuance, error) {
	if invite == nil {
		return nil, ErrInviteIssuanceUnknown
	}
	issuance := invite.Issuance
	if issuance == nil {
		if invite.SuspendedSecret != "" {
			return nil, ErrInviteIssuanceUnknown
		}
		return nil, nil
	}
	if err := issuance.RecoveryProgress.Validate(); err != nil {
		return nil, errors.Join(ErrInviteIssuanceUnknown, err)
	}
	if issuance.State != RecoveryAttempted && issuance.State != RecoveryConfirmed {
		return nil, ErrInviteIssuanceUnknown
	}
	frozen, cert := issuance.Context, &issuance.PreparedEffect
	if !filepath.IsAbs(frozen.IdentityHome) ||
		filepath.Clean(frozen.IdentityHome) != frozen.IdentityHome ||
		strings.TrimSpace(frozen.RegistryURL) == "" ||
		cert.Team != awid.BuildTeamID(invite.Domain, invite.TeamName) {
		return nil, ErrInviteIssuanceUnknown
	}
	pub, err := awid.ExtractPublicKey(cert.TeamDIDKey)
	if err != nil {
		return nil, ErrInviteIssuanceUnknown
	}
	if err := awid.VerifyTeamCertificate(cert, ed25519.PublicKey(pub)); err != nil {
		return nil, ErrInviteIssuanceUnknown
	}
	if invite.Secret != "" {
		return nil, ErrInviteIssuanceUnknown
	}
	if issuance.State == RecoveryAttempted && (invite.SuspendedSecret == "" || invite.ConsumedAt != "") {
		return nil, ErrInviteIssuanceUnknown
	}
	if issuance.State == RecoveryConfirmed && (invite.SuspendedSecret != "" || invite.ConsumedAt == "") {
		return nil, ErrInviteIssuanceUnknown
	}
	return issuance, nil
}

type BeginTeamInviteIssuanceInput struct {
	InviteID    string
	Context     TeamInviteIssuanceContext
	Certificate awid.TeamCertificate
}

// BeginTeamInviteIssuance durably retains the exact signed effect before its
// submission. The caller holds LockTeamInvite through registration and outcome
// persistence (docs/cli-integration-contract.md:161-198).
func BeginTeamInviteIssuance(input BeginTeamInviteIssuanceInput) error {
	invite, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		return err
	}
	prior, err := InspectTeamInviteIssuance(invite)
	if err != nil {
		return err
	}
	if prior != nil || invite.ConsumedAt != "" || invite.Secret == "" {
		return errors.New("invite is not unused; check or resume its recorded issuance instead of minting another certificate")
	}
	invite.Issuance = &TeamInviteIssuance{
		RecoveryProgress: RecoveryProgress{Version: 1, State: RecoveryAttempted},
		Context:          input.Context, PreparedEffect: input.Certificate,
	}
	invite.SuspendedSecret, invite.Secret = invite.Secret, ""
	if _, err := InspectTeamInviteIssuance(invite); err != nil {
		return err
	}
	return SaveTeamInvite(invite)
}

type TeamInviteIssuanceOutcomeInput struct {
	InviteID      string
	CertificateID string
	Now           time.Time
}

// ConfirmTeamInviteIssuance marks only the exact retained certificate consumed;
// a failed write leaves the durable attempted fence (docs/cli-integration-contract.md:161-198).
func ConfirmTeamInviteIssuance(input TeamInviteIssuanceOutcomeInput) error {
	if input.Now.IsZero() {
		return errors.New("an issuance confirmation time is required")
	}
	invite, err := loadExactTeamInviteIssuance(input)
	if err != nil {
		return err
	}
	if invite.Issuance.State == RecoveryConfirmed {
		return nil
	}
	invite.Issuance.State = RecoveryConfirmed
	invite.SuspendedSecret = ""
	invite.ConsumedAt = input.Now.UTC().Format(time.RFC3339)
	return SaveTeamInvite(invite)
}

// ClearTeamInviteIssuanceAfterRefusal restores the original bearer only after
// the caller proves a definite refusal of this attempt. A later absent status
// after an ambiguous write is insufficient (docs/cli-integration-contract.md:161-198).
func ClearTeamInviteIssuanceAfterRefusal(input TeamInviteIssuanceOutcomeInput) error {
	invite, err := loadExactTeamInviteIssuance(input)
	if err != nil {
		return err
	}
	if invite.Issuance.State != RecoveryAttempted {
		return errors.New("confirmed issuance cannot become an unused invite; revoke its membership certificate separately")
	}
	invite.Secret, invite.SuspendedSecret = invite.SuspendedSecret, ""
	invite.Issuance = nil
	return SaveTeamInvite(invite)
}

func loadExactTeamInviteIssuance(input TeamInviteIssuanceOutcomeInput) (*TeamInvite, error) {
	invite, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		return nil, err
	}
	issuance, err := InspectTeamInviteIssuance(invite)
	if err != nil {
		return nil, err
	}
	if issuance == nil || input.CertificateID == "" || issuance.PreparedEffect.CertificateID != input.CertificateID {
		return nil, fmt.Errorf("certificate does not match the invite's retained issuance; retain the record and resume its exact certificate")
	}
	return invite, nil
}
