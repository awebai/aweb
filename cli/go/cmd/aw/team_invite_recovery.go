package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

type inviteInspectionOutput struct {
	InviteID      string                            `json:"invite_id"`
	State         awconfig.TeamInviteLifecycleState `json:"state"`
	Code          string                            `json:"code"`
	CertificateID string                            `json:"certificate_id,omitempty"`
	ExpiresAt     string                            `json:"expires_at,omitempty"`
	RegistryURL   string                            `json:"registry_url,omitempty"`
	IdentityHome  string                            `json:"identity_home,omitempty"`
	NextStep      string                            `json:"next_step"`
	Message       string                            `json:"message,omitempty"`
}

var teamCheckInviteID string
var teamResumeInviteID string

var teamCheckInviteCmd = &cobra.Command{
	Use: "check-invite", Short: "Inspect a saved invite and check its exact attempted certificate online", Args: cobra.NoArgs,
	RunE: runTeamCheckInvite,
}

var teamResumeInviteCmd = &cobra.Command{
	Use: "resume-invite", Short: "Resume the exact saved certificate into its original recipient home", Args: cobra.NoArgs,
	RunE: runTeamResumeInvite,
}

// Checking never clears an attempted fence: absence after an uncertain write
// cannot prove that submission will not commit (docs/cli-integration-contract.md:161-198).
func runTeamCheckInvite(cmd *cobra.Command, args []string) (resultErr error) {
	id := strings.TrimSpace(teamCheckInviteID)
	if id == "" {
		return usageError("--invite-id is required; pass the invite_id returned when the invite was created")
	}
	lock, err := awconfig.LockTeamInvite(id)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	invite, err := awconfig.LoadTeamInvite(id)
	if err != nil {
		return fmt.Errorf("read invite for online check: %w; restore its original local record before reconciling the exact certificate", err)
	}
	issuance, err := awconfig.InspectTeamInviteIssuance(invite)
	if err != nil {
		return withErrorCode("invite_issuance_pending", fmt.Errorf("inspect retained issuance: %w; retain the original record and restore it or upgrade its reader before reconciling the exact certificate", err))
	}
	lifecycle, lifecycleErr := awconfig.InspectTeamInviteLifecycle(awconfig.TeamInviteLifecycleRequest{Invite: invite, Now: time.Now()})
	if lifecycleErr != nil {
		return withErrorCode("invite_issuance_pending", fmt.Errorf("inspect saved invite: %w; retain and restore its original record before reconciling its certificate", lifecycleErr))
	}
	out := inviteInspectionOutput{InviteID: id, State: lifecycle.State}
	if !lifecycle.ExpiresAt.IsZero() {
		out.ExpiresAt = lifecycle.ExpiresAt.Format(time.RFC3339Nano)
	}
	if issuance == nil {
		if lifecycle.State == awconfig.TeamInviteConsumed {
			out.State, out.Code = awconfig.TeamInviteConsumed, "invite_already_used"
			out.NextStep = formatShellCommand([]string{"aw", "id", "team", "remove-member", "--namespace", invite.Domain, "--team", invite.TeamName, "--cert-id", "<certificate-id>"})
		} else {
			if invite.Secret == "" {
				return nativeInviteIssuanceRefusal(invite, awconfig.ErrInviteIssuanceUnknown)
			}
			out.Code = "invite_unused"
			if lifecycle.State == awconfig.TeamInviteExpired {
				out.Code = "invite_expired"
			}
			out.NextStep = formatShellCommand([]string{"aw", "id", "team", "revoke-invite", "--invite-id", id})
		}
		return printJSON(out)
	}
	out.Code = "invite_issuance_pending"
	out.CertificateID, out.RegistryURL, out.IdentityHome = issuance.PreparedEffect.CertificateID, issuance.Context.RegistryURL, issuance.Context.IdentityHome
	out.NextStep = formatShellCommand([]string{"aw", "--identity-home", out.IdentityHome, "id", "team", "resume-invite", "--invite-id", id})
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return err
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	status, err := registry.GetTeamCertificateStatus(ctx, out.RegistryURL, invite.Domain, invite.TeamName, out.CertificateID)
	if err != nil {
		// Print the retained selection even on an inconclusive online check.
		out.Code = "outcome_unknown"
		outputErr := printJSON(out)
		return errors.Join(withErrorCode("outcome_unknown", fmt.Errorf("online certificate check was inconclusive: %w; retain the original recipient and record, then run `%s` to resume its exact effect", err, out.NextStep)), outputErr)
	}
	if status.TeamID != issuance.PreparedEffect.Team || status.TeamDIDKey != issuance.PreparedEffect.TeamDIDKey {
		return nativeInviteIssuanceRefusal(invite, errors.New("registry status differs from the retained team or controller"))
	}
	if status.Status == "active" && status.RevokedAt == nil {
		out.Code = "invite_certificate_active"
	} else if status.Status == "revoked" && status.RevokedAt != nil {
		out.Code = "invite_certificate_revoked"
		out.NextStep = ""
		out.Message = "The retained certificate is revoked; retain the invite history and request a new unused invitation from its issuer."
	} else {
		return nativeInviteIssuanceRefusal(invite, errors.New("registry returned an unknown certificate status"))
	}
	if issuance.State == awconfig.RecoveryConfirmed {
		out.State = awconfig.TeamInviteConsumed
	}
	return printJSON(out)
}

// Recovery requires the recorded recipient's own key and exact home; knowing
// an invite ID never permits replacing another identity (docs/cli-integration-contract.md:161-198).
func runTeamResumeInvite(cmd *cobra.Command, args []string) (resultErr error) {
	id := strings.TrimSpace(teamResumeInviteID)
	if id == "" {
		return usageError("--invite-id is required; pass the invite_id from the incomplete issuance")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	if home.Source != awconfig.IdentityHomeFlag {
		return usageError("invite recovery requires explicit --identity-home for its original recipient; pass that recorded path and retry")
	}
	lock, err := awconfig.LockTeamInvite(id)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	invite, err := awconfig.LoadTeamInvite(id)
	if err != nil {
		return err
	}
	issuance, err := awconfig.InspectTeamInviteIssuance(invite)
	if err != nil {
		return nativeInviteIssuanceRefusal(invite, err)
	}
	if issuance == nil {
		return usageError("this invite has no retained issuance to resume; run `aw id team check-invite --invite-id %s --json` before choosing its next action", id)
	}
	ctx, cancel := commandAPIContext(cmd)
	defer cancel()
	accepted, err := resumeNativeInviteIssuance(ctx, nativeInviteResumeRequest{WorkingDir: workingDir, Options: teamAcceptInviteOptions{IdentityHome: home.Root}, Invite: invite, Issuance: issuance})
	if err != nil {
		return err
	}
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{
		WorkingDir:   workingDir,
		Output:       accepted.Output,
		Certificate:  accepted.Certificate,
		RegistryURL:  accepted.RegistryURL,
		AwebURL:      accepted.AwebURL,
		IdentityHome: resolvedEncryptionKeyIdentityHome(home),
		Activation:   membershipMakeActive,
	}); err != nil {
		return err
	}
	if err := writeExternalLocalIdentityStateIfNeeded(home.Root, accepted.Certificate); err != nil {
		return err
	}
	return printOutput(*accepted.Output, formatTeamAcceptInvite)
}

func init() {
	teamCheckInviteCmd.Flags().StringVar(&teamCheckInviteID, "invite-id", "", "Saved local invite_id to inspect")
	teamResumeInviteCmd.Flags().StringVar(&teamResumeInviteID, "invite-id", "", "Saved invite_id whose exact issuance is resumed")
	teamCmd.AddCommand(teamCheckInviteCmd, teamResumeInviteCmd)
	identityHomeNeutralCommandExemptions[teamCheckInviteCmd] = struct{}{}
	identityHomeNeutralCommandExemptions[teamResumeInviteCmd] = struct{}{}
}
