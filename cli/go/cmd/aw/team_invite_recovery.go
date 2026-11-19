package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

type inviteInspectionState string

const (
	inviteInspectionUnused    inviteInspectionState = "unused"
	inviteInspectionAttempted inviteInspectionState = "attempted"
	inviteInspectionConsumed  inviteInspectionState = "consumed"
)

type inviteInspectionOutput struct {
	InviteID      string                `json:"invite_id"`
	State         inviteInspectionState `json:"state"`
	Code          string                `json:"code"`
	CertificateID string                `json:"certificate_id,omitempty"`
	RegistryURL   string                `json:"registry_url,omitempty"`
	IdentityHome  string                `json:"identity_home,omitempty"`
	NextStep      string                `json:"next_step"`
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
// cannot prove that submission will not commit (docs/cli-integration-contract.md:151-175).
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
		return nativeInviteIssuanceRefusal(invite, err)
	}
	out := inviteInspectionOutput{InviteID: id}
	if issuance == nil {
		if invite.ConsumedAt != "" {
			out.State, out.Code = inviteInspectionConsumed, "invite_already_used"
			out.NextStep = formatShellCommand([]string{"aw", "id", "team", "remove-member", "--namespace", invite.Domain, "--team", invite.TeamName, "--cert-id", "<certificate-id>"})
		} else {
			if invite.Secret == "" {
				return nativeInviteIssuanceRefusal(invite, awconfig.ErrInviteIssuanceUnknown)
			}
			out.State, out.Code = inviteInspectionUnused, "invite_unused"
			out.NextStep = formatShellCommand([]string{"aw", "id", "team", "revoke-invite", "--invite-id", id})
		}
		printOutput(out, formatJSONOutput)
		return nil
	}
	out.State, out.Code = inviteInspectionAttempted, "invite_issuance_pending"
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
		printOutput(out, formatJSONOutput)
		return nativeInviteIssuanceRefusal(invite, err)
	}
	if status.TeamID != issuance.PreparedEffect.Team || status.TeamDIDKey != issuance.PreparedEffect.TeamDIDKey {
		return nativeInviteIssuanceRefusal(invite, errors.New("registry status differs from the retained team or controller"))
	}
	if status.Status == "active" && status.RevokedAt == nil {
		out.Code = "invite_certificate_active"
	} else if status.Status == "revoked" && status.RevokedAt != nil {
		out.Code = "invite_certificate_revoked"
		out.NextStep = "The retained certificate is revoked; retain the invite history and request a new unused invitation."
	} else {
		return nativeInviteIssuanceRefusal(invite, errors.New("registry returned an unknown certificate status"))
	}
	if issuance.State == awconfig.RecoveryConfirmed {
		out.State = inviteInspectionConsumed
	}
	printOutput(out, formatJSONOutput)
	return nil
}

// Recovery requires the recorded recipient's own key and exact home; knowing
// an invite ID never permits replacing another identity (docs/cli-integration-contract.md:151-175).
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
	if err := recordAcceptedTeamMembership(workingDir, accepted.Output, accepted.Certificate, accepted.RegistryURL, accepted.AwebURL, recordMembershipOptions{IdentityHome: resolvedEncryptionKeyIdentityHome(home), SetActive: true}); err != nil {
		return err
	}
	if err := writeExternalLocalIdentityStateIfNeeded(home.Root, accepted.Certificate); err != nil {
		return err
	}
	printOutput(*accepted.Output, formatTeamAcceptInvite)
	return nil
}

func init() {
	teamCheckInviteCmd.Flags().StringVar(&teamCheckInviteID, "invite-id", "", "Saved local invite_id to inspect")
	teamResumeInviteCmd.Flags().StringVar(&teamResumeInviteID, "invite-id", "", "Saved invite_id whose exact issuance is resumed")
	teamCmd.AddCommand(teamCheckInviteCmd, teamResumeInviteCmd)
	identityHomeNeutralCommandExemptions[teamCheckInviteCmd] = struct{}{}
	identityHomeNeutralCommandExemptions[teamResumeInviteCmd] = struct{}{}
}
