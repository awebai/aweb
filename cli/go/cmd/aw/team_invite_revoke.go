package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type inviteCancellationState string
type inviteChildDisposition string

const (
	inviteCancelled     inviteCancellationState = "cancelled"
	inviteAbsent        inviteCancellationState = "absent"
	inviteAlreadyUsed   inviteCancellationState = "already_used"
	inviteAttempted     inviteCancellationState = "attempted"
	inviteChildNone     inviteChildDisposition  = "none"
	inviteChildVoided   inviteChildDisposition  = "voided"
	inviteChildIssued   inviteChildDisposition  = "already_issued"
	inviteChildMissing  inviteChildDisposition  = "absent"
	inviteChildRetained inviteChildDisposition  = "retained"
)

type inviteCancellationOutput struct {
	InviteID     string                  `json:"invite_id"`
	Status       inviteCancellationState `json:"status"`
	Code         string                  `json:"code"`
	LinkedChild  inviteChildDisposition  `json:"linked_child_disposition"`
	Message      string                  `json:"message"`
	NextStep     string                  `json:"next_step"`
	IdentityHome string                  `json:"identity_home,omitempty"`
}

var teamRevokeInviteID string
var teamRevokeInviteCmd = &cobra.Command{
	Use:   "revoke-invite",
	Short: "Cancel an unused local controller invite; issued membership certificates remain valid",
	Args:  cobra.NoArgs,
	RunE:  runTeamRevokeInvite,
}

// Cancellation is local controller authority over an unused enrollment record;
// certificate removal remains controller-signed (docs/awid-sot.md:853-858).
func runTeamRevokeInvite(cmd *cobra.Command, args []string) (resultErr error) {
	id := strings.TrimSpace(teamRevokeInviteID)
	if id == "" {
		return usageError("--invite-id is required; pass the invite_id returned when the invite was created")
	}
	lock, err := awconfig.LockTeamInvite(id)
	if err != nil {
		return err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	invite, err := awconfig.LoadTeamInvite(id)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read local invite: %w; check the invite ID and its local record", err)
	}
	out := inviteCancellationOutput{InviteID: id, LinkedChild: inviteChildNone, NextStep: "aw id team remove-member --team <team> --namespace <domain> --cert-id <certificate-id>"}
	if errors.Is(err, os.ErrNotExist) {
		out.Status, out.Code, out.Message = inviteAbsent, "invite_absent", "No pending local invite is stored here; it may already have been used. This does not revoke an issued certificate."
		return printJSON(out)
	}
	out.NextStep = formatShellCommand([]string{"aw", "id", "team", "remove-member", "--team", invite.TeamName, "--namespace", invite.Domain, "--cert-id", "<certificate-id>"})
	issuance, inspectErr := awconfig.InspectTeamInviteIssuance(invite)
	lifecycle, lifecycleErr := awconfig.InspectTeamInviteLifecycle(awconfig.TeamInviteLifecycleRequest{Invite: invite, Now: time.Now()})
	inspectErr = errors.Join(inspectErr, lifecycleErr)
	if inspectErr != nil || lifecycle.State == awconfig.TeamInviteAttempted || lifecycle.State == awconfig.TeamInviteUnknown {
		out.Status, out.Code = inviteAttempted, "invite_issuance_pending"
		out.Message = "This invite has an attempted or unknown issuance. Cancellation cannot determine whether its certificate was issued."
		out.NextStep = formatShellCommand(nativeInviteCheckArgv(invite))
		if issuance != nil {
			out.IdentityHome = issuance.Context.IdentityHome
		}
		if invite.IDChild != nil {
			out.LinkedChild = inviteChildRetained
		}
		outputErr := printJSON(out)
		if inspectErr == nil {
			inspectErr = awconfig.ErrInviteIssuanceUnknown
		}
		return errors.Join(nativeInviteIssuanceRefusal(invite, inspectErr), outputErr)
	}
	if lifecycle.State == awconfig.TeamInviteConsumed {
		out.Status, out.Code, out.Message = inviteAlreadyUsed, "invite_already_used", "This invite was already used. Cancelling an unused invite does not revoke an issued certificate."
		if invite.IDChild != nil {
			out.LinkedChild = inviteChildIssued
		}
		outputErr := printJSON(out)
		return errors.Join(withErrorCode("invite_already_used", fmt.Errorf("%s Revoke the issued membership with %s", out.Message, out.NextStep)), outputErr)
	}
	if invite.Domain == "" || invite.TeamName == "" || strings.HasPrefix(id, "hosted-") || strings.HasPrefix(id, "creator-") {
		return withErrorCode("invite_not_local_controller", fmt.Errorf("this record is not an unused local controller invite; cancel the hosted invitation through its issuing service"))
	}
	if invite.Secret == "" {
		return nativeInviteIssuanceRefusal(invite, awconfig.ErrInviteIssuanceUnknown)
	}
	if _, err := awconfig.LoadTeamKey(invite.Domain, invite.TeamName); err != nil {
		return teamKeyLoadError(awid.BuildTeamID(invite.Domain, invite.TeamName), invite.Domain, err)
	}
	out.LinkedChild, err = cancelLinkedInviteChild(invite.IDChild)
	if err != nil {
		return fmt.Errorf("cancel linked child invitation: %w; retain the team invite until its child disposition is established", err)
	}
	if err := awconfig.DeleteTeamInvite(id); err != nil {
		return err
	}
	out.Status, out.Code, out.Message = inviteCancelled, "invite_cancelled", "Cancelled the unused invite. This does not revoke an issued certificate."
	return printJSON(out)
}

func cancelLinkedInviteChild(link *awconfig.TeamInviteIDChild) (disposition inviteChildDisposition, resultErr error) {
	if link == nil {
		return inviteChildNone, nil
	}
	store := awconfig.IDInvitationFileStore{Dir: awconfig.IdentityInvitationsDir(link.IssuerHome)}
	lock, err := awconfig.LockExclusive(store.Dir + ".lock")
	if err != nil {
		return inviteChildNone, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()
	invitation, err := store.Invitation(link.InvitationID)
	if err != nil {
		return inviteChildNone, err
	}
	if invitation == nil {
		return inviteChildMissing, nil
	}
	parent, validParent := invitation.Parent["id"].(string)
	if !validParent || parent != link.Parent || invitation.Domain != link.Domain {
		return inviteChildNone, fmt.Errorf("linked invitation differs from its recorded parent or domain; inspect the issuer's local invitation before retrying")
	}
	if invitation.Request != nil && invitation.Request.State == awid.IDRequestIssued {
		return inviteChildIssued, fmt.Errorf("linked child invitation already issued a certificate; inspect that identity before cancelling its pending membership")
	}
	invitation.Void = true
	if err := store.PutInvitation(invitation); err != nil {
		return inviteChildNone, err
	}
	return inviteChildVoided, nil
}

func init() {
	teamRevokeInviteCmd.Flags().StringVar(&teamRevokeInviteID, "invite-id", "", "Local invite_id to cancel")
	teamCmd.AddCommand(teamRevokeInviteCmd)
	identityHomeNeutralCommandExemptions[teamRevokeInviteCmd] = struct{}{}
}
