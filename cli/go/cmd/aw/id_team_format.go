package main

import (
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/awebai/aw/awid"
)

func formatTeamCreate(v any) string {
	out := v.(teamCreateOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Team DID:    %s\n", out.TeamDIDKey))
	sb.WriteString(fmt.Sprintf("Key:         %s\n", out.TeamKeyPath))
	if strings.TrimSpace(out.RegistryURL) != "" {
		sb.WriteString(fmt.Sprintf("Registry:    %s\n", out.RegistryURL))
	}
	sb.WriteString("\nKeep the ~/.awid team controller key safe and backed up. It controls team membership.\n")
	return sb.String()
}

func formatTeamInvite(v any) string {
	out := v.(teamInviteOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Invite ID:   %s\n", out.InviteID))
	sb.WriteString(fmt.Sprintf("Token:       %s\n", out.Token))
	sb.WriteString(fmt.Sprintf("Command:     aw id team accept-invite %s --alias <alias>\n", out.Token))
	return sb.String()
}

func formatTeamAcceptInvite(v any) string {
	out := v.(teamAcceptInviteOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Alias:       %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Certificate: %s\n", out.CertPath))
	return sb.String()
}

func formatTeamAddMember(v any) string {
	out := v.(teamAddMemberOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Member:      %s\n", firstNonEmpty(out.Member, out.MemberAddress)))
	sb.WriteString(fmt.Sprintf("Certificate: %s\n", out.CertificateID))
	if strings.TrimSpace(out.FetchCommand) != "" {
		sb.WriteString(fmt.Sprintf("Fetch:       %s\n", out.FetchCommand))
	}
	return sb.String()
}

func formatTeamFetchCert(v any) string {
	out := v.(teamFetchCertOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Alias:       %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Certificate: %s\n", out.CertificateID))
	sb.WriteString(fmt.Sprintf("Path:        %s\n", out.CertPath))
	return sb.String()
}

func formatTeamRemoveMember(v any) string {
	out := v.(teamRemoveMemberOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Member:      %s\n", out.MemberAddress))
	return sb.String()
}

func formatTeamImportRequest(v any) string {
	out := v.(teamImportRequestOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.AWIDTeamID))
	sb.WriteString(fmt.Sprintf("Mode:        %s\n", map[bool]string{true: "dry-run", false: "apply"}[out.DryRun]))
	sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", out.Timestamp))
	sb.WriteString(fmt.Sprintf("Controller:  %s\n", out.ControllerDID))
	sb.WriteString(fmt.Sprintf("Signature:   %s\n", out.ControllerSignature))
	sb.WriteString("Request body:\n")
	if body, err := awid.CanonicalJSONValue(out.RequestBody); err == nil {
		sb.WriteString(body)
		sb.WriteByte('\n')
	}
	return sb.String()
}

func formatTeamRegister(v any) string {
	out := v.(teamRegisterOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.AWIDTeamID))
	sb.WriteString(fmt.Sprintf("Service:     %s\n", out.ServiceURL))
	sb.WriteString(fmt.Sprintf("Mode:        %s\n", map[bool]string{true: "dry-run", false: "apply"}[out.DryRun]))
	sb.WriteString(fmt.Sprintf("Timestamp:   %s\n", out.Timestamp))
	sb.WriteString(fmt.Sprintf("Controller:  %s\n", out.ControllerDID))
	if strings.TrimSpace(out.TeamDIDKey) != "" {
		sb.WriteString(fmt.Sprintf("Team DID:    %s\n", out.TeamDIDKey))
	}
	if strings.TrimSpace(out.DashboardURL) != "" {
		sb.WriteString(fmt.Sprintf("Dashboard:   %s\n", out.DashboardURL))
	}
	if len(out.NextSteps) > 0 {
		sb.WriteString("\nNext steps:\n")
		for _, step := range out.NextSteps {
			label := strings.TrimSpace(step.Label)
			if label == "" {
				label = "Run"
			}
			required := ""
			if step.Required {
				required = " (required)"
			}
			sb.WriteString(fmt.Sprintf("- %s%s: %s\n", label, required, strings.TrimSpace(step.Command)))
			if desc := strings.TrimSpace(step.Description); desc != "" {
				sb.WriteString(fmt.Sprintf("  %s\n", desc))
			}
		}
	}
	return sb.String()
}

func formatTeamCleanupCloud(v any) string {
	out := v.(teamCleanupCloudOutput)
	var sb strings.Builder
	if out.DryRun {
		sb.WriteString("Status:      dry-run\n")
	} else {
		sb.WriteString("Status:      deleted\n")
	}
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	if strings.TrimSpace(out.ControllerScope) != "" {
		sb.WriteString(fmt.Sprintf("Authority:   %s\n", out.ControllerScope))
	}
	sb.WriteString(fmt.Sprintf("Controller:  %s\n", out.ControllerDID))
	sb.WriteString(fmt.Sprintf("Aweb URL:    %s\n", out.CloudURL))
	sb.WriteString(fmt.Sprintf("Agents:      %d\n", out.AgentsDeleted))
	sb.WriteString(fmt.Sprintf("Workspaces:  %d\n", out.WorkspacesDeleted))
	sb.WriteString(fmt.Sprintf("Metadata:    %d\n", out.CloudWorkspaceMetadataDeleted))
	sb.WriteString(fmt.Sprintf("Members:     %d\n", out.TeamMembersDeleted))
	if out.BYOTAuthorizationsDeleted > 0 {
		sb.WriteString(fmt.Sprintf("BYOT auths:  %d\n", out.BYOTAuthorizationsDeleted))
	}
	sb.WriteString(fmt.Sprintf("Team row:    %t\n", out.TeamDeleted))
	if strings.TrimSpace(out.AuditID) != "" {
		sb.WriteString(fmt.Sprintf("Audit:       %s\n", out.AuditID))
	}
	return sb.String()
}

func formatTeamAdd(v any) string {
	out := v.(teamAddOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Alias:       %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Certificate: %s\n", out.CertPath))
	return sb.String()
}

func formatTeamSwitch(v any) string {
	out := v.(teamSwitchOutput)
	if strings.TrimSpace(out.Status) == "already_active" {
		return fmt.Sprintf("Team %s is already active\n", out.ActiveTeam)
	}
	return fmt.Sprintf("Active team switched to %s\n", out.ActiveTeam)
}

func formatTeamList(v any) string {
	out := v.(teamListOutput)
	if len(out.Memberships) == 0 {
		return "No team memberships.\n"
	}
	var sb strings.Builder
	tw := tabwriter.NewWriter(&sb, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ACTIVE\tTEAM\tALIAS\tIDENTITY\tISSUED")
	for _, item := range out.Memberships {
		active := ""
		if item.Active {
			active = "*"
		}
		identityClass := "-"
		if strings.TrimSpace(item.IdentityScope) != "" {
			identityClass = awid.NormalizeIdentityScope(item.IdentityScope)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			active,
			item.TeamID,
			item.Alias,
			identityClass,
			firstNonEmpty(item.IssuedAt, "-"),
		)
	}
	_ = tw.Flush()
	return sb.String()
}

func formatTeamLeave(v any) string {
	out := v.(teamLeaveOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Left team %s\n", out.TeamID))
	if strings.TrimSpace(out.ActiveTeam) != "" {
		sb.WriteString(fmt.Sprintf("Active team: %s\n", out.ActiveTeam))
	}
	return sb.String()
}

func formatCertShow(v any) string {
	out := v.(certShowOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Alias:       %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Member DID:  %s\n", out.MemberDIDKey))
	sb.WriteString(fmt.Sprintf("Team DID:    %s\n", out.TeamDIDKey))
	sb.WriteString(fmt.Sprintf("Identity:    %s\n", awid.NormalizeIdentityScope(out.IdentityScope)))
	sb.WriteString(fmt.Sprintf("Issued:      %s\n", out.IssuedAt))
	sb.WriteString(fmt.Sprintf("Certificate: %s\n", out.CertificateID))
	return sb.String()
}
