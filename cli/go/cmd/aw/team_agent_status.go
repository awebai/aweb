package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// Retirement is only believable if something other than the retire command can
// see it. This reads the two stores directly and reports each one, so the
// evidence that an agent is retired never comes from the command that retired it.
//
// It mutates nothing.

// Certificate store readings.
const (
	agentCertificateActive  = "active"
	agentCertificateNone    = "none"
	agentCertificateUnknown = "unknown"
)

// Coordination store readings.
const (
	agentWorkspacePresent = "present"
	agentWorkspaceAbsent  = "absent"
	agentWorkspaceUnknown = "unknown"
)

// Overall readings.
const (
	agentStateRetired = "retired"
	agentStateActive  = "active"
	agentStateUnknown = "unknown"
)

type teamAgentStatusOutput struct {
	State          string   `json:"state"`
	TeamID         string   `json:"team_id"`
	Alias          string   `json:"alias"`
	Certificate    string   `json:"certificate"`
	CertificateID  string   `json:"certificate_id,omitempty"`
	MemberAddress  string   `json:"member_address,omitempty"`
	Workspace      string   `json:"workspace"`
	WorkspaceID    string   `json:"workspace_id,omitempty"`
	ClaimsHeld     int      `json:"claims_held"`
	ClaimedTasks   []string `json:"claimed_tasks,omitempty"`
	ClaimsComplete bool     `json:"claims_complete"`
	NameReusable   bool     `json:"name_reusable"`
	Unreadable     []string `json:"unreadable,omitempty"`
}

var teamHumanAgentStatusCmd = &cobra.Command{
	Use:   "agent-status <name>",
	Short: "Read whether an agent still holds a certificate, a workspace, or task claims",
	Long: "Read the state of one agent across the stores retirement has to clear.\n\n" +
		"This reads and never writes. It exists so that the evidence an agent is\n" +
		"retired comes from somewhere other than the command that retired it.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanAgentStatus,
}

func runTeamHumanAgentStatus(cmd *cobra.Command, args []string) error {
	loadDotenvBestEffort()

	teamID := strings.TrimSpace(teamHumanAgentStatusTeamID)
	if teamID == "" {
		var err error
		teamID, err = activeTeamIDForHumanTeamCommand()
		if err != nil {
			return err
		}
	}
	domain, team, err := awid.ParseTeamID(teamID)
	if err != nil {
		return err
	}

	alias := strings.TrimSpace(args[0])
	if idx := strings.LastIndex(alias, "/"); idx >= 0 {
		alias = strings.TrimSpace(alias[idx+1:])
	}
	if alias == "" {
		return usageError("agent name is required")
	}

	workingDir, _ := os.Getwd()
	client, _, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out := teamAgentStatusOutput{TeamID: teamID, Alias: alias}
	readAgentCertificateState(ctx, &out, domain, team)
	readAgentCoordinationState(ctx, client, &out, alias)

	out.NameReusable = out.Certificate == agentCertificateNone && out.Workspace == agentWorkspaceAbsent
	switch {
	case out.Certificate == agentCertificateUnknown || out.Workspace == agentWorkspaceUnknown:
		out.State = agentStateUnknown
	case out.Certificate == agentCertificateNone && out.Workspace == agentWorkspaceAbsent && out.ClaimsHeld == 0:
		out.State = agentStateRetired
	default:
		out.State = agentStateActive
	}
	printOutput(out, formatTeamAgentStatus)
	return nil
}

// readAgentCertificateState answers whether the alias holds an active
// certificate.
//
// A 404 on the member lookup on its own does not establish that: an
// unreachable or misaddressed registry answers the same way. So the team itself
// is read first, and only a team that answers turns a member 404 into the
// established reading "no active certificate". Without that corroboration the
// state is reported unknown rather than guessed at.
func readAgentCertificateState(ctx context.Context, out *teamAgentStatusOutput, domain, team string) {
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		out.Certificate = agentCertificateUnknown
		out.Unreadable = append(out.Unreadable, fmt.Sprintf("certificate store: %v", err))
		return
	}
	registryURL := resolveTeamRemoveRegistryURL(registry)

	if _, err := registry.GetTeam(ctx, registryURL, domain, team); err != nil {
		out.Certificate = agentCertificateUnknown
		out.Unreadable = append(out.Unreadable, fmt.Sprintf(
			"certificate store: could not read team %s from %s, so an absent member cannot be told from an unreachable registry: %v",
			awid.BuildTeamID(domain, team), registryURL, err,
		))
		return
	}

	member, err := registry.ResolveTeamMember(ctx, registryURL, domain, team, out.Alias)
	if err == nil {
		out.Certificate = agentCertificateActive
		out.CertificateID = strings.TrimSpace(member.CertificateID)
		out.MemberAddress = strings.TrimSpace(member.MemberAddress)
		return
	}
	if status, ok := awid.HTTPStatusCode(err); ok && status == http.StatusNotFound {
		out.Certificate = agentCertificateNone
		return
	}
	out.Certificate = agentCertificateUnknown
	out.Unreadable = append(out.Unreadable, fmt.Sprintf("certificate store: %v", err))
}

// readAgentCoordinationState answers whether the alias still has a workspace
// record and what task claims are held under it.
func readAgentCoordinationState(ctx context.Context, client *aweb.Client, out *teamAgentStatusOutput, alias string) {
	resp, err := client.WorkspaceList(ctx, aweb.WorkspaceListParams{
		Alias:           alias,
		IncludePresence: false,
		Limit:           2,
	})
	if err != nil {
		out.Workspace = agentWorkspaceUnknown
		out.Unreadable = append(out.Unreadable, fmt.Sprintf("coordination store: %v", err))
		return
	}

	var matched *aweb.WorkspaceInfo
	for i := range resp.Workspaces {
		if strings.EqualFold(strings.TrimSpace(resp.Workspaces[i].Alias), alias) {
			matched = &resp.Workspaces[i]
			break
		}
	}
	if matched == nil {
		out.Workspace = agentWorkspaceAbsent
		out.ClaimsComplete = true
		return
	}

	out.Workspace = agentWorkspacePresent
	out.WorkspaceID = matched.WorkspaceID

	claims, err := client.ClaimsList(ctx, matched.WorkspaceID, 100)
	if err != nil {
		out.Unreadable = append(out.Unreadable, fmt.Sprintf("task claims: %v", err))
		return
	}
	out.ClaimsHeld = len(claims.Claims)
	// A truncated page would understate the claims held, and understating them is
	// the failure this command exists to prevent.
	out.ClaimsComplete = !claims.HasMore
	for _, claim := range claims.Claims {
		out.ClaimedTasks = append(out.ClaimedTasks, claim.TaskRef)
	}
}

func formatTeamAgentStatus(v any) string {
	out := v.(teamAgentStatusOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("State:       %s\n", out.State))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Agent:       %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Certificate: %s", out.Certificate))
	if strings.TrimSpace(out.CertificateID) != "" {
		sb.WriteString(" (" + out.CertificateID + ")")
	}
	sb.WriteString("\n")
	sb.WriteString(fmt.Sprintf("Workspace:   %s", out.Workspace))
	if strings.TrimSpace(out.WorkspaceID) != "" {
		sb.WriteString(" (" + out.WorkspaceID + ")")
	}
	sb.WriteString("\n")
	claims := fmt.Sprintf("%d", out.ClaimsHeld)
	if !out.ClaimsComplete {
		claims += " or more (listing truncated)"
	}
	if len(out.ClaimedTasks) > 0 {
		claims += ": " + strings.Join(out.ClaimedTasks, ", ")
	}
	sb.WriteString(fmt.Sprintf("Claims:      %s\n", claims))
	sb.WriteString(fmt.Sprintf("Name free:   %t\n", out.NameReusable))
	for _, unreadable := range out.Unreadable {
		sb.WriteString(fmt.Sprintf("Unread:      %s\n", unreadable))
	}
	return sb.String()
}
