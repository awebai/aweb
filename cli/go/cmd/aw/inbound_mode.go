package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type inboundModeOutput struct {
	AgentID      string `json:"agent_id,omitempty"`
	TeamID       string `json:"team_id,omitempty"`
	Alias        string `json:"alias,omitempty"`
	IdentityMode string `json:"identity_scope,omitempty"`
	InboundMode  string `json:"inbound_mode,omitempty"`
	Label        string `json:"label,omitempty"`
	Configurable bool   `json:"configurable"`
}

var inboundModeCmd = &cobra.Command{
	Use:   "inbound-mode [open|team-and-contacts]",
	Short: "Show or set the current agent's inbound delivery mode",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runInboundMode,
}

func init() {
	rootCmd.AddCommand(inboundModeCmd)
}

func runInboundMode(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	c, _, err := resolveClientSelection()
	if err != nil {
		return err
	}
	var resp *awid.AgentInboundModeResponse
	if len(args) == 0 {
		resp, err = c.Client.GetMyInboundMode(ctx)
	} else {
		mode, modeErr := normalizeInboundModeCLIValue(args[0])
		if modeErr != nil {
			return modeErr
		}
		resp, err = c.Client.UpdateMyInboundMode(ctx, mode)
	}
	if err != nil {
		return err
	}
	printOutput(newInboundModeOutput(resp), formatInboundMode)
	return nil
}

func normalizeInboundModeCLIValue(value string) (string, error) {
	switch strings.TrimSpace(strings.ToLower(value)) {
	case "open", "all":
		return "open", nil
	case "team-and-contacts", "team_and_contacts", "contacts-only", "contacts_only":
		return "team_and_contacts", nil
	case "":
		return "", usageError("inbound mode is required")
	default:
		return "", usageError("inbound mode must be one of {open, team-and-contacts}; got %q", value)
	}
}

func inboundModeLabel(mode string) string {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "open":
		return "All"
	case "team_and_contacts", "contacts_only":
		return "Team and contacts"
	default:
		return strings.TrimSpace(mode)
	}
}

func newInboundModeOutput(resp *awid.AgentInboundModeResponse) inboundModeOutput {
	if resp == nil {
		return inboundModeOutput{}
	}
	return inboundModeOutput{
		AgentID:      strings.TrimSpace(resp.AgentID),
		TeamID:       strings.TrimSpace(resp.TeamID),
		Alias:        strings.TrimSpace(resp.Alias),
		IdentityMode: strings.TrimSpace(resp.IdentityScope),
		InboundMode:  strings.TrimSpace(resp.InboundMode),
		Label:        inboundModeLabel(resp.InboundMode),
		Configurable: resp.Configurable,
	}
}

func formatInboundMode(v any) string {
	out := v.(inboundModeOutput)
	var sb strings.Builder
	if out.Alias != "" {
		sb.WriteString(fmt.Sprintf("Name:       %s\n", out.Alias))
	}
	if out.AgentID != "" {
		sb.WriteString(fmt.Sprintf("Agent ID:   %s\n", out.AgentID))
	}
	if out.TeamID != "" {
		sb.WriteString(fmt.Sprintf("Team:       %s\n", out.TeamID))
	}
	if out.IdentityMode != "" {
		sb.WriteString(fmt.Sprintf("Identity:   %s\n", out.IdentityMode))
	}
	if out.InboundMode != "" {
		sb.WriteString(fmt.Sprintf("Inbound:    %s (%s)\n", out.Label, out.InboundMode))
	}
	if !out.Configurable {
		sb.WriteString("Config:     local identities do not have configurable public inbound delivery\n")
	}
	return sb.String()
}
