package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

var teamSpawnAuthorityTeamID string

var teamSpawnAuthorityCmd = &cobra.Command{
	Use:   "spawn-authority",
	Short: "Check whether the selected identity can create hosted spawn invites",
	Long: "Check hosted spawn authority for the selected identity and team.\n\n" +
		"This is a read-only proof against /api/v1/spawn/authority. It does not use or prove CLI human auth status.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTeamSpawnAuthority(cmd.Context(), cmd)
	},
}

type teamSpawnAuthorityOutput struct {
	TeamID       string `json:"team_id,omitempty"`
	ActorAgentID string `json:"actor_agent_id,omitempty"`
	AuthKind     string `json:"auth_kind,omitempty"`
	LiveAgent    bool   `json:"live_agent"`
	CanSpawn     bool   `json:"can_spawn"`
}

func init() {
	teamSpawnAuthorityCmd.Flags().StringVar(&teamSpawnAuthorityTeamID, "team-id", "", "Canonical team id to check (defaults to selected team)")
	teamSpawnAuthorityCmd.GroupID = teamGroupMembership
	teamHumanCmd.AddCommand(teamSpawnAuthorityCmd)
}

func runTeamSpawnAuthority(ctx context.Context, cmd *cobra.Command) error {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}
	teamID := strings.TrimSpace(teamSpawnAuthorityTeamID)
	if teamID == "" && sel != nil {
		teamID = strings.TrimSpace(sel.TeamID)
	}
	path := "/api/v1/spawn/authority"
	if teamID != "" {
		path += "?team_id=" + url.QueryEscape(teamID)
	}
	var out teamSpawnAuthorityOutput
	if err := client.Get(ctx, path, &out); err != nil {
		return err
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "can_spawn: %t\n", out.CanSpawn)
	if out.TeamID != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "team_id: %s\n", out.TeamID)
	}
	if out.ActorAgentID != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "actor_agent_id: %s\n", out.ActorAgentID)
	}
	if out.AuthKind != "" {
		fmt.Fprintf(cmd.OutOrStdout(), "auth_kind: %s\n", out.AuthKind)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "live_agent: %t\n", out.LiveAgent)
	return nil
}
