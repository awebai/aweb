package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var teamSpawnAuthorityTeamID string

var teamSpawnAuthorityCmd = &cobra.Command{
	Use:   "spawn-authority",
	Short: "Check whether the selected identity can create hosted spawn invites",
	Long: "Check hosted spawn authority for the selected identity and team.\n\n" +
		"Pass --team-id as the canonical <name>:<domain> team ID. If omitted, the selected team's canonical ID is used.\n" +
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

type teamSpawnAuthorityRequestError struct {
	status int
	cause  error
}

func (e *teamSpawnAuthorityRequestError) Error() string {
	switch e.status {
	case http.StatusUnprocessableEntity:
		return "spawn-authority request was rejected (HTTP 422); pass --team-id in canonical <name>:<domain> form and confirm the selected server supports canonical team IDs"
	case http.StatusForbidden:
		return "spawn-authority request was forbidden (HTTP 403); confirm the selected identity belongs to the requested team and is authorized to check its spawn authority"
	default:
		return "spawn-authority request failed"
	}
}

func (e *teamSpawnAuthorityRequestError) Unwrap() error { return e.cause }

func init() {
	teamSpawnAuthorityCmd.Flags().StringVar(&teamSpawnAuthorityTeamID, "team-id", "", "Canonical team ID (<name>:<domain>) to check (defaults to selected team)")
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
		if status, ok := awid.HTTPStatusCode(err); ok && (status == http.StatusUnprocessableEntity || status == http.StatusForbidden) {
			return &teamSpawnAuthorityRequestError{status: status, cause: err}
		}
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
