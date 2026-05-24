package main

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type teamDeleteOutput struct {
	Status        string `json:"status"`
	TeamID        string `json:"team_id"`
	Domain        string `json:"domain"`
	Team          string `json:"team"`
	ControllerDID string `json:"controller_did"`
	RegistryURL   string `json:"registry_url"`
}

type teamDeleteOptions struct {
	Domain      string
	Team        string
	RegistryURL string
	Reason      string
}

var (
	teamDeleteTeam        string
	teamDeleteNamespace   string
	teamDeleteRegistryURL string
	teamDeleteReason      string
	teamDeleteCmd         = &cobra.Command{
		Use:   "delete",
		Short: "Delete an AWID team using the namespace controller key",
		Long: "Delete an AWID team using the local namespace controller key.\n\n" +
			"Delete-team requires the team's active certificates to be revoked first. It\n" +
			"does not delete the namespace or any unrelated address claims.",
		RunE: runTeamDelete,
	}
)

func init() {
	teamDeleteCmd.Flags().StringVar(&teamDeleteTeam, "team", "", "Team name")
	teamDeleteCmd.Flags().StringVar(&teamDeleteNamespace, "namespace", "", "Namespace domain")
	teamDeleteCmd.Flags().StringVar(&teamDeleteRegistryURL, "registry", "", "Registry origin override")
	teamDeleteCmd.Flags().StringVar(&teamDeleteReason, "reason", "", "Optional deletion reason recorded by the registry")
	teamCmd.AddCommand(teamDeleteCmd)
}

func runTeamDelete(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	out, err := executeTeamDelete(ctx, teamDeleteOptions{
		Domain:      teamDeleteNamespace,
		Team:        teamDeleteTeam,
		RegistryURL: teamDeleteRegistryURL,
		Reason:      teamDeleteReason,
	})
	if err != nil {
		return err
	}
	printOutput(out, formatTeamDelete)
	return nil
}

func executeTeamDelete(ctx context.Context, opts teamDeleteOptions) (teamDeleteOutput, error) {
	domain, err := normalizeIDCreateDomain(opts.Domain, false)
	if err != nil {
		return teamDeleteOutput{}, err
	}
	teamName := strings.ToLower(strings.TrimSpace(opts.Team))
	if teamName == "" {
		return teamDeleteOutput{}, usageError("--team is required")
	}
	if strings.Contains(teamName, "/") || strings.Contains(teamName, ":") {
		return teamDeleteOutput{}, usageError("--team must be a team name, not a full team id")
	}
	controllerKey, controllerDID, err := loadVerifiedNamespaceControllerKey(ctx, domain, opts.RegistryURL)
	if err != nil {
		return teamDeleteOutput{}, err
	}

	registry, err := newRegistryClientWithPreferredBaseURL(opts.RegistryURL)
	if err != nil {
		return teamDeleteOutput{}, err
	}
	registryURL, err := registry.DiscoverRegistry(ctx, domain)
	if err != nil {
		return teamDeleteOutput{}, fmt.Errorf("discover registry for %s: %w", domain, err)
	}

	if err := registry.DeleteTeam(ctx, registryURL, domain, teamName, controllerKey, opts.Reason); err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusConflict {
			return teamDeleteOutput{}, fmt.Errorf("delete team %s:%s: active certificates exist; run `aw id team remove-member` for active members first: %w", teamName, domain, err)
		}
		return teamDeleteOutput{}, fmt.Errorf("delete team %s:%s: %w", teamName, domain, err)
	}

	return teamDeleteOutput{
		Status:        "deleted",
		TeamID:        fmt.Sprintf("%s:%s", teamName, domain),
		Domain:        domain,
		Team:          teamName,
		ControllerDID: controllerDID,
		RegistryURL:   registryURL,
	}, nil
}

func formatTeamDelete(v any) string {
	out := v.(teamDeleteOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Deleted team %s\n", out.TeamID)
	fmt.Fprintf(&b, "  controller:    %s\n", out.ControllerDID)
	fmt.Fprintf(&b, "  registry:      %s\n", out.RegistryURL)
	return b.String()
}
