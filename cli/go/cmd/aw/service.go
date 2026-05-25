package main

import (
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var (
	serviceInitServiceURL string
	serviceInitTeamID     string
	serviceInitRole       string
)

var serviceCmd = &cobra.Command{
	Use:   "service",
	Short: "Connect an existing AWID identity to a service",
	Long: "Connect an existing AWID identity and team certificate to an aw-compatible service.\n\n" +
		"Service commands do not create identities, register AWID teams, mutate team\n" +
		"membership, or call BYOD onboarding flows. Use `aw id team register` to add a\n" +
		"team projection to a service first, then run `aw service init` from each\n" +
		"certified agent workspace.",
}

var serviceInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize this workspace against a service using an existing team certificate",
	Long: "Initialize this workspace against a service using the existing .aw signing key\n" +
		"and team certificate in this directory. This command only connects this\n" +
		"workspace to the service; it does not create identities, create teams, or\n" +
		"change AWID team membership.",
	RunE: runServiceInit,
}

func init() {
	serviceCmd.GroupID = groupWorkspace
	serviceInitCmd.Flags().StringVar(&serviceInitServiceURL, "service", "", "Service URL to connect to")
	serviceInitCmd.Flags().StringVar(&serviceInitTeamID, "team", "", "Canonical AWID team id to activate before connecting")
	serviceInitCmd.Flags().StringVar(&serviceInitRole, "role", "", "Optional role name for this workspace")
	serviceCmd.AddCommand(serviceInitCmd)
	rootCmd.AddCommand(serviceCmd)
}

func runServiceInit(cmd *cobra.Command, args []string) error {
	if strings.TrimSpace(serviceInitServiceURL) == "" {
		return usageError("--service is required")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	if teamID := strings.TrimSpace(serviceInitTeamID); teamID != "" {
		if err := activateExistingTeamMembership(workingDir, teamID); err != nil {
			return err
		}
	}
	urls, err := resolveOnboardingServiceURLs(serviceInitServiceURL)
	if err != nil {
		return err
	}
	result, err := initCertificateConnectWithOptions(workingDir, urls.AwebURL, certificateConnectOptions{
		Role: strings.TrimSpace(serviceInitRole),
	})
	if err != nil {
		return err
	}
	printOutput(result, formatConnect)
	return nil
}

func activateExistingTeamMembership(workingDir, teamID string) error {
	teamState, err := requireTeamStateForMembership(workingDir)
	if err != nil {
		return err
	}
	if teamState.Membership(teamID) == nil {
		return usageError("team certificate for %s is not installed in this workspace; run `aw id team fetch-cert` first", teamID)
	}
	teamState.ActiveTeam = teamID
	return awconfig.SaveTeamState(workingDir, teamState)
}
