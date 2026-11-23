package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var teamClaimHumanRequestInput struct {
	Team, Namespace, Username, Email, Timestamp string
}

// teamClaimHumanRequestCmd produces the shared artifact only. Possession of the
// local key does not establish that the registry still names it as controller.
var teamClaimHumanRequestCmd = &cobra.Command{
	Use:   "claim-human-request",
	Short: "Sign a prospective ownership claim with a local team controller key",
	Long: "Write a controller claim JSON artifact to stdout. No member credential is created.\n" +
		"Cloud checks the registry's current controller before accepting ownership.\n" +
		"Submit this file from an existing member home with aw claim-human --controller-claim-file <file>.\n" +
		"The artifact is valid for five minutes; regenerate it if it expires.",
	Args: cobra.NoArgs,
	RunE: runTeamClaimHumanRequest,
}

func init() {
	flags := teamClaimHumanRequestCmd.Flags()
	flags.StringVar(&teamClaimHumanRequestInput.Team, "team", "", "Team name")
	flags.StringVar(&teamClaimHumanRequestInput.Namespace, "namespace", "", "Namespace domain")
	flags.StringVar(&teamClaimHumanRequestInput.Username, "username", "", "Prospective owner's username")
	flags.StringVar(&teamClaimHumanRequestInput.Email, "email", "", "Prospective owner's email")
	flags.StringVar(&teamClaimHumanRequestInput.Timestamp, "timestamp", "", "RFC3339 timestamp (defaults to now; five-minute window)")
}

func runTeamClaimHumanRequest(cmd *cobra.Command, args []string) error {
	team := strings.ToLower(strings.TrimSpace(teamClaimHumanRequestInput.Team))
	domain := awconfig.NormalizeDomain(teamClaimHumanRequestInput.Namespace)
	if team == "" || domain == "" {
		return usageError("--team and --namespace are required")
	}
	teamID := awid.BuildTeamID(domain, team)
	if _, _, err := awid.ParseTeamID(teamID); err != nil {
		return usageError("select a canonical team with --team and --namespace: %v", err)
	}
	target := normalizeClaimHumanTarget(claimHumanTarget{
		Username: teamClaimHumanRequestInput.Username, Email: teamClaimHumanRequestInput.Email,
	})
	if target.Username == "" || target.Email == "" {
		return usageError("--username and --email are required")
	}
	now := time.Now().UTC()
	timestamp := strings.TrimSpace(teamClaimHumanRequestInput.Timestamp)
	if timestamp == "" {
		timestamp = now.Format(time.RFC3339)
	}
	if err := checkClaimHumanTimestamp(claimHumanTimestampInput{Timestamp: timestamp, Now: now}); err != nil {
		return err
	}
	key, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return teamKeyLoadError(teamID, domain, err)
	}
	artifact, err := (awid.UnownedTeamClaimRequest{
		AWIDTeamID: teamID, Email: target.Email, Username: target.Username, Timestamp: timestamp,
	}).Sign(key)
	if err != nil {
		return err
	}
	encoded, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("encode controller claim: %w", err)
	}
	_, err = fmt.Fprintln(cmd.OutOrStdout(), string(encoded))
	return err
}
