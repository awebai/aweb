package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type teamRequestOutput struct {
	Command string `json:"command"`
	TeamID  string `json:"team_id"`
	Team    string `json:"team"`
	Domain  string `json:"domain"`
	DIDKey  string `json:"did_key"`
	Alias   string `json:"alias"`
	DIDAW   string `json:"did_aw,omitempty"`
	Address string `json:"address,omitempty"`
}

var (
	teamRequestTeamID string
	teamRequestAlias  string
)

var teamRequestCmd = &cobra.Command{
	Use:   "request",
	Short: "Print the add-member command the team owner should run",
	RunE:  runTeamRequest,
}

func init() {
	teamRequestCmd.Flags().StringVar(&teamRequestTeamID, "team", "", "Canonical team ID (<name>:<domain>)")
	teamRequestCmd.Flags().StringVar(&teamRequestAlias, "alias", "", "Suggested alias for the new team membership")
	teamCmd.AddCommand(teamRequestCmd)
}

func runTeamRequest(cmd *cobra.Command, args []string) error {
	teamID := strings.TrimSpace(teamRequestTeamID)
	alias := strings.TrimSpace(teamRequestAlias)
	if teamID == "" {
		return usageError("--team is required")
	}
	if alias == "" {
		return usageError("--alias is required")
	}
	teamDomain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return usageError("invalid --team %q: %v", teamID, err)
	}

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}

	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(workingDir))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return usageError("current identity has no local signing key")
		}
		return fmt.Errorf("load signing key: %w", err)
	}
	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))

	commandParts := []string{
		"aw", "id", "team", "add-member",
		"--team", teamName,
		"--namespace", teamDomain,
		"--did", didKey,
		"--alias", alias,
	}

	out := teamRequestOutput{
		TeamID: teamID,
		Team:   teamName,
		Domain: teamDomain,
		DIDKey: didKey,
		Alias:  alias,
	}

	identity, err := loadOptionalTeamRequestIdentity(workingDir)
	if err != nil {
		return err
	}
	if identity != nil && strings.TrimSpace(identity.Lifetime) == awid.LifetimePersistent {
		stableID := strings.TrimSpace(identity.StableID)
		address := strings.TrimSpace(identity.Address)
		if stableID == "" || address == "" {
			return usageError("current persistent identity is missing stable_id or address; restore .aw/identity.yaml or run `aw id create` again")
		}
		commandParts = append(commandParts,
			"--lifetime", awid.LifetimePersistent,
			"--did-aw", stableID,
			"--address", address,
		)
		out.DIDAW = stableID
		out.Address = address
	}

	out.Command = strings.Join(commandParts, " ")
	printOutput(out, formatTeamRequest)
	return nil
}

func loadOptionalTeamRequestIdentity(workingDir string) (*awconfig.ResolvedIdentity, error) {
	identity, err := awconfig.ResolveIdentity(workingDir)
	if err == nil {
		if err := validateResolvedIdentity(identity); err != nil {
			return nil, err
		}
		return identity, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, err
}

func formatTeamRequest(v any) string {
	out := v.(teamRequestOutput)
	return strings.TrimSpace(out.Command) + "\n"
}
