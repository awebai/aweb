package main

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

var agentHomeFlag string

var agentCmd = &cobra.Command{
	Use:     "agent",
	Short:   "Inspect local materialized agents",
	Long:    "Inspect local materialized agent homes under agents/instances/<name>.",
	GroupID: groupCoordination,
	Args:    cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return cmd.Help()
	},
}

func init() {
	rootCmd.AddCommand(agentCmd)
}

func resolveAgentHome(name string) (string, error) {
	if name == "" {
		return "", usageError("agent name is required")
	}
	if strings.TrimSpace(agentHomeFlag) != "" {
		return filepath.Abs(agentHomeFlag)
	}
	if !isValidWorkspaceAlias(name) {
		return "", usageError("invalid agent name %q: must start with an alphanumeric and contain only alphanumerics, dashes, or underscores (max 64 chars); use --home for an explicit path", name)
	}
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(resolveRepoRoot(wd), "agents", "instances", name), nil
}
