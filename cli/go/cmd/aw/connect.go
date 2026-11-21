package main

import (
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var connectCmd = &cobra.Command{
	Use:   "connect",
	Short: "Unsupported legacy bootstrap-token command",
	RunE:  runConnect,
}

func init() {
	connectCmd.GroupID = groupWorkspace
	// Keep released flags recognizable while obsolete dashboard commands migrate.
	connectCmd.Flags().String("bootstrap-token", "", "Unsupported; use a dashboard setup key or aw init --join-from")
	connectCmd.Flags().String("address", "", "Legacy bootstrap address (unsupported)")
	connectCmd.Flags().String("mock-url", "", "Legacy bootstrap URL (unsupported)")
	connectCmd.Hidden = true
	rootCmd.AddCommand(connectCmd)
}

func runConnect(_ *cobra.Command, _ []string) error {
	return usageError("%s", awid.ErrBootstrapTokensUnsupported)
}
