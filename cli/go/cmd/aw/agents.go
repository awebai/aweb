package main

import (
	"github.com/spf13/cobra"
)

var identityCmd = &cobra.Command{
	Use:   "id",
	Short: "Identity lifecycle, registry, settings, and key management",
}

func init() {
	rootCmd.AddCommand(identityCmd)
}
