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

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
