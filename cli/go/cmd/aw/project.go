package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

var projectCmd = &cobra.Command{
	Use:   "project",
	Short: "Show the current project",
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		c, err := resolveClient()
		if err != nil {
			return err
		}
		resp, err := c.GetCurrentProject(ctx)
		if err != nil {
			return err
		}
		printOutput(resp, formatProject)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(projectCmd)
}
