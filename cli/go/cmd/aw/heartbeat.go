package main

import (
	"context"
	"time"

	"github.com/spf13/cobra"
)

var heartbeatCmd = &cobra.Command{
	Use:   "heartbeat",
	Short: "Send an explicit presence heartbeat",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveClient()
		if err != nil {
			return err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		resp, err := client.Heartbeat(ctx)
		if err != nil {
			return err
		}
		printJSON(resp)
		return nil
	},
}

func init() {
	rootCmd.AddCommand(heartbeatCmd)
}
