package main

import (
	"context"
	"fmt"
	"time"

	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var controlCmd = &cobra.Command{
	Use:   "control",
	Short: "Send control signals to agents",
}

func controlSignalCmd(signal awid.ControlSignal) *cobra.Command {
	var agentAlias string

	cmd := &cobra.Command{
		Use:   string(signal),
		Short: fmt.Sprintf("Send %s signal to an agent", signal),
		RunE: func(cmd *cobra.Command, args []string) error {
			if agentAlias == "" {
				return usageError("missing required flag: --agent")
			}

			client, err := resolveClient()
			if err != nil {
				return err
			}

			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			resp, err := client.SendControlSignal(ctx, agentAlias, signal)
			if err != nil {
				return err
			}

			printOutput(resp, func(v any) string {
				r := v.(*awid.SendControlSignalResponse)
				return fmt.Sprintf("Sent %s signal to %s (signal_id=%s)\n", r.Signal, agentAlias, r.SignalID)
			})
			return nil
		},
	}

	cmd.Flags().StringVar(&agentAlias, "agent", "", "Agent alias to send signal to")
	return cmd
}

func init() {
	controlCmd.AddCommand(
		controlSignalCmd(awid.ControlSignalPause),
		controlSignalCmd(awid.ControlSignalResume),
		controlSignalCmd(awid.ControlSignalInterrupt),
	)
	rootCmd.AddCommand(controlCmd)
}
