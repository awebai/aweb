package main

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

var taskDeleteCmd = &cobra.Command{
	Use:   "delete <ref>",
	Short: "Delete a task",
	Args:  cobra.ExactArgs(1),
	RunE:  runTaskDelete,
}

func init() {
	taskCmd.AddCommand(taskDeleteCmd)
}

func runTaskDelete(cmd *cobra.Command, args []string) error {
	ref := args[0]

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := client.TaskDelete(ctx, ref); err != nil {
		return fmt.Errorf("deleting task: %w", err)
	}

	printOutput(map[string]string{"deleted": ref}, func(v any) string {
		return fmt.Sprintf("✓ Deleted %s\n", ref)
	})
	return nil
}
