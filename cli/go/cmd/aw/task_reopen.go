package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskReopenCmd = &cobra.Command{
	Use:   "reopen <ref>",
	Short: "Reopen a closed task",
	Args:  cobra.ExactArgs(1),
	RunE:  runTaskReopen,
}

func init() {
	taskCmd.AddCommand(taskReopenCmd)
}

func runTaskReopen(cmd *cobra.Command, args []string) error {
	ref := args[0]

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	status := "open"
	req := &aweb.TaskUpdateRequest{Status: &status}
	resp, err := client.TaskUpdate(ctx, ref, req)
	if err != nil {
		var held *aweb.TaskHeldError
		if errors.As(err, &held) {
			return fmt.Errorf("task %s is held by another agent: %s", ref, held.Detail)
		}
		return fmt.Errorf("reopening task %s: %w", ref, err)
	}
	if resp.RetriedAfterNotFound {
		if verifyErr := verifyTaskUpdate(ctx, client, ref, req); verifyErr != nil {
			return fmt.Errorf("task %s still exists, but the retried reopen could not be verified: %w; inspect the task before retrying", ref, verifyErr)
		}
	}

	printOutput(resp, func(v any) string {
		r := v.(*aweb.TaskUpdateResponse)
		return fmt.Sprintf("✓ Reopened %s: %s\n", r.TaskRef, r.Title)
	})
	return nil
}
