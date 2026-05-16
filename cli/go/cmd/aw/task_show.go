package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskShowCmd = &cobra.Command{
	Use:   "show <ref>",
	Short: "Show task details",
	Args:  cobra.ExactArgs(1),
	RunE:  runTaskShow,
}

func init() {
	taskCmd.AddCommand(taskShowCmd)
}

func runTaskShow(cmd *cobra.Command, args []string) error {
	ref := args[0]

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	task, err := client.TaskGet(ctx, ref)
	if err != nil {
		return fmt.Errorf("getting task %s: %w", ref, err)
	}
	comments, err := client.TaskCommentList(ctx, ref)
	if err != nil {
		return fmt.Errorf("getting comments for task %s: %w", ref, err)
	}
	task.Comments = comments.Comments

	printOutput(task, func(v any) string {
		return formatTaskDetail(v.(*aweb.Task))
	})
	return nil
}
