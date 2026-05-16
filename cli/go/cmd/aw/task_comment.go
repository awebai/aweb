package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskCommentCmd = &cobra.Command{
	Use:   "comment",
	Short: "Manage task comments",
}

var taskCommentAddCmd = &cobra.Command{
	Use:   "add <ref> <body>",
	Short: "Add a comment to a task",
	Args:  cobra.ExactArgs(2),
	RunE:  runTaskCommentAdd,
}

var taskCommentListCmd = &cobra.Command{
	Use:   "list <ref>",
	Short: "List comments on a task",
	Args:  cobra.ExactArgs(1),
	RunE:  runTaskCommentList,
}

func init() {
	taskCommentCmd.AddCommand(taskCommentAddCmd, taskCommentListCmd)
	taskCmd.AddCommand(taskCommentCmd)
}

func runTaskCommentAdd(cmd *cobra.Command, args []string) error {
	ref, body := args[0], args[1]

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	comment, err := client.TaskCommentCreate(ctx, ref, &aweb.TaskCommentCreateRequest{Body: body})
	if err != nil {
		return fmt.Errorf("adding comment to %s: %w", ref, err)
	}

	printOutput(comment, func(v any) string {
		return fmt.Sprintf("✓ Added comment to %s\n", ref)
	})
	return nil
}

func runTaskCommentList(cmd *cobra.Command, args []string) error {
	ref := args[0]

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TaskCommentList(ctx, ref)
	if err != nil {
		return fmt.Errorf("listing comments for %s: %w", ref, err)
	}

	printOutput(resp, func(v any) string {
		r := v.(*aweb.TaskCommentListResponse)
		return formatTaskComments(r.Comments)
	})
	return nil
}
