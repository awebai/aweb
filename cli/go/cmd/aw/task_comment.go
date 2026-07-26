package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskCommentCmd = &cobra.Command{
	Use:   "comment",
	Short: "Manage task comments",
}

var taskCommentAddCmd = &cobra.Command{
	Use:   "add <ref> [body]",
	Short: "Add a comment to a task",
	Args:  cobra.RangeArgs(1, 2),
	RunE:  runTaskCommentAdd,
}

var taskCommentListCmd = &cobra.Command{
	Use:   "list <ref>",
	Short: "List comments on a task",
	Args:  cobra.ExactArgs(1),
	RunE:  runTaskCommentList,
}

func init() {
	taskCommentAddCmd.Flags().String("body", "", "Comment body")
	taskCommentAddCmd.Flags().String("body-file", "", "Read comment body from file")
	taskCommentAddCmd.MarkFlagsMutuallyExclusive("body", "body-file")
	taskCommentCmd.AddCommand(taskCommentAddCmd, taskCommentListCmd)
	taskCmd.AddCommand(taskCommentCmd)
}

func runTaskCommentAdd(cmd *cobra.Command, args []string) error {
	ref := args[0]
	body := ""
	if len(args) == 2 {
		if cmd.Flags().Changed("body") || cmd.Flags().Changed("body-file") {
			return fmt.Errorf("comment body must be provided either positionally, with --body, or with --body-file")
		}
		body = args[1]
	} else if cmd.Flags().Changed("body") {
		body, _ = cmd.Flags().GetString("body")
	} else if cmd.Flags().Changed("body-file") {
		bodyPath, _ := cmd.Flags().GetString("body-file")
		data, err := os.ReadFile(bodyPath)
		if err != nil {
			return fmt.Errorf("reading comment body file: %w", err)
		}
		body = string(data)
	}
	if strings.TrimSpace(body) == "" {
		return fmt.Errorf("comment body is required")
	}

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
