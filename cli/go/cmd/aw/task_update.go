package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskUpdateCmd = &cobra.Command{
	Use:   "update <ref>",
	Short: "Update a task",
	Args:  cobra.ExactArgs(1),
	RunE:  runTaskUpdate,
}

func init() {
	taskUpdateCmd.Flags().String("status", "", "Status (open, in_progress, closed)")
	taskUpdateCmd.Flags().String("title", "", "Title")
	taskUpdateCmd.Flags().String("description", "", "Description")
	taskUpdateCmd.Flags().String("notes", "", "Notes")
	taskUpdateCmd.Flags().String("type", "", "Type (task, bug, feature, epic)")
	taskUpdateCmd.Flags().String("priority", "", "Priority 0-4 (accepts P0-P4)")
	taskUpdateCmd.Flags().String("labels", "", "Comma-separated labels")
	taskUpdateCmd.Flags().String("assignee", "", "Assignee agent alias")
	taskCmd.AddCommand(taskUpdateCmd)
}

func runTaskUpdate(cmd *cobra.Command, args []string) error {
	ref := args[0]

	req := &aweb.TaskUpdateRequest{}
	hasUpdate := false

	if v, _ := cmd.Flags().GetString("status"); v != "" {
		if v == "blocked" {
			return fmt.Errorf("invalid status: blocked is derived from task dependencies; use `aw work blocked` or `aw task list --status blocked`")
		}
		req.Status = &v
		hasUpdate = true
	}
	if v, _ := cmd.Flags().GetString("title"); v != "" {
		req.Title = &v
		hasUpdate = true
	}
	if v, _ := cmd.Flags().GetString("description"); v != "" {
		req.Description = &v
		hasUpdate = true
	}
	if v, _ := cmd.Flags().GetString("notes"); v != "" {
		req.Notes = &v
		hasUpdate = true
	}
	if v, _ := cmd.Flags().GetString("type"); v != "" {
		req.TaskType = &v
		hasUpdate = true
	}
	if raw, _ := cmd.Flags().GetString("priority"); raw != "" {
		pv, err := parsePriority(raw)
		if err != nil {
			return err
		}
		req.Priority = &pv
		hasUpdate = true
	}
	if v, _ := cmd.Flags().GetString("labels"); v != "" {
		req.Labels = splitAndTrimLabels(v)
		hasUpdate = true
	}
	if v, _ := cmd.Flags().GetString("assignee"); v != "" {
		req.AssigneeAlias = &v
		hasUpdate = true
	}

	if !hasUpdate {
		return fmt.Errorf("no fields to update — use --status, --title, --description, --notes, --type, --priority, --labels, or --assignee")
	}

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TaskUpdate(ctx, ref, req)
	if err != nil {
		var held *aweb.TaskHeldError
		if errors.As(err, &held) {
			return fmt.Errorf("task %s is held by another agent: %s", ref, held.Detail)
		}
		return fmt.Errorf("updating task %s: %w", ref, err)
	}

	printOutput(resp, func(v any) string {
		r := v.(*aweb.TaskUpdateResponse)
		output := fmt.Sprintf("✓ Updated %s: %s\n", r.TaskRef, r.Title)
		if len(r.AutoClosed) > 0 {
			output += fmt.Sprintf("\nAuto-closed %d descendant(s):\n", len(r.AutoClosed))
			for _, t := range r.AutoClosed {
				output += fmt.Sprintf("  ✓ %s: %s\n", t.TaskRef, t.Title)
			}
		}
		return output
	})
	return nil
}
