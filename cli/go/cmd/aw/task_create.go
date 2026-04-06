package main

import (
	"context"
	"fmt"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskCreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a new task",
	RunE:  runTaskCreate,
}

func init() {
	taskCreateCmd.Flags().String("title", "", "Task title (required)")
	taskCreateCmd.Flags().String("description", "", "Task description")
	taskCreateCmd.Flags().String("notes", "", "Task notes")
	taskCreateCmd.Flags().String("type", "", "Task type (task, bug, feature, epic)")
	taskCreateCmd.Flags().String("priority", "", "Priority 0-4 (accepts P0-P4)")
	taskCreateCmd.Flags().String("labels", "", "Comma-separated labels")
	taskCreateCmd.Flags().String("assignee", "", "Assignee agent alias")
	taskCreateCmd.Flags().String("parent", "", "Parent task ref")
	taskCmd.AddCommand(taskCreateCmd)
}

func runTaskCreate(cmd *cobra.Command, args []string) error {
	title, _ := cmd.Flags().GetString("title")
	if title == "" {
		return fmt.Errorf("--title is required")
	}

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	const defaultPriority = 2

	req := &aweb.TaskCreateRequest{
		Title:       title,
		Priority:    defaultPriority,
	}

	if v, _ := cmd.Flags().GetString("description"); v != "" {
		req.Description = v
	}
	if v, _ := cmd.Flags().GetString("notes"); v != "" {
		req.Notes = v
	}
	if v, _ := cmd.Flags().GetString("type"); v != "" {
		req.TaskType = v
	}
	if raw, _ := cmd.Flags().GetString("priority"); raw != "" {
		pv, err := parsePriority(raw)
		if err != nil {
			return err
		}
		req.Priority = pv
	}
	if v, _ := cmd.Flags().GetString("labels"); v != "" {
		req.Labels = splitAndTrimLabels(v)
	}
	if v, _ := cmd.Flags().GetString("assignee"); v != "" {
		req.AssigneeAlias = &v
	}
	if v, _ := cmd.Flags().GetString("parent"); v != "" {
		req.ParentTaskID = &v
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	task, err := client.TaskCreate(ctx, req)
	if err != nil {
		return fmt.Errorf("creating task: %w", err)
	}

	printOutput(task, func(v any) string {
		t := v.(*aweb.Task)
		return fmt.Sprintf("✓ Created %s: %s\n", t.TaskRef, t.Title)
	})
	return nil
}
