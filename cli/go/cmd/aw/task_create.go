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
	taskCreateCmd.Flags().String("description", "", shellExpandedInlineHelp("Task description", "--description-file"))
	taskCreateCmd.Flags().String("description-file", "", safeFileInputHelp("task description"))
	taskCreateCmd.Flags().String("notes", "", shellExpandedInlineHelp("Task notes", "--notes-file"))
	taskCreateCmd.Flags().String("notes-file", "", safeFileInputHelp("task notes"))
	taskCreateCmd.MarkFlagsMutuallyExclusive("description", "description-file")
	taskCreateCmd.MarkFlagsMutuallyExclusive("notes", "notes-file")
	taskCreateCmd.Flags().String("type", "", "Task type (task, bug, feature, epic)")
	taskCreateCmd.Flags().String("priority", "", "Priority 0-4 (accepts P0-P4)")
	taskCreateCmd.Flags().String("labels", "", "Comma-separated labels")
	taskCreateCmd.Flags().String("assignee", "", "Assignee agent name")
	taskCreateCmd.Flags().String("parent", "", "Parent task ref")
	taskCmd.AddCommand(taskCreateCmd)
}

func runTaskCreate(cmd *cobra.Command, args []string) error {
	title, _ := cmd.Flags().GetString("title")
	if title == "" {
		return fmt.Errorf("--title is required")
	}

	description, descriptionSet, err := resolveLongTextFlags(cmd, "description", "description-file")
	if err != nil {
		return err
	}
	notes, notesSet, err := resolveLongTextFlags(cmd, "notes", "notes-file")
	if err != nil {
		return err
	}

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	const defaultPriority = 2

	req := &aweb.TaskCreateRequest{
		Title:    title,
		Priority: defaultPriority,
	}

	if descriptionSet && description != "" {
		req.Description = description
	}
	if notesSet && notes != "" {
		req.Notes = notes
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
