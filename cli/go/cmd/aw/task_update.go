package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
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
	taskUpdateCmd.Flags().String("description", "", shellExpandedInlineHelp("Description", "--description-file"))
	taskUpdateCmd.Flags().String("description-file", "", safeFileInputHelp("task description"))
	taskUpdateCmd.Flags().String("notes", "", shellExpandedInlineHelp("Notes", "--notes-file"))
	taskUpdateCmd.Flags().String("notes-file", "", safeFileInputHelp("task notes"))
	taskUpdateCmd.MarkFlagsMutuallyExclusive("description", "description-file")
	taskUpdateCmd.MarkFlagsMutuallyExclusive("notes", "notes-file")
	taskUpdateCmd.Flags().String("type", "", "Type (task, bug, feature, epic)")
	taskUpdateCmd.Flags().String("priority", "", "Priority 0-4 (accepts P0-P4)")
	taskUpdateCmd.Flags().String("labels", "", "Comma-separated labels")
	taskUpdateCmd.Flags().String("assignee", "", "Assignee agent name (empty to unassign)")
	taskUpdateCmd.Flags().String("parent", "", "Parent task ref (empty to make root)")
	taskCmd.AddCommand(taskUpdateCmd)
}

func runTaskUpdate(cmd *cobra.Command, args []string) error {
	ref := args[0]

	description, descriptionSet, err := resolveLongTextFlags(cmd, "description", "description-file")
	if err != nil {
		return err
	}
	notes, notesSet, err := resolveLongTextFlags(cmd, "notes", "notes-file")
	if err != nil {
		return err
	}

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
	if descriptionSet && description != "" {
		req.Description = &description
		hasUpdate = true
	}
	if notesSet && notes != "" {
		req.Notes = &notes
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
	if cmd.Flags().Changed("assignee") {
		v, _ := cmd.Flags().GetString("assignee")
		req.AssigneeAlias = &v
		hasUpdate = true
	}
	if cmd.Flags().Changed("parent") {
		v, _ := cmd.Flags().GetString("parent")
		req.ParentTaskID = &v
		hasUpdate = true
	}

	if !hasUpdate {
		return fmt.Errorf("no fields to update — use --status, --title, --description, --notes, --type, --priority, --labels, --assignee, or --parent")
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
	if resp.RetriedAfterNotFound {
		if verifyErr := verifyTaskUpdate(ctx, client, ref, req); verifyErr != nil {
			return fmt.Errorf("task %s still exists, but the retried update could not be verified: %w; inspect the task before retrying", ref, verifyErr)
		}
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

func verifyTaskUpdate(ctx context.Context, client *aweb.Client, ref string, req *aweb.TaskUpdateRequest) error {
	task, err := client.TaskGet(ctx, ref)
	if err != nil {
		return err
	}
	if req.Title != nil && task.Title != *req.Title {
		return fmt.Errorf("title is %q, want %q", task.Title, *req.Title)
	}
	if req.Description != nil && task.Description != *req.Description {
		return fmt.Errorf("description does not match")
	}
	if req.Notes != nil && task.Notes != *req.Notes {
		return fmt.Errorf("notes do not match")
	}

	if req.Status != nil && task.Status != *req.Status {
		return fmt.Errorf("status is %q, want %q", task.Status, *req.Status)
	}
	if req.TaskType != nil && task.TaskType != *req.TaskType {
		return fmt.Errorf("type is %q, want %q", task.TaskType, *req.TaskType)
	}
	if req.Priority != nil && task.Priority != *req.Priority {
		return fmt.Errorf("priority is %d, want %d", task.Priority, *req.Priority)
	}
	if req.Labels != nil && !slices.Equal(task.Labels, req.Labels) {
		return fmt.Errorf("labels do not match")
	}
	if req.AssigneeAlias != nil {
		if *req.AssigneeAlias == "" {
			if task.AssigneeAlias != nil {
				return fmt.Errorf("task remains assigned")
			}
		} else if task.AssigneeAlias == nil || *task.AssigneeAlias != *req.AssigneeAlias {
			return fmt.Errorf("assignee does not match")
		}
	}
	if req.ParentTaskID != nil {
		if *req.ParentTaskID == "" {
			if task.ParentTaskID != nil {
				return fmt.Errorf("task remains parented")
			}
		} else {
			parent, err := client.TaskGet(ctx, *req.ParentTaskID)
			if err != nil {
				return fmt.Errorf("resolving updated parent: %w", err)
			}
			if task.ParentTaskID == nil || *task.ParentTaskID != parent.TaskID {
				return fmt.Errorf("parent does not match")
			}
		}
	}
	return nil
}
