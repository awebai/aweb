package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskListCmd = &cobra.Command{
	Use:   "list",
	Short: "List tasks",
	RunE:  runTaskList,
}

func init() {
	taskListCmd.Flags().String("status", "", "Filter by status (open, in_progress, closed, blocked)")
	taskListCmd.Flags().String("type", "", "Filter by type (task, bug, feature, epic)")
	taskListCmd.Flags().String("priority", "", "Filter by priority 0-4 (accepts P0-P4)")
	taskListCmd.Flags().String("labels", "", "Filter by labels (comma-separated)")
	taskListCmd.Flags().String("assignee", "", "Filter by assignee agent alias")
	taskCmd.AddCommand(taskListCmd)
}

func runTaskList(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	params := aweb.TaskListParams{}
	statusFilter := ""

	if v, _ := cmd.Flags().GetString("status"); v != "" {
		statusFilter = v
		if v != "blocked" {
			params.Status = v
		}
	}
	if v, _ := cmd.Flags().GetString("type"); v != "" {
		params.TaskType = v
	}
	if raw, _ := cmd.Flags().GetString("priority"); raw != "" {
		pv, err := parsePriority(raw)
		if err != nil {
			return err
		}
		params.Priority = &pv
	}
	if v, _ := cmd.Flags().GetString("labels"); v != "" {
		params.Labels = splitAndTrimLabels(v)
	}
	if v, _ := cmd.Flags().GetString("assignee"); v != "" {
		params.AssigneeAlias = v
	}

	var resp *aweb.TaskListResponse
	if statusFilter == "blocked" {
		resp, err = client.TaskListBlocked(ctx)
		if err != nil {
			return fmt.Errorf("listing blocked tasks: %w", err)
		}
		for i := range resp.Tasks {
			resp.Tasks[i].Status = "blocked"
		}
	} else {
		resp, err = client.TaskList(ctx, params)
		if err != nil {
			return fmt.Errorf("listing tasks: %w", err)
		}
	}

	printOutput(resp, func(v any) string {
		r := v.(*aweb.TaskListResponse)
		if len(r.Tasks) == 0 {
			return "No tasks found.\n"
		}
		var sb strings.Builder
		for _, t := range r.Tasks {
			sb.WriteString(formatTaskLine(t))
			sb.WriteString("\n")
		}
		return sb.String()
	})
	return nil
}
