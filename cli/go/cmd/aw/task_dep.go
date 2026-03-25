package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskDepCmd = &cobra.Command{
	Use:   "dep",
	Short: "Manage task dependencies",
}

var taskDepAddCmd = &cobra.Command{
	Use:   "add <ref> <depends-on>",
	Short: "Add a dependency",
	Args:  cobra.ExactArgs(2),
	RunE:  runTaskDepAdd,
}

var taskDepRemoveCmd = &cobra.Command{
	Use:   "remove <ref> <dep-ref>",
	Short: "Remove a dependency",
	Args:  cobra.ExactArgs(2),
	RunE:  runTaskDepRemove,
}

var taskDepListCmd = &cobra.Command{
	Use:   "list <ref>",
	Short: "List dependencies for a task",
	Args:  cobra.ExactArgs(1),
	RunE:  runTaskDepList,
}

func init() {
	taskDepCmd.AddCommand(taskDepAddCmd, taskDepRemoveCmd, taskDepListCmd)
	taskCmd.AddCommand(taskDepCmd)
}

func runTaskDepAdd(cmd *cobra.Command, args []string) error {
	ref, dependsOn := args[0], args[1]

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := client.TaskAddDep(ctx, ref, &aweb.TaskAddDepRequest{DependsOn: dependsOn}); err != nil {
		return fmt.Errorf("adding dependency: %w", err)
	}

	printOutput(map[string]string{"ref": ref, "depends_on": dependsOn}, func(v any) string {
		return fmt.Sprintf("✓ %s now depends on %s\n", ref, dependsOn)
	})
	return nil
}

func runTaskDepRemove(cmd *cobra.Command, args []string) error {
	ref, depRef := args[0], args[1]

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := client.TaskRemoveDep(ctx, ref, depRef); err != nil {
		return fmt.Errorf("removing dependency: %w", err)
	}

	printOutput(map[string]string{"ref": ref, "removed": depRef}, func(v any) string {
		return fmt.Sprintf("✓ Removed dependency: %s no longer depends on %s\n", ref, depRef)
	})
	return nil
}

type taskDepListOutput struct {
	BlockedBy []aweb.TaskDepView `json:"blocked_by"`
	Blocks    []aweb.TaskDepView `json:"blocks"`
}

func runTaskDepList(cmd *cobra.Command, args []string) error {
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

	out := taskDepListOutput{BlockedBy: task.BlockedBy, Blocks: task.Blocks}
	printOutput(out, func(v any) string {
		o := v.(taskDepListOutput)
		if len(o.BlockedBy) == 0 && len(o.Blocks) == 0 {
			return "No dependencies.\n"
		}
		var sb strings.Builder
		if len(o.BlockedBy) > 0 {
			sb.WriteString("Blocked by:\n")
			for _, dep := range o.BlockedBy {
				sb.WriteString(fmt.Sprintf("  → %s: %s [%s]\n", dep.TaskRef, dep.Title, dep.Status))
			}
		}
		if len(o.Blocks) > 0 {
			sb.WriteString("Blocks:\n")
			for _, dep := range o.Blocks {
				sb.WriteString(fmt.Sprintf("  ← %s: %s [%s]\n", dep.TaskRef, dep.Title, dep.Status))
			}
		}
		return sb.String()
	})
	return nil
}
