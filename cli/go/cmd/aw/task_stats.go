package main

import (
	"fmt"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskStatsCmd = &cobra.Command{
	Use:   "stats",
	Short: "Show task statistics",
	RunE:  runTaskStats,
}

func init() {
	taskCmd.AddCommand(taskStatsCmd)
}

type taskStatsOutput struct {
	Total      int `json:"total"`
	Open       int `json:"open"`
	InProgress int `json:"in_progress"`
	Blocked    int `json:"blocked"`
	Closed     int `json:"closed"`
}

func runTaskStats(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := commandAPIContext(cmd)
	defer cancel()

	resp, err := client.TaskList(ctx, aweb.TaskListParams{})
	if err != nil {
		return fmt.Errorf("listing tasks: %w", err)
	}
	blockedResp, err := client.TaskListBlocked(ctx)
	if err != nil {
		return fmt.Errorf("listing blocked tasks: %w", err)
	}

	blockedRefs := make(map[string]struct{}, len(blockedResp.Tasks))
	for _, task := range blockedResp.Tasks {
		blockedRefs[task.TaskRef] = struct{}{}
	}

	var stats taskStatsOutput
	stats.Blocked = len(blockedRefs)
	allRefs := make(map[string]struct{}, len(resp.Tasks)+len(blockedRefs))
	for _, t := range resp.Tasks {
		allRefs[t.TaskRef] = struct{}{}
		if _, blocked := blockedRefs[t.TaskRef]; blocked {
			continue
		}
		switch t.Status {
		case "open":
			stats.Open++
		case "in_progress":
			stats.InProgress++
		case "closed":
			stats.Closed++
		}
	}
	for ref := range blockedRefs {
		allRefs[ref] = struct{}{}
	}
	stats.Total = len(allRefs)

	printOutput(stats, func(v any) string {
		s := v.(taskStatsOutput)
		return fmt.Sprintf("Total: %d\n  Open: %d\n  In progress: %d\n  Blocked: %d\n  Closed: %d\n",
			s.Total, s.Open, s.InProgress, s.Blocked, s.Closed)
	})
	return nil
}
