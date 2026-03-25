package main

import (
	"context"
	"fmt"
	"time"

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

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TaskList(ctx, aweb.TaskListParams{})
	if err != nil {
		return fmt.Errorf("listing tasks: %w", err)
	}

	var stats taskStatsOutput
	for _, t := range resp.Tasks {
		stats.Total++
		switch t.Status {
		case "open":
			stats.Open++
		case "in_progress":
			stats.InProgress++
		case "blocked":
			stats.Blocked++
		case "closed":
			stats.Closed++
		}
	}

	printOutput(stats, func(v any) string {
		s := v.(taskStatsOutput)
		return fmt.Sprintf("Total: %d\n  Open: %d\n  In progress: %d\n  Blocked: %d\n  Closed: %d\n",
			s.Total, s.Open, s.InProgress, s.Blocked, s.Closed)
	})
	return nil
}
