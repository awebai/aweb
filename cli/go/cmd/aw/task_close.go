package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskCloseCmd = &cobra.Command{
	Use:   "close <ref> [<ref2> ...]",
	Short: "Close one or more tasks",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTaskClose,
}

func init() {
	taskCloseCmd.Flags().String("reason", "", "Reason for closing (replaces notes)")
	taskCmd.AddCommand(taskCloseCmd)
}

type taskCloseOutput struct {
	Closed   []aweb.TaskUpdateResponse `json:"closed"`
	Failures []taskCloseFailure        `json:"failures,omitempty"`
}

type taskCloseFailure struct {
	Ref   string `json:"ref"`
	Error string `json:"error"`
}

func runTaskClose(cmd *cobra.Command, args []string) error {
	reason, _ := cmd.Flags().GetString("reason")

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	result := taskCloseOutput{
		Closed: make([]aweb.TaskUpdateResponse, 0),
	}

	for _, ref := range args {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)

		status := "closed"
		req := &aweb.TaskUpdateRequest{Status: &status}
		if reason != "" {
			req.Notes = &reason
		}

		resp, err := client.TaskUpdate(ctx, ref, req)
		cancel()
		if err != nil {
			result.Failures = append(result.Failures, taskCloseFailure{Ref: ref, Error: err.Error()})
			continue
		}
		result.Closed = append(result.Closed, *resp)
	}

	printOutput(result, formatTaskCloseOutput)

	if len(result.Failures) > 0 {
		return fmt.Errorf("failed to close %d of %d tasks", len(result.Failures), len(args))
	}
	return nil
}

func formatTaskCloseOutput(v any) string {
	r := v.(taskCloseOutput)
	var sb strings.Builder
	for _, closed := range r.Closed {
		sb.WriteString(fmt.Sprintf("✓ Closed %s: %s\n", closed.TaskRef, closed.Title))
		for _, ac := range closed.AutoClosed {
			sb.WriteString(fmt.Sprintf("  ✓ Auto-closed %s: %s\n", ac.TaskRef, ac.Title))
		}
	}
	for _, fail := range r.Failures {
		sb.WriteString(fmt.Sprintf("✗ Failed to close %s: %s\n", fail.Ref, fail.Error))
	}
	return sb.String()
}
