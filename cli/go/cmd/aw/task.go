package main

import (
	"fmt"
	"strconv"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/spf13/cobra"
)

var taskCmd = &cobra.Command{
	Use:   "task",
	Short: "Manage tasks",
}

func init() {
	rootCmd.AddCommand(taskCmd)
}

// --- Shared formatting ---

func priorityIcon(p int) string {
	if p <= 2 {
		return "●"
	}
	return "○"
}

func formatTaskLine(t aweb.TaskSummary) string {
	icon := priorityIcon(t.Priority)
	return fmt.Sprintf("%s %s [%s P%d] [%s] - %s",
		icon, t.TaskRef, icon, t.Priority, t.TaskType, t.Title)
}

func formatTaskDetail(t *aweb.Task) string {
	var sb strings.Builder

	icon := priorityIcon(t.Priority)
	statusLabel := strings.ToUpper(t.Status)
	sb.WriteString(fmt.Sprintf("%s %s · %s   [%s P%d · %s]\n",
		icon, t.TaskRef, t.Title, icon, t.Priority, statusLabel))
	sb.WriteString(fmt.Sprintf("Type: %s\n", t.TaskType))
	sb.WriteString(fmt.Sprintf("Created: %s · Updated: %s\n", formatDate(t.CreatedAt), formatDate(t.UpdatedAt)))

	if t.Description != "" {
		sb.WriteString(fmt.Sprintf("\nDESCRIPTION\n%s\n", t.Description))
	}

	if t.Notes != "" {
		sb.WriteString(fmt.Sprintf("\nNOTES\n%s\n", t.Notes))
	}

	if len(t.BlockedBy) > 0 {
		sb.WriteString("\nBLOCKED BY\n")
		for _, dep := range t.BlockedBy {
			sb.WriteString(fmt.Sprintf("  → ○ %s: %s [%s]\n", dep.TaskRef, dep.Title, dep.Status))
		}
	}

	if len(t.Blocks) > 0 {
		sb.WriteString("\nBLOCKS\n")
		for _, dep := range t.Blocks {
			sb.WriteString(fmt.Sprintf("  ← ○ %s: %s [%s]\n", dep.TaskRef, dep.Title, dep.Status))
		}
	}

	return sb.String()
}

// formatDate parses an RFC3339 timestamp and returns just the date portion.
func formatDate(ts string) string {
	t, ok := parseTimeBestEffort(ts)
	if !ok {
		return ts
	}
	return t.Format("2006-01-02")
}

// parsePriority parses a priority string, stripping P/p prefix.
func parsePriority(raw string) (int, error) {
	p := strings.TrimPrefix(strings.TrimPrefix(raw, "P"), "p")
	pv, err := strconv.Atoi(p)
	if err != nil || pv < 0 || pv > 4 {
		return 0, fmt.Errorf("invalid priority %q — use a number 0-4 (e.g., --priority 2 or --priority P2)", raw)
	}
	return pv, nil
}

// splitAndTrimLabels splits a comma-separated label string and trims whitespace.
func splitAndTrimLabels(s string) []string {
	parts := strings.Split(s, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
