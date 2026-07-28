package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var workCmd = &cobra.Command{
	Use:   "work",
	Short: "Discover coordination-aware work",
}

var workReadyCmd = &cobra.Command{
	Use:   "ready",
	Short: "List ready tasks that are not already claimed by other workspaces",
	RunE:  runWorkReady,
}

var workActiveCmd = &cobra.Command{
	Use:   "active",
	Short: "List active in-progress work across the team",
	RunE:  runWorkActive,
}

var workBlockedCmd = &cobra.Command{
	Use:   "blocked",
	Short: "List blocked tasks",
	RunE:  runWorkBlocked,
}

type workListItem struct {
	TaskRef                 string  `json:"task_ref"`
	Title                   string  `json:"title"`
	TaskType                string  `json:"task_type"`
	Priority                int     `json:"priority"`
	Status                  string  `json:"status,omitempty"`
	OwnerAlias              *string `json:"owner_alias,omitempty"`
	ClaimedAt               *string `json:"claimed_at,omitempty"`
	OwnerLastSeenAt         *string `json:"owner_last_seen_at,omitempty"`
	ClaimAgeBand            string  `json:"claim_age_band,omitempty"`
	ClaimantActivityAgeBand string  `json:"claimant_activity_age_band,omitempty"`
	CanonicalOrigin         *string `json:"canonical_origin,omitempty"`
	Branch                  *string `json:"branch,omitempty"`
}

type workListOutput struct {
	Kind  string         `json:"kind"`
	Items []workListItem `json:"items"`
}

func init() {
	workCmd.AddCommand(workReadyCmd)
	workCmd.AddCommand(workActiveCmd)
	workCmd.AddCommand(workBlockedCmd)
	rootCmd.AddCommand(workCmd)
}

func runWorkReady(cmd *cobra.Command, args []string) error {
	client, sel, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	claimsResp, err := client.ClaimsList(ctx, "", 200)
	if err != nil {
		return err
	}
	claimedByOthers := map[string]bool{}
	for _, claim := range claimsResp.Claims {
		if claim.WorkspaceID != sel.WorkspaceID {
			claimedByOthers[claim.BeadID] = true
		}
	}

	resp, err := client.TaskListReady(ctx)
	if err != nil {
		return err
	}

	items := make([]workListItem, 0, len(resp.Tasks))
	for _, task := range resp.Tasks {
		if claimedByOthers[task.TaskRef] {
			continue
		}
		items = append(items, workListItem{
			TaskRef:  task.TaskRef,
			Title:    task.Title,
			TaskType: task.TaskType,
			Priority: task.Priority,
			Status:   task.Status,
		})
	}

	printOutput(workListOutput{Kind: "ready", Items: items}, formatWorkList)
	return nil
}

func runWorkActive(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TaskListActive(ctx)
	if err != nil {
		return err
	}

	items := make([]workListItem, 0, len(resp.Tasks))
	for _, task := range resp.Tasks {
		claimAgeBand := coordinationAgeBand(valueOrEmpty(task.ClaimedAt))
		claimantActivityAgeBand := ""
		if claimAgeBand != "" {
			claimantActivityAgeBand = coordinationAgeBand(valueOrEmpty(task.OwnerLastSeenAt))
			if claimantActivityAgeBand == "" {
				claimantActivityAgeBand = "unknown"
			}
		}
		items = append(items, workListItem{
			TaskRef:                 task.TaskRef,
			Title:                   task.Title,
			TaskType:                task.TaskType,
			Priority:                task.Priority,
			Status:                  task.Status,
			OwnerAlias:              task.OwnerAlias,
			ClaimedAt:               task.ClaimedAt,
			OwnerLastSeenAt:         task.OwnerLastSeenAt,
			ClaimAgeBand:            claimAgeBand,
			ClaimantActivityAgeBand: claimantActivityAgeBand,
			CanonicalOrigin:         task.CanonicalOrigin,
			Branch:                  task.Branch,
		})
	}

	sort.Slice(items, func(i, j int) bool {
		leftRepo := strings.TrimSpace(valueOrEmpty(items[i].CanonicalOrigin))
		rightRepo := strings.TrimSpace(valueOrEmpty(items[j].CanonicalOrigin))
		if leftRepo != rightRepo {
			if leftRepo == "" {
				return false
			}
			if rightRepo == "" {
				return true
			}
			return leftRepo < rightRepo
		}
		if items[i].Priority != items[j].Priority {
			return items[i].Priority < items[j].Priority
		}
		return items[i].TaskRef < items[j].TaskRef
	})

	printOutput(workListOutput{Kind: "active", Items: items}, formatWorkList)
	return nil
}

func runWorkBlocked(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.TaskListBlocked(ctx)
	if err != nil {
		return err
	}

	items := make([]workListItem, 0, len(resp.Tasks))
	for _, task := range resp.Tasks {
		items = append(items, workListItem{
			TaskRef:  task.TaskRef,
			Title:    task.Title,
			TaskType: task.TaskType,
			Priority: task.Priority,
			Status:   "blocked",
		})
	}

	printOutput(workListOutput{Kind: "blocked", Items: items}, formatWorkList)
	return nil
}

func formatWorkList(v any) string {
	out := v.(workListOutput)
	if len(out.Items) == 0 {
		switch out.Kind {
		case "ready":
			return "No ready work.\n"
		case "active":
			return "No active work.\n"
		case "blocked":
			return "No blocked work.\n"
		default:
			return "No work items.\n"
		}
	}

	title := map[string]string{
		"ready":   "Ready work",
		"active":  "Active work",
		"blocked": "Blocked work",
	}[out.Kind]
	if title == "" {
		title = "Work"
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("%s (%d):\n\n", title, len(out.Items)))
	if out.Kind == "active" {
		currentRepo := ""
		for _, item := range out.Items {
			repo := strings.TrimSpace(valueOrEmpty(item.CanonicalOrigin))
			if repo == "" {
				repo = "(unknown repo)"
			}
			if repo != currentRepo {
				if currentRepo != "" {
					sb.WriteString("\n")
				}
				sb.WriteString("## " + repo + "\n")
				currentRepo = repo
			}
			owner := strings.TrimSpace(valueOrEmpty(item.OwnerAlias))
			if owner == "" {
				owner = "-"
			}
			line := fmt.Sprintf(
				"  %s  P%d  %s  %s  %s",
				item.TaskRef,
				item.Priority,
				formatWorkTaskTitle(item.TaskType, item.Title),
				owner,
				formatOptionalBranch(item.Branch),
			)
			line = strings.TrimRight(line, " ")
			if item.ClaimAgeBand != "" {
				activityBand := item.ClaimantActivityAgeBand
				if activityBand == "" {
					activityBand = "unknown"
				}
				line += fmt.Sprintf(
					"  [claim age: %s; claimant activity: %s]",
					item.ClaimAgeBand,
					activityBand,
				)
			}
			sb.WriteString(line + "\n")
		}
		return sb.String()
	}
	for i, item := range out.Items {
		icon := priorityIcon(item.Priority)
		sb.WriteString(fmt.Sprintf("%d. [%s P%d] [%s] %s: %s", i+1, icon, item.Priority, item.TaskType, item.TaskRef, item.Title))
		if item.OwnerAlias != nil && strings.TrimSpace(*item.OwnerAlias) != "" {
			sb.WriteString(fmt.Sprintf(" — %s", strings.TrimSpace(*item.OwnerAlias)))
		}
		if item.ClaimedAt != nil && strings.TrimSpace(*item.ClaimedAt) != "" {
			sb.WriteString(fmt.Sprintf(" (claim age: %s)", coordinationAgeBand(*item.ClaimedAt)))
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func valueOrEmpty(v *string) string {
	if v == nil {
		return ""
	}
	return *v
}

func currentWorkspaceID(workingDir string, sel *awconfig.Selection) string {
	if state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir); err == nil {
		if membership, err := workspaceMembershipForSelection(state, sel); err == nil && membership != nil && strings.TrimSpace(membership.WorkspaceID) != "" {
			return strings.TrimSpace(membership.WorkspaceID)
		}
	}
	if sel == nil {
		return ""
	}
	return strings.TrimSpace(sel.WorkspaceID)
}

func coordinationAgeBand(timestamp string) string {
	if strings.TrimSpace(timestamp) == "" {
		return ""
	}
	return coordinationAgeBandAt(timestamp, time.Now().UTC())
}

func coordinationAgeBandAt(timestamp string, now time.Time) string {
	ts, ok := parseTimeBestEffort(timestamp)
	if !ok {
		return "unknown"
	}
	age := now.Sub(ts)
	if age < 24*time.Hour {
		return "under a day"
	}
	if age < 7*24*time.Hour {
		return "days"
	}
	if age < 30*24*time.Hour {
		return "weeks"
	}
	return "months"
}

func formatWorkTaskTitle(taskType, title string) string {
	taskType = strings.TrimSpace(taskType)
	if taskType == "" {
		return title
	}
	return fmt.Sprintf("[%s] %s", taskType, title)
}

func formatOptionalBranch(branch *string) string {
	value := strings.TrimSpace(valueOrEmpty(branch))
	if value == "" || isDefaultBranch(value) {
		return ""
	}
	return value
}

func isDefaultBranch(branch string) bool {
	switch strings.TrimSpace(branch) {
	case "main", "master":
		return true
	default:
		return false
	}
}
