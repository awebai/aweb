package main

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
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
	Short: "List active in-progress work across the project",
	RunE:  runWorkActive,
}

var workBlockedCmd = &cobra.Command{
	Use:   "blocked",
	Short: "List blocked tasks",
	RunE:  runWorkBlocked,
}

type workListItem struct {
	TaskRef    string  `json:"task_ref"`
	Title      string  `json:"title"`
	TaskType   string  `json:"task_type"`
	Priority   int     `json:"priority"`
	Status     string  `json:"status,omitempty"`
	OwnerAlias *string `json:"owner_alias,omitempty"`
	ClaimedAt  *string `json:"claimed_at,omitempty"`
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
		if claim.WorkspaceID != sel.IdentityID {
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

	tasksResp, err := client.TaskList(ctx, aweb.TaskListParams{Status: "in_progress"})
	if err != nil {
		return err
	}
	claimsResp, err := client.ClaimsList(ctx, "", 200)
	if err != nil {
		return err
	}
	agentsResp, err := client.ListIdentities(ctx)
	if err != nil {
		return err
	}

	agentAliases := map[string]string{}
	for _, agent := range agentsResp.Identities {
		if strings.TrimSpace(agent.IdentityID) != "" && strings.TrimSpace(agent.Alias) != "" {
			agentAliases[agent.IdentityID] = agent.Alias
		}
	}

	type claimMeta struct {
		alias     string
		claimedAt string
	}
	claimsByRef := map[string]claimMeta{}
	for _, claim := range claimsResp.Claims {
		if _, exists := claimsByRef[claim.BeadID]; !exists {
			claimsByRef[claim.BeadID] = claimMeta{alias: claim.Alias, claimedAt: claim.ClaimedAt}
		}
	}

	items := make([]workListItem, 0, len(tasksResp.Tasks))
	for _, task := range tasksResp.Tasks {
		item := workListItem{
			TaskRef:  task.TaskRef,
			Title:    task.Title,
			TaskType: task.TaskType,
			Priority: task.Priority,
			Status:   task.Status,
		}
		if claim, ok := claimsByRef[task.TaskRef]; ok {
			item.OwnerAlias = stringPtr(claim.alias)
			item.ClaimedAt = stringPtr(claim.claimedAt)
		} else if task.AssigneeAgentID != nil {
			if alias := strings.TrimSpace(agentAliases[*task.AssigneeAgentID]); alias != "" {
				item.OwnerAlias = stringPtr(alias)
			}
		}
		items = append(items, item)
	}

	sort.Slice(items, func(i, j int) bool {
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
			Status:   task.Status,
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
	for i, item := range out.Items {
		icon := priorityIcon(item.Priority)
		sb.WriteString(fmt.Sprintf("%d. [%s P%d] [%s] %s: %s", i+1, icon, item.Priority, item.TaskType, item.TaskRef, item.Title))
		if item.OwnerAlias != nil && strings.TrimSpace(*item.OwnerAlias) != "" {
			sb.WriteString(fmt.Sprintf(" — %s", strings.TrimSpace(*item.OwnerAlias)))
		}
		if item.ClaimedAt != nil && strings.TrimSpace(*item.ClaimedAt) != "" {
			sb.WriteString(fmt.Sprintf(" (%s)", formatTimeAgo(strings.TrimSpace(*item.ClaimedAt))))
			if isClaimStale(strings.TrimSpace(*item.ClaimedAt)) {
				sb.WriteString(" [stale]")
			}
		}
		sb.WriteString("\n")
	}
	return sb.String()
}

func currentWorkspaceID(workingDir string, sel *awconfig.Selection) string {
	if state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir); err == nil && strings.TrimSpace(state.WorkspaceID) != "" {
		return strings.TrimSpace(state.WorkspaceID)
	}
	if sel == nil {
		return ""
	}
	return strings.TrimSpace(sel.IdentityID)
}

func isClaimStale(claimedAt string) bool {
	ts, ok := parseTimeBestEffort(claimedAt)
	if !ok {
		return false
	}
	return time.Since(ts) > 24*time.Hour
}
