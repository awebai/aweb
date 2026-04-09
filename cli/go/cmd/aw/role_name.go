package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var roleNameCmd = &cobra.Command{
	Use:   "role-name",
	Short: "Manage the current workspace role name",
}

var roleNameSetCmd = &cobra.Command{
	Use:   "set [role-name]",
	Short: "Set the current workspace role name",
	Args:  cobra.MaximumNArgs(1),
	RunE:  runRoleNameSet,
}

func init() {
	roleNameCmd.AddCommand(roleNameSetCmd)
	rootCmd.AddCommand(roleNameCmd)
	roleNameCmd.GroupID = groupCoordination
}

func runRoleNameSet(cmd *cobra.Command, args []string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}

	requested := ""
	if len(args) > 0 {
		requested = strings.TrimSpace(args[0])
	}

	roleName, err := resolveRole(client, requested, isTTY() && requested == "", os.Stdin, os.Stderr)
	if err != nil {
		return err
	}

	wd, _ := os.Getwd()
	workspace, workspacePath, err := awconfig.LoadWorktreeWorkspaceFromDir(wd)
	if err != nil {
		if os.IsNotExist(err) {
			return usageError("current worktree is missing .aw/workspace.yaml; run `aw init` first")
		}
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.PatchCurrentWorkspace(ctx, &aweb.PatchCurrentWorkspaceRequest{
		Role: roleName,
	})
	if err != nil {
		return fmt.Errorf("setting role name: %w", err)
	}
	workspace.RoleName = strings.TrimSpace(resp.Role)
	workspace.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		return fmt.Errorf("write %s: %w", workspacePath, err)
	}
	fmt.Printf("Role name set to %s\n", roleName)
	return nil
}
