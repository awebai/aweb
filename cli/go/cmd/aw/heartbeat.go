package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

var heartbeatCmd = &cobra.Command{
	Use:   "heartbeat",
	Short: "Send an explicit presence heartbeat",
	RunE: func(cmd *cobra.Command, args []string) error {
		client, err := resolveClient()
		if err != nil {
			return err
		}

		heartbeatCtx, heartbeatCancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := client.Heartbeat(heartbeatCtx)
		heartbeatCancel()
		if err != nil {
			return err
		}

		repairCtx, repairCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer repairCancel()
		workingDir, _ := os.Getwd()
		resp.RepoStatus, resp.CanonicalOrigin, resp.RepoID, err = repairHeartbeatRepoBinding(repairCtx, client, workingDir)
		if err != nil {
			resp.RepoError = err.Error()
		}
		printJSON(resp)
		return nil
	},
}

func repairHeartbeatRepoBinding(ctx context.Context, client *aweb.Client, workingDir string) (string, string, string, error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return "repair_failed", "", "", err
	}
	workspacePath := filepath.Join(home.Root, "workspace.yaml")
	state, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil {
		return "repair_failed", "", "", err
	}

	repoPath := strings.TrimSpace(state.WorkspacePath)
	if repoPath == "" {
		repoPath = workingDir
	}
	repoOrigin := discoverRepoOrigin(repoPath)
	canonicalOrigin := canonicalizeGitOrigin(repoOrigin)
	if canonicalOrigin == "" {
		return "unavailable", "", strings.TrimSpace(state.RepoID), nil
	}
	if strings.TrimSpace(state.CanonicalOrigin) == canonicalOrigin && strings.TrimSpace(state.RepoID) != "" {
		return "current", canonicalOrigin, strings.TrimSpace(state.RepoID), nil
	}

	patched, err := client.PatchCurrentWorkspace(ctx, &aweb.PatchCurrentWorkspaceRequest{RepoOrigin: repoOrigin})
	if err != nil {
		return "repair_failed", canonicalOrigin, strings.TrimSpace(state.RepoID), err
	}
	if strings.TrimSpace(patched.RepoID) == "" || strings.TrimSpace(patched.CanonicalOrigin) == "" {
		return "repair_failed", canonicalOrigin, strings.TrimSpace(state.RepoID), fmt.Errorf("workspace repo repair response omitted repo binding")
	}

	state.RepoID = strings.TrimSpace(patched.RepoID)
	state.CanonicalOrigin = strings.TrimSpace(patched.CanonicalOrigin)
	state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, state); err != nil {
		return "repair_failed", state.CanonicalOrigin, state.RepoID, err
	}
	return "repaired", state.CanonicalOrigin, state.RepoID, nil
}

func init() {
	rootCmd.AddCommand(heartbeatCmd)
}
