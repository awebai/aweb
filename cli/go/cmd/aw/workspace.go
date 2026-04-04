package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var workspaceCmd = &cobra.Command{
	Use:   "workspace",
	Short: "Manage repo-local coordination workspaces",
}

var workspaceInitCmd = &cobra.Command{
	Use:    "init",
	Short:  "Register the current git worktree for coordination",
	Hidden: true,
	RunE:   runWorkspaceInit,
}

var workspaceStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show coordination status for the current workspace/identity and team",
	RunE:  runWorkspaceStatus,
}

var workspaceAddWorktreeCmd = &cobra.Command{
	Use:   "add-worktree [role]",
	Short: "Create a sibling git worktree and initialize a new coordination workspace in it",
	Args:  cobra.RangeArgs(0, 1),
	RunE:  runWorkspaceAddWorktree,
}

var (
	workspaceInitRole       string
	workspaceInitRepoOrigin string
	workspaceStatusLimit    int
	workspaceAddAlias       string
)

type workspaceInitOutput struct {
	WorkspaceID     string `json:"workspace_id"`
	ProjectID       string `json:"project_id"`
	ProjectSlug     string `json:"project_slug"`
	RepoID          string `json:"repo_id"`
	CanonicalOrigin string `json:"canonical_origin"`
	Alias           string `json:"alias"`
	HumanName       string `json:"human_name"`
	Role            string `json:"role,omitempty"`
	Hostname        string `json:"hostname,omitempty"`
	WorkspacePath   string `json:"workspace_path,omitempty"`
	Created         bool   `json:"created"`
}

type workspaceStatusOutput struct {
	Workspace          aweb.WorkspaceInfo                `json:"workspace"`
	ContextKind        string                            `json:"context_kind"`
	Locks              []aweb.ReservationView            `json:"locks,omitempty"`
	Team               []aweb.WorkspaceInfo              `json:"team,omitempty"`
	TeamLocks          map[string][]aweb.ReservationView `json:"team_locks,omitempty"`
	EscalationsPending int                               `json:"escalations_pending"`
	ConflictCount      int                               `json:"conflict_count"`
}

type workspaceAddWorktreeOutput struct {
	Alias        string `json:"alias"`
	Role         string `json:"role"`
	Branch       string `json:"branch"`
	WorktreePath string `json:"worktree_path"`
}

func init() {
	workspaceInitCmd.Flags().StringVar(&workspaceInitRole, "role", "", "Coordination role for this workspace")
	workspaceInitCmd.Flags().StringVar(&workspaceInitRepoOrigin, "repo-origin", "", "Override git remote origin URL")

	workspaceStatusCmd.Flags().IntVar(&workspaceStatusLimit, "limit", 15, "Maximum team workspaces to show")
	workspaceAddWorktreeCmd.Flags().StringVar(&workspaceAddAlias, "alias", "", "Override the default alias")

	workspaceCmd.AddCommand(workspaceInitCmd)
	workspaceCmd.AddCommand(workspaceStatusCmd)
	workspaceCmd.AddCommand(workspaceAddWorktreeCmd)
	rootCmd.AddCommand(workspaceCmd)
}

func runWorkspaceInit(cmd *cobra.Command, args []string) error {
	loadDotenvBestEffort()

	root, err := currentGitWorktreeRoot()
	if err != nil {
		return usageError("workspace init requires a git worktree")
	}

	client, sel, err := resolveClientSelectionForDir(root)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sel.IdentityID) == "" || strings.TrimSpace(sel.IdentityHandle) == "" {
		return usageError("selected account has no identity; run 'aw init' first")
	}

	out, err := registerWorkspaceForRoot(root, client, strings.TrimSpace(workspaceInitRole), strings.TrimSpace(workspaceInitRepoOrigin))
	if err != nil {
		return err
	}
	printOutput(*out, formatWorkspaceInit)
	return nil
}

func runWorkspaceStatus(cmd *cobra.Command, args []string) error {
	loadDotenvBestEffort()

	workingDir, _ := os.Getwd()
	client, sel, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return err
	}
	if strings.TrimSpace(sel.IdentityID) == "" {
		return usageError("selected account has no identity; run 'aw init' first")
	}

	state, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("load workspace state: %w", err)
	}

	workspaceID := strings.TrimSpace(sel.IdentityID)
	if state != nil && strings.TrimSpace(state.WorkspaceID) != "" {
		workspaceID = strings.TrimSpace(state.WorkspaceID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	teamResp, err := client.WorkspaceTeam(ctx, aweb.WorkspaceTeamParams{
		IncludeClaims:            true,
		IncludePresence:          true,
		OnlyWithClaims:           false,
		AlwaysIncludeWorkspaceID: workspaceID,
		Limit:                    workspaceStatusLimit,
	})
	if err != nil {
		return err
	}

	locksResp, err := client.ReservationList(ctx, "")
	if err != nil {
		return err
	}

	statusResp, err := client.CoordinationStatus(ctx, "")
	if err != nil {
		return err
	}

	locksByWorkspace := map[string][]aweb.ReservationView{}
	for _, reservation := range locksResp.Reservations {
		holder := strings.TrimSpace(reservation.HolderAgentID)
		if holder == "" {
			continue
		}
		locksByWorkspace[holder] = append(locksByWorkspace[holder], reservation)
	}
	for holder := range locksByWorkspace {
		sort.Slice(locksByWorkspace[holder], func(i, j int) bool {
			return locksByWorkspace[holder][i].ResourceKey < locksByWorkspace[holder][j].ResourceKey
		})
	}

	var self aweb.WorkspaceInfo
	team := make([]aweb.WorkspaceInfo, 0, len(teamResp.Workspaces))
	for _, workspace := range teamResp.Workspaces {
		if workspace.WorkspaceID == workspaceID {
			self = workspace
			continue
		}
		team = append(team, workspace)
	}

	if self.WorkspaceID == "" {
		self = fallbackWorkspaceInfo(sel, state)
	}

	teamLocks := map[string][]aweb.ReservationView{}
	for _, workspace := range team {
		if locks := locksByWorkspace[workspace.WorkspaceID]; len(locks) > 0 {
			teamLocks[workspace.WorkspaceID] = locks
		}
	}

	printOutput(workspaceStatusOutput{
		Workspace:          self,
		ContextKind:        inferWorkspaceContextKind(self, state),
		Locks:              locksByWorkspace[workspaceID],
		Team:               team,
		TeamLocks:          teamLocks,
		EscalationsPending: statusResp.EscalationsPending,
		ConflictCount:      len(statusResp.Conflicts),
	}, formatWorkspaceStatus)

	// Opportunistically clean up workspaces whose directories have disappeared.
	if gone := detectGoneWorkspaces(client, workspaceID); len(gone) > 0 {
		fmt.Fprint(os.Stderr, formatGoneWorkspaces(gone))
	}
	return nil
}

func runWorkspaceAddWorktree(cmd *cobra.Command, args []string) error {
	loadDotenvBestEffort()

	workingDir, _ := os.Getwd()
	client, sel, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return err
	}

	root, err := currentGitWorktreeRootFromDir(workingDir)
	if err != nil {
		return usageError("workspace add-worktree requires a git worktree")
	}

	requested := ""
	if len(args) > 0 {
		requested = strings.TrimSpace(args[0])
	}
	role, err := resolveRole(client, requested, isTTY() && requested == "", os.Stdin, os.Stderr)
	if err != nil {
		return err
	}
	role = normalizeWorkspaceRole(role)
	if !isValidWorkspaceRole(role) {
		return usageError("invalid role: use 1-2 words (letters/numbers) with hyphens/underscores allowed; max 50 chars")
	}

	alias := strings.TrimSpace(workspaceAddAlias)
	aliasExplicit := alias != ""
	if aliasExplicit && !isValidWorkspaceAlias(alias) {
		return usageError("invalid alias %q: must start with an alphanumeric and contain only alphanumerics, dashes, or underscores (max 64 chars)", alias)
	}

	namespaceSlug := strings.TrimSpace(sel.NamespaceSlug)
	if namespaceSlug == "" {
		namespaceSlug = strings.TrimSpace(sel.DefaultProject)
	}
	var state *awconfig.WorktreeWorkspace
	if loaded, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir); err == nil {
		state = loaded
		if namespaceSlug == "" {
			namespaceSlug = strings.TrimSpace(loaded.ProjectSlug)
		}
	}
	if namespaceSlug == "" {
		return usageError("selected account has no namespace/project context; run 'aw init' first")
	}

	sourceAPIKey := strings.TrimSpace(sel.APIKey)
	if sourceAPIKey == "" {
		return usageError("selected account has no API key; run 'aw init' first")
	}
	sourceBaseURL := strings.TrimSpace(sel.BaseURL)
	if sourceBaseURL == "" {
		return fmt.Errorf("selected account missing server URL")
	}
	sourceServerName := strings.TrimSpace(sel.ServerName)
	if sourceServerName == "" {
		derived, derr := awconfig.DeriveServerNameFromURL(sourceBaseURL)
		if derr != nil {
			return fmt.Errorf("derive server name: %w", derr)
		}
		sourceServerName = derived
	}

	humanName := ""
	if state != nil {
		humanName = strings.TrimSpace(state.HumanName)
	}

	wantJSON := jsonFlag

	const maxAttempts = 25
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		if !aliasExplicit {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			suggestion, err := client.SuggestAliasPrefix(ctx, namespaceSlug)
			cancel()
			if err != nil {
				return fmt.Errorf("failed to suggest alias prefix: %w", err)
			}
			if !isValidSuggestedAliasPrefix(strings.TrimSpace(suggestion.NamePrefix)) {
				return fmt.Errorf("invalid alias prefix from server: %q", suggestion.NamePrefix)
			}
			alias = strings.TrimSpace(suggestion.NamePrefix)
		}

		branchName := alias
		worktreePath, err := deriveWorkspaceAddWorktreePath(root, branchName)
		if err != nil {
			return fmt.Errorf("security error: %w", err)
		}
		if _, err := os.Stat(worktreePath); err == nil {
			return fmt.Errorf("directory %s already exists", worktreePath)
		}

		if !wantJSON {
			fmt.Fprintf(os.Stderr, "Creating worktree for branch %q...\n", branchName)
			fmt.Fprintf(os.Stderr, "  Main repo: %s\n", root)
			fmt.Fprintf(os.Stderr, "  Worktree:  %s\n", worktreePath)
			fmt.Fprintf(os.Stderr, "  Role:      %s\n", role)
			fmt.Fprintf(os.Stderr, "  Alias:     %s\n\n", alias)
			fmt.Fprintln(os.Stderr, "Creating git worktree...")
		}

		branchCreated, err := createWorkspaceGitWorktree(root, worktreePath, branchName, wantJSON)
		if err != nil {
			return fmt.Errorf("failed to create worktree: %w", err)
		}

		if !wantJSON {
			fmt.Fprintln(os.Stderr, "Initializing aw...")
		}

		// Create a short-lived invite from the current workspace,
		// then accept it in the new worktree. This is the supported
		// hosted path for one workspace spawning another in the same project.
		inviteToken, initErr := createWorktreeInvite(client, alias)
		if initErr == nil {
			initOpts := initOptions{
				Flow:          flowInvite,
				WorkingDir:    worktreePath,
				BaseURL:       sourceBaseURL,
				ServerName:    sourceServerName,
				IdentityAlias: alias,
				HumanName:     humanName,
				AgentType:     "agent",
				SaveConfig:    true,
				SetDefault:    false,
				WriteContext:  true,
				InviteToken:   inviteToken,
				AccountName:   "",
				WorkspaceRole: role,
				Lifetime:      awid.LifetimeEphemeral,
			}
			_, initErr = executeInit(initOpts)
		}
		if initErr != nil {
			if !wantJSON {
				fmt.Fprintln(os.Stderr)
				fmt.Fprintln(os.Stderr, "Error: Failed to initialize aw. Cleaning up worktree...")
			}
			cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)

			if !aliasExplicit && isWorkspaceAliasTakenError(initErr) {
				if !wantJSON {
					fmt.Fprintf(os.Stderr, "Alias %q was taken; retrying with a new name...\n", alias)
				}
				if attempt < maxAttempts {
					time.Sleep(time.Duration(attempt) * 50 * time.Millisecond)
				}
				continue
			}

			return fmt.Errorf("aw init failed: %w", initErr)
		}

		output := workspaceAddWorktreeOutput{
			Alias:        alias,
			Role:         role,
			Branch:       branchName,
			WorktreePath: worktreePath,
		}
		if wantJSON {
			printJSON(output)
		} else {
			fmt.Print(formatWorkspaceAddWorktree(output))
		}
		return nil
	}

	return fmt.Errorf("exhausted %d attempts to create a worktree (try specifying --alias)", maxAttempts)
}

func currentGitWorktreeRoot() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return currentGitWorktreeRootFromDir(wd)
}

func currentGitWorktreeRootFromDir(workingDir string) (string, error) {
	cmd := exec.Command("git", "-C", workingDir, "rev-parse", "--show-toplevel")
	out, err := cmd.Output()
	if err != nil {
		return "", err
	}
	root := strings.TrimSpace(string(out))
	if root == "" {
		return "", fmt.Errorf("git returned empty worktree root")
	}
	return root, nil
}

type contextAttachResult struct {
	Workspace   *workspaceInitOutput
	ContextKind string
}

func autoAttachContext(workingDir string, client *aweb.Client, roleOverride string) (*contextAttachResult, error) {
	root, err := currentGitWorktreeRootFromDir(workingDir)
	if err != nil {
		return registerLocalAttachmentForDir(workingDir, client)
	}

	origin, err := resolveWorkspaceRepoOrigin(root, "")
	if err != nil {
		return registerLocalAttachmentForDir(workingDir, client)
	}

	out, err := registerWorkspaceForRoot(root, client, strings.TrimSpace(roleOverride), origin)
	if err != nil {
		return nil, err
	}
	return &contextAttachResult{
		Workspace:   out,
		ContextKind: "repo_worktree",
	}, nil
}

func registerWorkspaceForRoot(root string, client *aweb.Client, roleOverride string, repoOrigin string) (*workspaceInitOutput, error) {
	origin, err := resolveWorkspaceRepoOrigin(root, repoOrigin)
	if err != nil {
		return nil, err
	}
	hostname, _ := os.Hostname()

	statePath := filepath.Join(root, awconfig.DefaultWorktreeWorkspaceRelativePath())
	existingState, err := awconfig.LoadWorktreeWorkspaceFrom(statePath)
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read %s: %w", statePath, err)
	}

	role := strings.TrimSpace(roleOverride)
	if role == "" && existingState != nil {
		role = strings.TrimSpace(existingState.Role)
	}
	// Only resolve from project roles if we don't already have a role.
	// Callers that pre-validate the role (init, project create,
	// add-worktree, role-name set) pass it here already validated.
	if role == "" {
		role, err = resolveRole(client, "", isTTY(), os.Stdin, os.Stderr)
		if err != nil {
			return nil, err
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.WorkspaceRegister(ctx, &aweb.WorkspaceRegisterRequest{
		RepoOrigin:    origin,
		Role:          role,
		Hostname:      hostname,
		WorkspacePath: root,
	})
	if err != nil {
		return nil, err
	}

	state := &awconfig.WorktreeWorkspace{
		WorkspaceID:     resp.WorkspaceID,
		ProjectID:       resp.ProjectID,
		ProjectSlug:     resp.ProjectSlug,
		RepoID:          resp.RepoID,
		CanonicalOrigin: resp.CanonicalOrigin,
		Alias:           resp.Alias,
		HumanName:       resp.HumanName,
		Role:            role,
		Hostname:        hostname,
		WorkspacePath:   root,
		UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
	}
	if existingState != nil {
		state = existingState
		state.WorkspaceID = resp.WorkspaceID
		state.ProjectID = resp.ProjectID
		state.ProjectSlug = resp.ProjectSlug
		state.RepoID = resp.RepoID
		state.CanonicalOrigin = resp.CanonicalOrigin
		state.Alias = resp.Alias
		if strings.TrimSpace(resp.HumanName) != "" {
			state.HumanName = resp.HumanName
		}
		state.RoleName = role
		state.Role = role
		state.Hostname = hostname
		state.WorkspacePath = root
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(statePath, state); err != nil {
		return nil, fmt.Errorf("write %s: %w", statePath, err)
	}

	return &workspaceInitOutput{
		WorkspaceID:     resp.WorkspaceID,
		ProjectID:       resp.ProjectID,
		ProjectSlug:     resp.ProjectSlug,
		RepoID:          resp.RepoID,
		CanonicalOrigin: resp.CanonicalOrigin,
		Alias:           resp.Alias,
		HumanName:       resp.HumanName,
		Role:            role,
		Hostname:        hostname,
		WorkspacePath:   root,
		Created:         resp.Created,
	}, nil
}

func registerLocalAttachmentForDir(workingDir string, client *aweb.Client) (*contextAttachResult, error) {
	hostname, _ := os.Hostname()
	workspacePath := filepath.Clean(workingDir)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.WorkspaceAttach(ctx, &aweb.WorkspaceAttachRequest{
		AttachmentType: "local_dir",
		Hostname:       hostname,
		WorkspacePath:  workspacePath,
	})
	if err != nil {
		return nil, err
	}

	statePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	state, stateErr := awconfig.LoadWorktreeWorkspaceFrom(statePath)
	switch {
	case stateErr == nil:
		state.WorkspaceID = strings.TrimSpace(resp.WorkspaceID)
		if v := strings.TrimSpace(resp.ProjectID); v != "" {
			state.ProjectID = v
		}
		if v := strings.TrimSpace(resp.ProjectSlug); v != "" {
			state.ProjectSlug = v
			if strings.TrimSpace(state.NamespaceSlug) == "" {
				state.NamespaceSlug = v
			}
		}
		if v := strings.TrimSpace(resp.Alias); v != "" {
			state.Alias = v
			if strings.TrimSpace(state.IdentityHandle) == "" {
				state.IdentityHandle = v
			}
		}
		if v := strings.TrimSpace(resp.HumanName); v != "" {
			state.HumanName = v
		}
		state.RepoID = ""
		state.CanonicalOrigin = ""
		state.Hostname = hostname
		state.WorkspacePath = workspacePath
		state.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
		if err := awconfig.SaveWorktreeWorkspaceTo(statePath, state); err != nil {
			return nil, fmt.Errorf("write %s: %w", statePath, err)
		}
	case os.IsNotExist(stateErr):
		// Commands that own identity/project binding persistence will write
		// workspace.yaml after attach. Do not create a coordination-only file
		// here for plain local directories.
	case stateErr != nil:
		return nil, fmt.Errorf("read %s: %w", statePath, stateErr)
	}

	return &contextAttachResult{
		ContextKind: "local_dir",
		Workspace: &workspaceInitOutput{
			WorkspaceID:   resp.WorkspaceID,
			ProjectID:     resp.ProjectID,
			ProjectSlug:   resp.ProjectSlug,
			Alias:         resp.Alias,
			HumanName:     resp.HumanName,
			Hostname:      hostname,
			WorkspacePath: workspacePath,
			Created:       resp.Created,
		},
	}, nil
}

func resolveWorkspaceRepoOrigin(root, explicit string) (string, error) {
	if strings.TrimSpace(explicit) != "" {
		return strings.TrimSpace(explicit), nil
	}
	cmd := exec.Command("git", "-C", root, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return "", usageError("missing git remote origin; use --repo-origin to register this workspace")
	}
	origin := strings.TrimSpace(string(out))
	if origin == "" {
		return "", usageError("missing git remote origin; use --repo-origin to register this workspace")
	}
	return origin, nil
}

func fallbackWorkspaceInfo(sel *awconfig.Selection, state *awconfig.WorktreeWorkspace) aweb.WorkspaceInfo {
	info := aweb.WorkspaceInfo{
		WorkspaceID: sel.IdentityID,
		Alias:       sel.IdentityHandle,
		Status:      "offline",
	}
	if state == nil {
		return info
	}
	if strings.TrimSpace(state.WorkspaceID) != "" {
		info.WorkspaceID = strings.TrimSpace(state.WorkspaceID)
	}
	if strings.TrimSpace(state.Alias) != "" {
		info.Alias = strings.TrimSpace(state.Alias)
	}
	if strings.TrimSpace(state.HumanName) != "" {
		info.HumanName = stringPtr(strings.TrimSpace(state.HumanName))
	}
	if strings.TrimSpace(state.ProjectID) != "" {
		info.ProjectID = stringPtr(strings.TrimSpace(state.ProjectID))
	}
	if strings.TrimSpace(state.ProjectSlug) != "" {
		info.ProjectSlug = stringPtr(strings.TrimSpace(state.ProjectSlug))
	}
	if strings.TrimSpace(state.Role) != "" {
		info.Role = stringPtr(strings.TrimSpace(state.Role))
	}
	if strings.TrimSpace(state.Hostname) != "" {
		info.Hostname = stringPtr(strings.TrimSpace(state.Hostname))
	}
	if strings.TrimSpace(state.WorkspacePath) != "" {
		info.WorkspacePath = stringPtr(strings.TrimSpace(state.WorkspacePath))
	}
	if strings.TrimSpace(state.CanonicalOrigin) != "" {
		info.Repo = stringPtr(strings.TrimSpace(state.CanonicalOrigin))
	}
	return info
}

func inferWorkspaceContextKind(info aweb.WorkspaceInfo, state *awconfig.WorktreeWorkspace) string {
	if kind := derefString(info.ContextKind); kind != "" {
		return kind
	}
	if state != nil {
		if strings.TrimSpace(state.CanonicalOrigin) != "" || strings.TrimSpace(state.WorkspacePath) != "" {
			return "repo_worktree"
		}
	}
	if derefString(info.Repo) != "" || derefString(info.Branch) != "" || derefString(info.WorkspacePath) != "" {
		return "repo_worktree"
	}
	return "none"
}

func stringPtr(v string) *string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	return &v
}

func formatWorkspaceInit(v any) string {
	out := v.(workspaceInitOutput)
	var sb strings.Builder
	action := "Updated"
	if out.Created {
		action = "Registered"
	}
	sb.WriteString(fmt.Sprintf("%s workspace %s\n", action, out.Alias))
	sb.WriteString(fmt.Sprintf("Workspace ID: %s\n", out.WorkspaceID))
	sb.WriteString(fmt.Sprintf("Project:      %s\n", out.ProjectSlug))
	sb.WriteString(fmt.Sprintf("Repo:         %s\n", out.CanonicalOrigin))
	if out.Role != "" {
		sb.WriteString(fmt.Sprintf("Role:         %s\n", out.Role))
	}
	if out.WorkspacePath != "" {
		sb.WriteString(fmt.Sprintf("Path:         %s\n", abbreviateUserHome(out.WorkspacePath)))
	}
	return sb.String()
}

func formatWorkspaceAddWorktree(v any) string {
	out := v.(workspaceAddWorktreeOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("New agent worktree created at %s\n", abbreviateUserHome(out.WorktreePath)))
	sb.WriteString(fmt.Sprintf("Alias:      %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Role:       %s\n", out.Role))
	sb.WriteString(fmt.Sprintf("Branch:     %s\n", out.Branch))
	sb.WriteString(fmt.Sprintf("Workspace:  this worktree is now agent %s\n", out.Alias))
	sb.WriteString("State:      .aw/ in that worktree stores the local identity and workspace binding\n")
	sb.WriteString("\nTo use:\n")
	sb.WriteString(fmt.Sprintf("  cd %s\n", abbreviateUserHome(out.WorktreePath)))
	sb.WriteString("  aw run codex\n")
	sb.WriteString("  aw run claude\n")
	return sb.String()
}

var (
	workspaceAliasPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$`)
	workspaceRoleWordPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)
)

func isValidWorkspaceAlias(alias string) bool {
	return workspaceAliasPattern.MatchString(strings.TrimSpace(alias))
}

func isValidSuggestedAliasPrefix(alias string) bool {
	return isValidWorkspaceAlias(alias)
}

func normalizeWorkspaceRole(role string) string {
	fields := strings.Fields(strings.TrimSpace(role))
	if len(fields) == 0 {
		return ""
	}
	return strings.ToLower(strings.Join(fields, " "))
}

func isValidWorkspaceRole(role string) bool {
	normalized := normalizeWorkspaceRole(role)
	if normalized == "" || len(normalized) > 50 {
		return false
	}
	words := strings.Split(normalized, " ")
	if len(words) > 2 {
		return false
	}
	for _, word := range words {
		if !workspaceRoleWordPattern.MatchString(word) {
			return false
		}
	}
	return true
}

// fetchAvailableRoles returns the available roles from the project roles bundle.
// This is the single source of truth for role lists.
func fetchAvailableRoles(client *aweb.Client) ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.ActiveProjectRoles(ctx, aweb.ActiveProjectRolesParams{OnlySelected: false})
	if err != nil {
		return nil, fmt.Errorf("fetching project roles: %w", err)
	}

	roles := make([]string, 0, len(resp.Roles))
	for name := range resp.Roles {
		roles = append(roles, name)
	}
	sort.Strings(roles)
	return roles, nil
}

// resolveRole fetches available roles from the project roles bundle, validates
// the requested role against them, and optionally prompts the user to
// choose. This is the single entry point for role resolution.
func resolveRole(client *aweb.Client, requested string, allowPrompt bool, in io.Reader, out io.Writer) (string, error) {
	roles, err := fetchAvailableRoles(client)
	if err != nil {
		debugLog("fetch roles: %v", err)
		return normalizeWorkspaceRole(requested), nil
	}
	if len(roles) == 0 {
		return normalizeWorkspaceRole(requested), nil
	}
	return selectRoleFromAvailableRoles(requested, roles, allowPrompt, in, out)
}

func selectRoleFromAvailableRoles(requested string, roles []string, allowPrompt bool, in io.Reader, out io.Writer) (string, error) {
	if len(roles) == 0 {
		return "", usageError("no roles defined in the active project roles")
	}

	normalizedRoles := make(map[string]string, len(roles))
	for _, role := range roles {
		normalized := normalizeWorkspaceRole(role)
		if normalized != "" {
			normalizedRoles[normalized] = role
		}
	}

	requested = normalizeWorkspaceRole(requested)
	if requested != "" {
		if role, ok := normalizedRoles[requested]; ok {
			return role, nil
		}
		return "", usageError("invalid role %q; available roles: %s", requested, strings.Join(roles, ", "))
	}

	if !allowPrompt {
		return "", usageError("no role specified; available roles: %s", strings.Join(roles, ", "))
	}

	role, err := promptIndexedChoice("Role", roles, -1, in, out)
	if err != nil {
		return "", err
	}
	role = normalizeWorkspaceRole(role)
	if selected, ok := normalizedRoles[role]; ok {
		return selected, nil
	}
	return "", usageError("invalid role %q; available roles: %s", role, strings.Join(roles, ", "))
}

func deriveWorkspaceAddWorktreePath(mainRepo, branchName string) (string, error) {
	repoName := filepath.Base(mainRepo)
	parentDir := filepath.Dir(mainRepo)
	worktreePath := filepath.Join(parentDir, repoName+"-"+branchName)

	cleanPath := filepath.Clean(worktreePath)
	rel, err := filepath.Rel(parentDir, cleanPath)
	if err != nil {
		return "", fmt.Errorf("invalid worktree path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", fmt.Errorf("invalid worktree path: path traversal detected")
	}

	return cleanPath, nil
}

func workspaceBranchExists(repoPath, branch string) bool {
	cmd := exec.Command("git", "-C", repoPath, "rev-parse", "--verify", branch)
	return cmd.Run() == nil
}

func createWorkspaceGitWorktree(repoPath, worktreePath, branchName string, quiet bool) (branchCreated bool, err error) {
	if workspaceBranchExists(repoPath, branchName) {
		if !quiet {
			fmt.Fprintf(os.Stderr, "  Using existing branch %q\n", branchName)
		}
		cmd := exec.Command("git", "-C", repoPath, "worktree", "add", worktreePath, branchName)
		if !quiet {
			cmd.Stdout = os.Stderr
			cmd.Stderr = os.Stderr
		}
		return false, cmd.Run()
	}

	if !quiet {
		fmt.Fprintf(os.Stderr, "  Creating new branch %q\n", branchName)
	}
	cmd := exec.Command("git", "-C", repoPath, "worktree", "add", worktreePath, "-b", branchName)
	if !quiet {
		cmd.Stdout = os.Stderr
		cmd.Stderr = os.Stderr
	}
	return true, cmd.Run()
}

func cleanupWorkspaceWorktree(repoPath, worktreePath, branchName string, deleteBranch bool) {
	cmd := exec.Command("git", "-C", repoPath, "worktree", "remove", worktreePath, "--force")
	if err := cmd.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: git worktree remove failed: %v\n", err)
	}

	if _, err := os.Stat(worktreePath); err == nil {
		if err := os.RemoveAll(worktreePath); err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to remove directory %s: %v\n", worktreePath, err)
		}
	}

	if deleteBranch && workspaceBranchExists(repoPath, branchName) {
		inUse, err := workspaceBranchInUse(repoPath, branchName)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: failed to inspect worktree list for branch %s: %v\n", branchName, err)
		}
		if !inUse {
			deleteCmd := exec.Command("git", "-C", repoPath, "branch", "-D", branchName)
			if err := deleteCmd.Run(); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: failed to delete branch %s: %v\n", branchName, err)
			}
		}
	}
}

// createWorktreeInvite creates a single-use, short-lived CLI invite for
// bootstrapping another workspace identity in a sibling worktree. The current
// workspace's authenticated client creates the invite; the new worktree then
// accepts it via flowInvite.
func createWorktreeInvite(client *aweb.Client, aliasHint string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.SpawnCreateInvite(ctx, &awid.SpawnInviteCreateRequest{
		AliasHint:        aliasHint,
		MaxUses:          1,
		ExpiresInSeconds: 300, // 5 minutes
	})
	if err != nil {
		return "", fmt.Errorf("creating worktree invite: %w", err)
	}
	return resp.Token, nil
}

func isWorkspaceAliasTakenError(err error) bool {
	if err == nil {
		return false
	}
	code, ok := apiStructuredErrorCode(err)
	return ok && code == "ALIAS_TAKEN"
}

func workspaceBranchInUse(repoPath, branchName string) (bool, error) {
	cmd := exec.Command("git", "-C", repoPath, "worktree", "list", "--porcelain")
	out, err := cmd.Output()
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "branch ") && strings.TrimPrefix(line, "branch ") == "refs/heads/"+branchName {
			return true, nil
		}
	}
	return false, nil
}

func apiStructuredErrorCode(err error) (string, bool) {
	body, ok := awid.HTTPErrorBody(err)
	if !ok {
		return "", false
	}
	var envelope struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if json.Unmarshal([]byte(body), &envelope) != nil || strings.TrimSpace(envelope.Error.Code) == "" {
		return "", false
	}
	return strings.TrimSpace(envelope.Error.Code), true
}

func formatWorkspaceStatus(v any) string {
	out := v.(workspaceStatusOutput)
	var sb strings.Builder
	now := time.Now()

	sb.WriteString("## Self\n")
	sb.WriteString(fmt.Sprintf("- Alias: %s\n", out.Workspace.Alias))
	sb.WriteString(fmt.Sprintf("- Context: %s\n", out.ContextKind))
	if out.Workspace.Role != nil && strings.TrimSpace(*out.Workspace.Role) != "" {
		sb.WriteString(fmt.Sprintf("- Role: %s\n", strings.TrimSpace(*out.Workspace.Role)))
	}
	sb.WriteString(fmt.Sprintf("- Status: %s\n", out.Workspace.Status))
	if out.Workspace.Hostname != nil && strings.TrimSpace(*out.Workspace.Hostname) != "" {
		sb.WriteString(fmt.Sprintf("- Hostname: %s\n", strings.TrimSpace(*out.Workspace.Hostname)))
	}
	if out.Workspace.WorkspacePath != nil && strings.TrimSpace(*out.Workspace.WorkspacePath) != "" {
		sb.WriteString(fmt.Sprintf("- Path: %s\n", abbreviateUserHome(strings.TrimSpace(*out.Workspace.WorkspacePath))))
	}
	if out.Workspace.Repo != nil && strings.TrimSpace(*out.Workspace.Repo) != "" {
		sb.WriteString(fmt.Sprintf("- Repo: %s\n", strings.TrimSpace(*out.Workspace.Repo)))
	}
	if out.Workspace.Branch != nil && strings.TrimSpace(*out.Workspace.Branch) != "" {
		sb.WriteString(fmt.Sprintf("- Branch: %s\n", strings.TrimSpace(*out.Workspace.Branch)))
	}
	sb.WriteString(fmt.Sprintf("- Focus: %s\n", formatWorkspaceFocus(out.Workspace)))
	if apexLine := formatWorkspaceApexLine(out.Workspace); apexLine != "" {
		sb.WriteString(fmt.Sprintf("- %s\n", apexLine))
	}
	sb.WriteString(fmt.Sprintf("- Claims: %s\n", formatWorkspaceClaimsSummary(out.Workspace.Claims)))
	sb.WriteString(fmt.Sprintf("- Locks: %s\n", formatWorkspaceLocksSummary(out.Locks, now, 0)))

	sb.WriteString("\n## Team\n")
	if len(out.Team) == 0 {
		sb.WriteString("No other workspaces.\n")
	} else {
		for _, workspace := range out.Team {
			line := workspace.Alias
			if workspace.Role != nil && strings.TrimSpace(*workspace.Role) != "" {
				line += " (" + strings.TrimSpace(*workspace.Role) + ")"
			}
			line += " — " + workspace.Status
			if lastSeen := derefString(workspace.LastSeen); lastSeen != "" {
				line += ", seen " + formatTimeAgo(lastSeen)
			}
			sb.WriteString(line + "\n")
			if hostPathLine := formatWorkspaceHostPath(workspace); hostPathLine != "" {
				sb.WriteString(fmt.Sprintf("  %s\n", hostPathLine))
			}
			if repoLine := formatWorkspaceRepoBranch(workspace, true); repoLine != "" {
				sb.WriteString(fmt.Sprintf("  %s\n", repoLine))
			}
			sb.WriteString(fmt.Sprintf("  Focus: %s\n", formatWorkspaceFocus(workspace)))
			if apexLine := formatWorkspaceApexLine(workspace); apexLine != "" {
				sb.WriteString(fmt.Sprintf("  %s\n", apexLine))
			}
			sb.WriteString(fmt.Sprintf("  Claims: %s\n", formatWorkspaceClaimsSummary(workspace.Claims)))
			sb.WriteString(fmt.Sprintf("  Locks: %s\n", formatWorkspaceLocksSummary(out.TeamLocks[workspace.WorkspaceID], now, 3)))
		}
	}

	sb.WriteString(fmt.Sprintf("\nEscalations pending: %d\n", out.EscalationsPending))
	if out.ConflictCount > 0 {
		sb.WriteString(fmt.Sprintf("Claim conflicts: %d\n", out.ConflictCount))
	}
	return sb.String()
}

func formatWorkspaceHostPath(workspace aweb.WorkspaceInfo) string {
	hostname := strings.TrimSpace(derefString(workspace.Hostname))
	path := strings.TrimSpace(derefString(workspace.WorkspacePath))
	if path != "" {
		path = abbreviateUserHome(path)
	}
	switch {
	case hostname != "" && path != "":
		return fmt.Sprintf("Host: %s  Path: %s", hostname, path)
	case hostname != "":
		return fmt.Sprintf("Host: %s", hostname)
	case path != "":
		return fmt.Sprintf("Path: %s", path)
	default:
		return ""
	}
}

func formatWorkspaceRepoBranch(workspace aweb.WorkspaceInfo, hideDefaultBranch bool) string {
	repo := strings.TrimSpace(derefString(workspace.Repo))
	branch := strings.TrimSpace(derefString(workspace.Branch))
	if hideDefaultBranch && isDefaultBranch(branch) {
		branch = ""
	}
	switch {
	case repo != "" && branch != "":
		return fmt.Sprintf("Repo: %s  Branch: %s", repo, branch)
	case repo != "":
		return fmt.Sprintf("Repo: %s", repo)
	case branch != "":
		return fmt.Sprintf("Branch: %s", branch)
	default:
		return ""
	}
}

func formatWorkspaceFocus(workspace aweb.WorkspaceInfo) string {
	focusRef := strings.TrimSpace(derefString(workspace.FocusTaskRef))
	if focusRef == "" {
		return "none"
	}
	if focusTitle := strings.TrimSpace(derefString(workspace.FocusTaskTitle)); focusTitle != "" {
		return fmt.Sprintf("%s \"%s\"", focusRef, focusTitle)
	}
	return focusRef
}

func formatWorkspaceApexLine(workspace aweb.WorkspaceInfo) string {
	apexID := strings.TrimSpace(derefString(workspace.ApexID))
	if apexID == "" {
		return ""
	}
	prefix := "Working on"
	if strings.EqualFold(derefString(workspace.ApexType), "epic") {
		prefix = "Epic"
	}
	if apexTitle := strings.TrimSpace(derefString(workspace.ApexTitle)); apexTitle != "" {
		return fmt.Sprintf("%s: %s (%s)", prefix, apexID, apexTitle)
	}
	return fmt.Sprintf("%s: %s", prefix, apexID)
}

func formatWorkspaceClaimsSummary(claims []aweb.WorkspaceClaim) string {
	if len(claims) == 0 {
		return "none"
	}
	parts := make([]string, 0, len(claims))
	for _, claim := range claims {
		part := strings.TrimSpace(claim.TaskRef)
		if part == "" {
			part = strings.TrimSpace(claim.BeadID)
		}
		if title := strings.TrimSpace(derefString(claim.Title)); title != "" {
			part += fmt.Sprintf(" \"%s\"", title)
		}
		if strings.TrimSpace(claim.ClaimedAt) != "" {
			part += fmt.Sprintf(" (%s)", formatTimeAgo(claim.ClaimedAt))
			if isClaimStale(claim.ClaimedAt) {
				part += " [stale]"
			}
		}
		parts = append(parts, part)
	}
	return strings.Join(parts, ", ")
}

func formatWorkspaceLocksSummary(locks []aweb.ReservationView, now time.Time, limit int) string {
	if len(locks) == 0 {
		return "none"
	}
	display := locks
	if limit > 0 && len(display) > limit {
		display = display[:limit]
	}
	parts := make([]string, 0, len(display)+1)
	for _, lock := range display {
		part := fmt.Sprintf("%s (TTL: %s", lock.ResourceKey, formatDuration(ttlRemainingSeconds(lock.ExpiresAt, now)))
		if reason := formatWorkspaceLockReason(lock.Metadata); reason != "" {
			part += fmt.Sprintf(", reason: %s", reason)
		}
		part += ")"
		parts = append(parts, part)
	}
	if limit > 0 && len(locks) > limit {
		parts = append(parts, fmt.Sprintf("...%d more", len(locks)-limit))
	}
	return strings.Join(parts, ", ")
}

func formatWorkspaceLockReason(metadata map[string]any) string {
	if len(metadata) == 0 {
		return ""
	}
	reason, _ := metadata["reason"].(string)
	return strings.TrimSpace(reason)
}

func derefString(v *string) string {
	if v == nil {
		return ""
	}
	return strings.TrimSpace(*v)
}

func abbreviateUserHome(path string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return path
	}
	home = filepath.Clean(home)
	path = filepath.Clean(path)
	if path == home {
		return "~"
	}
	prefix := home + string(filepath.Separator)
	if strings.HasPrefix(path, prefix) {
		return "~" + string(filepath.Separator) + strings.TrimPrefix(path, prefix)
	}
	return path
}
