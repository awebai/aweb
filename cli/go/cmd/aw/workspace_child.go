package main

import (
	"errors"
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"os"
	"path/filepath"
	"strings"
)

// worktreeAgentCreation keeps the creator, new home and cleanup context
// explicit across the controller, signed-invitation and setup-key paths.
type worktreeAgentCreation struct {
	WorkingDir    string
	CreatorHome   awconfig.IdentityHome
	WorktreePath  string
	RepoRoot      string
	BranchName    string
	BranchCreated bool
	ServerURL     string
	TeamID        string
	Alias         string
	Role          string
	Workspace     *awconfig.WorktreeWorkspace
	APIKey        string
}

func addWorktreeViaLocalTeamKey(input worktreeAgentCreation) (connectOutput, error) {
	worktreePath, root, branchName := input.WorktreePath, input.RepoRoot, input.BranchName
	branchCreated := input.BranchCreated
	teamID, workingDir := input.TeamID, input.WorkingDir
	sourceServerURL, sourceIdentityHome := input.ServerURL, externalIdentityHomeRoot(input.CreatorHome)
	alias, role, state := input.Alias, input.Role, input.Workspace
	teamDomain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return connectOutput{}, err
	}
	registryURL, err := resolveWorkspaceTeamRegistryURLAt(workingDir, sourceIdentityHome, sourceServerURL, teamDomain)
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, err
	}

	created, err := mintPlannedTeamInvite(teamInviteMintRequest{
		Plan: teamInvitePlan{Kind: inviteAuthorityController, Source: teamInviteSource{
			WorkingDir: workingDir, Home: input.CreatorHome, Domain: teamDomain, Team: teamName,
			RegistryURL: registryURL, AwebURL: sourceServerURL,
		}},
		Scope: inviteMemberLocal,
	})
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("create local team invite for %s: %w", teamID, err)
	}
	acceptedInvite, err := acceptTeamInviteWithDetails(worktreePath, created.Token, teamAcceptInviteOptions{
		IdentityHome: filepath.Join(filepath.Clean(worktreePath), ".aw"),
		Name:         alias,
		Scope:        awid.IdentityModeLocal,
	})
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("accept team invite in new worktree: %w", err)
	}

	rollback := func(step string, cause error) (connectOutput, error) {
		rollbackErr := revokeAcceptedTeamCertificate(acceptedInvite)
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		if rollbackErr != nil {
			return connectOutput{}, fmt.Errorf("%s: %w (rollback revoke failed: %v)", step, cause, rollbackErr)
		}
		return connectOutput{}, fmt.Errorf("%s: %w", step, cause)
	}

	fmt.Fprintln(os.Stderr, "Connecting new workspace...")
	connectResult, err := initCertificateConnectWithOptions(worktreePath, sourceServerURL, certificateConnectOptions{
		Role:      role,
		HumanName: strings.TrimSpace(state.HumanName),
		AgentType: strings.TrimSpace(state.AgentType),
	})
	if err != nil {
		return rollback("connect new worktree", err)
	}
	if strings.TrimSpace(connectResult.Alias) != "" && !strings.EqualFold(strings.TrimSpace(connectResult.Alias), alias) {
		return rollback(
			"validate new worktree name",
			fmt.Errorf("new workspace connected as name %q, expected %q", strings.TrimSpace(connectResult.Alias), alias),
		)
	}
	return connectResult, nil
}

func addWorktreeViaCloudBootstrap(input worktreeAgentCreation) (connectOutput, error) {
	worktreePath, root, branchName := input.WorktreePath, input.RepoRoot, input.BranchName
	branchCreated := input.BranchCreated
	sourceServerURL, alias, role, state := input.ServerURL, input.Alias, input.Role, input.Workspace
	apiKey := input.APIKey
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, usageError(
			"no local team key and no workspace API key; " +
				"run `aw id team create` to manage teams locally, " +
				"or re-initialize with an API key from the dashboard",
		)
	}

	awebURL, err := normalizeAPIKeyBootstrapBaseURL(sourceServerURL)
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, err
	}

	fmt.Fprintln(os.Stderr, "Requesting certificate from cloud...")
	result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir:   worktreePath,
		IdentityHome: filepath.Join(filepath.Clean(worktreePath), ".aw"),
		AwebURL:      awebURL,
		APIKey:       apiKey,
		Alias:        alias,
		Role:         role,
		HumanName:    strings.TrimSpace(state.HumanName),
		AgentType:    strings.TrimSpace(state.AgentType),
		Global:       false,
	})
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("cloud bootstrap for new worktree: %w", err)
	}
	if strings.TrimSpace(result.Alias) != "" && !strings.EqualFold(strings.TrimSpace(result.Alias), alias) {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("new workspace connected as name %q, expected %q", strings.TrimSpace(result.Alias), alias)
	}
	return result, nil
}

func addWorktreeViaPrimaryInvite(input worktreeAgentCreation) (connectOutput, error) {
	worktreePath, root, branchName := input.WorktreePath, input.RepoRoot, input.BranchName
	branchCreated := input.BranchCreated
	primaryDir, primaryIdentityHome := input.WorkingDir, externalIdentityHomeRoot(input.CreatorHome)
	sourceServerURL, alias, role, state := input.ServerURL, input.Alias, input.Role, input.Workspace
	invite, err := createWorkspaceTeamInviteAt(primaryDir, primaryIdentityHome)
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("create team invite from primary workspace: %w", err)
	}
	if strings.TrimSpace(invite.AwebURL) == "" {
		invite.AwebURL = sourceServerURL
	}

	accepted, err := acceptTeamInviteWithPreferredAwebURL(primaryDir, primaryIdentityHome, worktreePath, invite.Token, strings.TrimSpace(invite.AwebURL), alias)
	if err != nil {
		var pending *hostedInviteSignaturePendingError
		if !errors.As(err, &pending) {
			cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		}
		return connectOutput{}, fmt.Errorf("accept team invite in new worktree: %w", err)
	}

	awebURL := strings.TrimSpace(accepted.AwebURL)
	if awebURL == "" {
		awebURL = strings.TrimSpace(invite.AwebURL)
	}
	if awebURL == "" {
		awebURL = strings.TrimSpace(sourceServerURL)
	}
	awebURL = awebURLOrDefault(awebURL)
	if err := upsertAcceptedTeamMembershipState(worktreePath, accepted.Output, accepted.Certificate, accepted.RegistryURL, awebURL, true); err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, err
	}

	fmt.Fprintln(os.Stderr, "Connecting new workspace...")
	connectResult, err := initCertificateConnectWithOptions(worktreePath, awebURL, certificateConnectOptions{
		Role:      role,
		HumanName: strings.TrimSpace(state.HumanName),
		AgentType: strings.TrimSpace(state.AgentType),
	})
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("connect new worktree: %w", err)
	}
	if strings.TrimSpace(connectResult.Alias) != "" && !strings.EqualFold(strings.TrimSpace(connectResult.Alias), alias) {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("new workspace connected as name %q, expected %q", strings.TrimSpace(connectResult.Alias), alias)
	}
	return connectResult, nil
}
