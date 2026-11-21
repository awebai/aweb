package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// worktreeAgentCreation keeps the creator, new home and cleanup context
// explicit across the controller, signed-invitation and setup-key paths.
type worktreeAgentCreation struct {
	WorkingDir      string
	CreatorHome     awconfig.IdentityHome
	WorktreePath    string
	RepoRoot        string
	BranchName      string
	BranchCreated   bool
	ServerURL       string
	TeamID          string
	Alias           string
	Role            string
	Workspace       *awconfig.WorktreeWorkspace
	APIKey          string
	SelectedTeam    *apiKeyCreationTeam
	TeamRegistryURL string
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
	registryURL, err := resolveWorkspaceTeamRegistryURL(context.Background(), registryAuthorityRequest{
		WorkingDir: workingDir, IdentityHome: sourceIdentityHome, AwebURL: sourceServerURL, Domain: teamDomain, TeamID: teamID,
	})
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
	_, err = acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: worktreePath,
		Token:      created.Token,
		Options: teamAcceptInviteOptions{
			IdentityHome: filepath.Join(filepath.Clean(worktreePath), ".aw"),
			Name:         alias,
			Scope:        awid.IdentityModeLocal,
		},
	})
	if err != nil {
		if !retainUnfinishedProvisioningIdentity(err) {
			cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		}
		return connectOutput{}, fmt.Errorf("accept team invite in new worktree: %w", err)
	}

	retain := func(step string, cause error) (connectOutput, error) {
		return connectOutput{}, retainWorktreeSetupFailure(worktreeSetupFailure{Creation: input, Cause: fmt.Errorf("%s: %w", step, cause), AwebURL: sourceServerURL})
	}

	fmt.Fprintln(os.Stderr, "Connecting new workspace...")
	connectResult, err := connectProvisionedTeamMembership(provisionedTeamMembership{WorkingDir: worktreePath, Home: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(worktreePath)}, AwebURL: sourceServerURL, Role: role, HumanName: strings.TrimSpace(state.HumanName), AgentType: strings.TrimSpace(state.AgentType)})
	if err != nil {
		return retain("connect new worktree", err)
	}
	if strings.TrimSpace(connectResult.Alias) != "" && !strings.EqualFold(strings.TrimSpace(connectResult.Alias), alias) {
		return retain(
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
	apiKey, selectedTeam := input.APIKey, input.SelectedTeam
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
	request := apiKeyInitRequest{
		SelectedTeam:          selectedTeam,
		WorkingDir:            worktreePath,
		IdentityHome:          filepath.Join(filepath.Clean(worktreePath), ".aw"),
		AwebURL:               awebURL,
		RegistryURL:           input.TeamRegistryURL,
		APIKey:                apiKey,
		Alias:                 alias,
		Role:                  role,
		HumanName:             strings.TrimSpace(state.HumanName),
		AgentType:             strings.TrimSpace(state.AgentType),
		Global:                false,
		EncryptionPublication: encryptionPublicationRequiredService,
	}
	result, err := runAPIKeyBootstrapInit(request)
	if err != nil {
		if !retainUnfinishedProvisioningIdentity(err) {
			cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		}
		return connectOutput{}, fmt.Errorf("cloud bootstrap for new worktree: %w", apiKeyCreationRecoveryAdvice(request, err))
	}
	if strings.TrimSpace(result.Alias) != "" && !strings.EqualFold(strings.TrimSpace(result.Alias), alias) {
		return connectOutput{}, retainWorktreeSetupFailure(worktreeSetupFailure{Creation: input, AwebURL: sourceServerURL, Cause: fmt.Errorf("new workspace connected as name %q, expected %q", strings.TrimSpace(result.Alias), alias)})
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

	accepted, err := acceptWorkspaceTeamInvite(workspaceInviteAcceptance{SourceDir: primaryDir, SourceHome: primaryIdentityHome, ChildDir: worktreePath, Invite: invite, Alias: alias})
	if err != nil {
		if !retainUnfinishedProvisioningIdentity(err) {
			cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		}
		return connectOutput{}, fmt.Errorf("accept team invite in new worktree: %w", err)
	}

	if accepted == nil || accepted.Certificate == nil || accepted.Output == nil {
		return connectOutput{}, retainWorktreeSetupFailure(worktreeSetupFailure{Creation: input, AwebURL: sourceServerURL, Cause: fmt.Errorf("accepted invitation is missing its membership installation material")})
	}
	awebURL := strings.TrimSpace(accepted.AwebURL)
	if awebURL == "" {
		awebURL = strings.TrimSpace(invite.AwebURL)
	}
	if awebURL == "" {
		awebURL = strings.TrimSpace(sourceServerURL)
	}
	awebURL = awebURLOrDefault(awebURL)
	if err := upsertAcceptedTeamMembershipState(teamMembershipStateUpdate{
		Location:    teamMembershipLocation{WorkingDir: worktreePath, IdentityHome: ""},
		Output:      accepted.Output,
		Certificate: accepted.Certificate,
		RegistryURL: accepted.RegistryURL,
		AwebURL:     awebURL,
		Activation:  membershipMakeActive,
	}); err != nil {
		return connectOutput{}, retainProvisionedRecordFailure(provisionedRecordFailure{Home: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(worktreePath)}, Certificate: *accepted.Certificate, RegistryURL: accepted.RegistryURL, AwebURL: awebURL, Cause: err})
	}

	fmt.Fprintln(os.Stderr, "Connecting new workspace...")
	connectResult, err := connectProvisionedTeamMembership(provisionedTeamMembership{WorkingDir: worktreePath, Home: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(worktreePath)}, AwebURL: awebURL, Role: role, HumanName: strings.TrimSpace(state.HumanName), AgentType: strings.TrimSpace(state.AgentType)})
	if err != nil {
		return connectOutput{}, retainWorktreeSetupFailure(worktreeSetupFailure{Creation: input, AwebURL: awebURL, Cause: fmt.Errorf("connect new worktree: %w", err)})
	}
	if strings.TrimSpace(connectResult.Alias) != "" && !strings.EqualFold(strings.TrimSpace(connectResult.Alias), alias) {
		return connectOutput{}, retainWorktreeSetupFailure(worktreeSetupFailure{Creation: input, AwebURL: awebURL, Cause: fmt.Errorf("new workspace connected as name %q, expected %q", strings.TrimSpace(connectResult.Alias), alias)})
	}
	return connectResult, nil
}
