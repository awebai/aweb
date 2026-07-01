package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type workspaceTeamInvite struct {
	Token   string
	AwebURL string
}

func addWorktreeViaPrimaryInvite(
	primaryDir, worktreePath, root, branchName string, branchCreated bool,
	sourceServerURL, alias, role string, state *awconfig.WorktreeWorkspace,
) (connectOutput, error) {
	invite, err := createWorkspaceTeamInviteFromDir(primaryDir)
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("create team invite from primary workspace: %w", err)
	}
	if strings.TrimSpace(invite.AwebURL) == "" {
		invite.AwebURL = sourceServerURL
	}

	accepted, err := acceptTeamInviteWithPreferredAwebURL(worktreePath, invite.Token, strings.TrimSpace(invite.AwebURL), alias)
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
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

func createWorkspaceTeamInviteFromDir(workingDir string) (workspaceTeamInvite, error) {
	workspace, teamState, rootDir, err := awconfig.LoadWorkspaceAndTeamState(workingDir)
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	membership := awconfig.ActiveMembershipFor(workspace, teamState)
	if membership == nil {
		return workspaceTeamInvite{}, fmt.Errorf("workspace %s has no active team", workingDir)
	}
	teamID := strings.TrimSpace(membership.TeamID)
	domain, team, err := awid.ParseTeamID(teamID)
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	awebURL := awebURLForTeamInvite(rootDir, teamID)
	if awebURL == "" {
		awebURL = strings.TrimSpace(workspace.AwebURL)
	}

	hasTeamKey, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	var token string
	if hasTeamKey {
		registryURL := registryURLForTeamInvite(rootDir, domain, awebURL)
		_, token, err = createTeamInviteToken(domain, team, registryURL, awebURL, true)
	} else if strings.TrimSpace(awebURL) != "" {
		_, token, err = createHostedTeamInviteToken(workingDir, teamID, true)
	} else {
		_, token, err = createTeamInviteToken(domain, team, "", awebURL, true)
	}
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	return workspaceTeamInvite{Token: token, AwebURL: awebURL}, nil
}

func acceptTeamInviteWithPreferredAwebURL(homeDir, token, preferredAwebURL, alias string) (*acceptedTeamInvite, error) {
	preferredAwebURL = strings.TrimSpace(preferredAwebURL)
	if preferredAwebURL == "" {
		return acceptTeamInviteWithDetails(homeDir, token, teamAcceptInviteOptions{Name: alias, Scope: awid.IdentityModeLocal})
	}

	previous, hadPrevious := os.LookupEnv("AWEB_URL")
	if err := os.Setenv("AWEB_URL", preferredAwebURL); err != nil {
		return nil, err
	}
	defer func() {
		if hadPrevious {
			_ = os.Setenv("AWEB_URL", previous)
		} else {
			_ = os.Unsetenv("AWEB_URL")
		}
	}()
	return acceptTeamInviteWithDetails(homeDir, token, teamAcceptInviteOptions{Name: alias, Scope: awid.IdentityModeLocal})
}
