package main

import (
	"fmt"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type workspaceTeamInvite struct {
	ExpiresAt string
	Token     string
	AwebURL   string
}

func createWorkspaceTeamInviteAt(workingDir, identityHome string) (workspaceTeamInvite, error) {
	return createWorkspaceTeamInviteForTeamAt(workingDir, identityHome, "", awid.IdentityModeLocal)
}

func createWorkspaceTeamInviteForTeamAt(workingDir, identityHome, explicitTeamID, scope string) (workspaceTeamInvite, error) {
	localMember := scope == awid.IdentityModeLocal
	workspace, teamState, rootDir, err := loadCurrentWorkspaceAndTeamState(workingDir, identityHome)
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	teamID := strings.TrimSpace(explicitTeamID)
	if teamID == "" {
		membership := awconfig.ActiveMembershipFor(workspace, teamState)
		if membership == nil {
			return workspaceTeamInvite{}, fmt.Errorf("workspace %s has no active team", workingDir)
		}
		teamID = strings.TrimSpace(membership.TeamID)
	} else if teamState == nil || teamState.Membership(teamID) == nil {
		return workspaceTeamInvite{}, usageError("team %q is not present in --join-from memberships", teamID)
	}
	domain, team, err := awid.ParseTeamID(teamID)
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	awebURL := awebURLForTeamInviteAt(rootDir, identityHome, teamID)
	if awebURL == "" {
		awebURL = strings.TrimSpace(workspace.AwebURL)
	}

	hasTeamKey, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	var token, expiry string
	if hasTeamKey {
		registryURL := registryURLForTeamInviteAt(rootDir, identityHome, domain, awebURL)
		_, token, err = createTeamInviteTokenAt(domain, team, registryURL, awebURL, localMember, workingDir, identityHome)
	} else if strings.TrimSpace(awebURL) != "" {
		var created *awid.SpawnCreateInviteResponse
		created, err = createHostedTeamInvite(workingDir, identityHome, teamID, localMember)
		if err == nil {
			token, expiry = created.Token, created.ExpiresAt
		}
	} else {
		_, token, err = createTeamInviteTokenAt(domain, team, "", awebURL, localMember, workingDir, identityHome)
	}
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	return workspaceTeamInvite{Token: token, AwebURL: awebURL, ExpiresAt: expiry}, nil
}

type workspaceInviteAcceptance struct {
	SourceDir  string
	SourceHome string
	ChildDir   string
	Invite     workspaceTeamInvite
	Alias      string
}

// acceptWorkspaceTeamInvite names the selected service in the acceptance
// request rather than changing selection for other operations in this process
// (docs/cli-identity-selection.md:13-33).
func acceptWorkspaceTeamInvite(input workspaceInviteAcceptance) (*acceptedTeamInvite, error) {
	return acceptProvisionedTeamInvite(input.SourceDir, input.SourceHome, input.ChildDir, input.Invite.Token, teamAcceptInviteOptions{
		IdentityHome: awconfig.WorktreeIdentityHome(input.ChildDir), Name: input.Alias,
		Scope: awid.IdentityModeLocal, AwebURL: strings.TrimSpace(input.Invite.AwebURL),
	})
}
