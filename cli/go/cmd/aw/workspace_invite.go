package main

import (
	"fmt"
	"os"
	"path/filepath"
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

func acceptTeamInviteWithPreferredAwebURL(primaryDir, primaryIdentityHome, homeDir, token, preferredAwebURL, alias string) (*acceptedTeamInvite, error) {
	preferredAwebURL = strings.TrimSpace(preferredAwebURL)
	opts := teamAcceptInviteOptions{
		IdentityHome: filepath.Join(filepath.Clean(homeDir), ".aw"),
		Name:         alias,
		Scope:        awid.IdentityModeLocal,
	}
	if preferredAwebURL == "" {
		return acceptProvisionedTeamInvite(primaryDir, primaryIdentityHome, homeDir, token, opts)
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
	return acceptProvisionedTeamInvite(primaryDir, primaryIdentityHome, homeDir, token, opts)
}
