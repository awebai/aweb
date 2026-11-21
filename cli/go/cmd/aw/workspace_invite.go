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
	Token   string
	AwebURL string
}

func createWorkspaceTeamInviteAt(workingDir, identityHome string) (workspaceTeamInvite, error) {
	return createWorkspaceTeamInviteForTeamAt(workingDir, identityHome, "")
}

func createWorkspaceTeamInviteForTeamAt(workingDir, identityHome, explicitTeamID string) (workspaceTeamInvite, error) {
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

	home := awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(workingDir)}
	if identityHome != "" {
		home = awconfig.IdentityHome{Root: identityHome, Source: awconfig.IdentityHomeFlag}
	}
	plan, err := planTeamInvite(teamInviteSource{WorkingDir: workingDir, Home: home, Domain: domain, Team: team, AwebURL: awebURL})
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	// Hosted minting uses the selected service's authority and needs no
	// controller registry discovery (docs/byot-onboarding-contract.md:36-46).
	if plan.Kind == inviteAuthorityController {
		plan.Source.RegistryURL = registryURLForTeamInviteAt(rootDir, identityHome, domain, awebURL)
	}
	created, err := mintPlannedTeamInvite(teamInviteMintRequest{Plan: plan, Scope: inviteMemberLocal})
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	return workspaceTeamInvite{Token: created.Token, AwebURL: awebURL}, nil
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
