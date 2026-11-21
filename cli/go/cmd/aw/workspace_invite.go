package main

import (
	"context"
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
		plan.Source.RegistryURL, err = resolveRegistryAuthority(context.Background(), registryAuthorityRequest{
			Kind: registryTeamRoute, WorkingDir: rootDir, IdentityHome: identityHome, AwebURL: awebURL, TeamID: teamID, Domain: domain,
		})
		if err != nil {
			return workspaceTeamInvite{}, err
		}
	}
	created, err := mintPlannedTeamInvite(teamInviteMintRequest{Plan: plan, Scope: teamInviteMemberScope(scope)})
	if err != nil {
		return workspaceTeamInvite{}, err
	}
	return workspaceTeamInvite{Token: created.Token, AwebURL: awebURL, ExpiresAt: created.ExpiresAt}, nil
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
