package main

import (
	"github.com/awebai/aw/awconfig"
	"strings"
)

type teamAgentMembershipState uint8

const (
	teamAgentMembershipReused teamAgentMembershipState = iota
	teamAgentMembershipCreated
)

type teamAgentMembershipPreparation struct {
	SourceDir string
	Plan      *teamHumanAddedAgent
	Authority creationAuthority
	APIKey    string
}
type preparedTeamAgentMembership struct {
	State    teamAgentMembershipState
	Accepted *acceptedTeamInvite
}

func prepareTeamAgentMembership(input teamAgentMembershipPreparation) (preparedTeamAgentMembership, error) {
	plan := input.Plan
	apiKeyBootstrapMode := input.Authority.Mode == creationAuthorityAPI
	if plan.Profile != nil {
		home := awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(plan.HomeDir), Source: awconfig.IdentityHomeDefault}
		if selected, err := resolveSelectionAtIdentityHome(plan.HomeDir, "", home); err == nil && strings.TrimSpace(selected.TeamID) != "" {
			plan.Alias, plan.TeamID = strings.TrimSpace(selected.Alias), strings.TrimSpace(selected.TeamID)
			return preparedTeamAgentMembership{State: teamAgentMembershipReused}, nil
		}
	}
	accepted, err := resolveOrCreateTeamMemberIdentity(input.SourceDir, *plan, apiKeyBootstrapMode, input.APIKey)
	if err != nil {
		return preparedTeamAgentMembership{}, err
	}
	plan.Alias, plan.TeamID, plan.CertPath = accepted.Output.Alias, accepted.Output.TeamID, accepted.Output.CertPath
	plan.ProfileRoleConnected = apiKeyBootstrapMode
	return preparedTeamAgentMembership{State: teamAgentMembershipCreated, Accepted: accepted}, nil
}
