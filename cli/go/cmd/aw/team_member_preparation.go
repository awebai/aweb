package main

import "github.com/awebai/aw/awconfig"

type teamAgentMembershipPreparation struct {
	SourceDir string
	Plan      *teamHumanAddedAgent
	Authority creationAuthority
	APIKey    string
}

func prepareTeamAgentMembership(input teamAgentMembershipPreparation) error {
	plan := input.Plan
	accepted := plan.ResumeMembership
	if accepted != nil {
		if err := completeProvisionedTeamMembership(provisionedTeamMembership{WorkingDir: plan.HomeDir, Home: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(plan.HomeDir)}, AwebURL: accepted.AwebURL}); err != nil {
			return err
		}
	} else {
		var err error
		accepted, err = resolveOrCreateTeamMemberIdentity(input)
		if err != nil {
			return err
		}
	}
	plan.Alias, plan.TeamID, plan.CertPath = accepted.Output.Alias, accepted.Output.TeamID, accepted.Output.CertPath
	plan.ProfileRoleConnected = input.Authority.Mode == creationAuthorityAPI && plan.ResumeMembership == nil
	return nil
}
