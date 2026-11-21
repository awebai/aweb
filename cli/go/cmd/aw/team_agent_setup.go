package main

import (
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
)

type teamAgentSetup struct {
	Membership        teamAgentMembershipPreparation
	CreatorHome       awconfig.IdentityHome
	WorktreeAnchorDir string
	WorkDir           string
	ExpectedTeamID    string
	AssertionSource   teamIDAssertionSource
	LayoutOnly        bool
}

// createAndSetUpTeamAgent keeps prepared or admitted credentials when setup
// remains incomplete. Only failures without a retained identity can roll back
// local files (docs/identity.md#provisioned-members-and-encryption-discovery).
func createAndSetUpTeamAgent(input teamAgentSetup) (teamID string, resultErr error) {
	plan := input.Membership.Plan
	rollback, err := captureAgentHomeRollback(plan.HomeDir)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(plan.HomeDir, 0o755); err != nil {
		homeRollbackErr := rollback.Rollback()
		return "", withLocalProvisioningRollback(localProvisioningRollback{Cause: err, Rollback: homeRollbackErr})
	}
	if input.LayoutOnly {
		return "", nil
	}
	if err := prepareTeamAgentMembership(input.Membership); err != nil {
		if retainUnfinishedProvisioningIdentity(err) {
			return "", err
		}
		homeRollbackErr := rollback.Rollback()
		return "", withLocalProvisioningRollback(localProvisioningRollback{Cause: err, Rollback: homeRollbackErr})
	}
	setupFailure := func(cause error) error {
		return retainProvisionedSetupFailure(provisionedSetupFailure{Cause: cause, Plan: *plan, CreatorDir: input.Membership.SourceDir, CreatorHome: input.CreatorHome, Authority: input.Membership.Authority.Mode, WorkDir: input.WorkDir})
	}
	if expected := strings.TrimSpace(input.ExpectedTeamID); expected != "" && !strings.EqualFold(strings.TrimSpace(plan.TeamID), expected) {
		return "", setupFailure(teamIDAssertionMismatchError(expected, strings.TrimSpace(plan.TeamID), input.AssertionSource))
	}
	if err := completePlannedTeamAgentProfile(teamAgentProfileSetup{
		Plan: plan, Home: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(plan.HomeDir), Source: awconfig.IdentityHomeDefault},
	}); err != nil {
		return "", setupFailure(err)
	}
	teamID = strings.TrimSpace(plan.TeamID)
	if err := setupTeamAddedAgentWorktree(input.WorktreeAnchorDir, *plan, input.WorkDir); err != nil {
		return teamID, setupFailure(err)
	}
	return teamID, nil
}
