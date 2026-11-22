package main

import (
	"fmt"
	"github.com/awebai/aw/awconfig"
)

type worktreeSetupFailure struct {
	Creation worktreeAgentCreation
	AwebURL  string
	Cause    error
}

// retainWorktreeSetupFailure keeps an issued member available for admission
// reconciliation and ordered retirement; registry revocation alone does not
// establish coordination cleanup (docs/aweb-sot.md §Self-retirement).
func retainWorktreeSetupFailure(input worktreeSetupFailure) error {
	home := awconfig.WorktreeIdentityHome(input.Creation.WorktreePath)
	command := workspaceConnectCommandForIdentityHome(input.AwebURL, home)
	return &provisionedMembershipIncompleteError{cause: fmt.Errorf("%w; the worktree and its issued member are retained at %s. Check the reported membership problem with your team, then run `%s` there to finish admission. Use the team's ordered remove-agent operation to retire it before deleting its credentials.", input.Cause, input.Creation.WorktreePath, command)}
}
