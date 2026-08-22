package main

import (
	"strings"

	"github.com/awebai/aw/awconfig"
)

// workspaceConnectRecoveryCommand recovers the service URL cached when a team
// certificate was installed. That state deliberately exists before
// workspace.yaml, so an identity-only join can always be completed without the
// operator having to rediscover which service issued the invite.
func workspaceConnectRecoveryCommand(workingDir, identityHome string) (string, bool) {
	var state *awconfig.TeamState
	var err error
	if strings.TrimSpace(identityHome) != "" {
		state, err = awconfig.LoadTeamStateFromIdentityHome(identityHome)
	} else {
		state, err = awconfig.LoadTeamState(workingDir)
	}
	if err == nil && state != nil {
		membership := state.ActiveMembership()
		if membership != nil {
			if raw := strings.TrimSpace(membership.AwebURL); raw != "" {
				if normalized, normalizeErr := validateInviteAwebURL(raw); normalizeErr == nil {
					return workspaceConnectCommand(normalized), true
				}
			}
			if raw := awebURLForTeamInviteAt(workingDir, identityHome, membership.TeamID); raw != "" {
				if normalized, normalizeErr := validateInviteAwebURL(raw); normalizeErr == nil {
					return workspaceConnectCommand(normalized), true
				}
			}
		}
	}
	return "", false
}

func workspaceConnectCommand(awebURL string) string {
	return formatShellCommand([]string{"aw", "workspace", "connect", "--service", awebURL})
}
