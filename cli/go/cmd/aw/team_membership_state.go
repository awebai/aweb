package main

import (
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"os"
	"path/filepath"
	"strings"
)

func upsertAcceptedTeamMembershipState(workingDir string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, registryURL, awebURL string, setActive bool, identityHomes ...string) error {
	if output == nil || cert == nil {
		return fmt.Errorf("accepted team membership is required")
	}
	teamState, err := loadOptionalTeamState(workingDir, identityHomes...)
	if err != nil {
		return err
	}
	if teamState == nil {
		teamState = &awconfig.TeamState{}
	}
	joinedAt := strings.TrimSpace(cert.IssuedAt)
	if existing := teamState.Membership(strings.TrimSpace(output.TeamID)); existing != nil {
		if strings.TrimSpace(registryURL) == "" {
			registryURL = strings.TrimSpace(existing.RegistryURL)
		}
		if strings.TrimSpace(awebURL) == "" {
			awebURL = strings.TrimSpace(existing.AwebURL)
		}
		// JoinedAt is the original join time; a re-accept or certificate
		// rotation must not overwrite it with the newer cert.IssuedAt.
		if strings.TrimSpace(existing.JoinedAt) != "" {
			joinedAt = strings.TrimSpace(existing.JoinedAt)
		}
	}
	teamState.AddMembership(awconfig.TeamMembership{
		TeamID:      strings.TrimSpace(output.TeamID),
		Alias:       strings.TrimSpace(output.Alias),
		CertPath:    filepath.ToSlash(strings.TrimSpace(output.CertPath)),
		JoinedAt:    joinedAt,
		RegistryURL: strings.TrimSpace(registryURL),
		AwebURL:     strings.TrimSpace(awebURL),
	})
	if setActive || strings.TrimSpace(teamState.ActiveTeam) == "" {
		teamState.ActiveTeam = strings.TrimSpace(output.TeamID)
	}
	if len(identityHomes) > 0 && strings.TrimSpace(identityHomes[0]) != "" {
		return awconfig.SaveTeamStateToIdentityHome(identityHomes[0], teamState)
	}
	return awconfig.SaveTeamState(workingDir, teamState)
}

func loadOptionalTeamState(workingDir string, identityHomes ...string) (*awconfig.TeamState, error) {
	var teamState *awconfig.TeamState
	var err error
	if len(identityHomes) > 0 && strings.TrimSpace(identityHomes[0]) != "" {
		teamState, err = awconfig.LoadTeamStateFromIdentityHome(identityHomes[0])
	} else {
		teamState, err = awconfig.LoadTeamState(workingDir)
	}
	if err == nil {
		return teamState, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, err
}
