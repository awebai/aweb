package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// recordMembershipOptions controls the two steps that legitimately differ across
// accept/enroll paths. WriteWorkspaceBinding is the intended join-vs-provision
// boundary: agent-provisioning paths write the worktree binding immediately so the
// agent is ready to run, while `aw team join`/`aw team accept-invite` leave it unset
// and defer it to `aw init`.
type recordMembershipOptions struct {
	IdentityHome          encryptionKeyIdentityHomeIntent
	SetActive             bool
	WriteWorkspaceBinding bool
}

// recordAcceptedTeamMembership finalizes an accepted team membership: the steps
// every accept/enroll path shares once the certificate is in hand. It records the
// teams.yaml membership, optionally writes the worktree binding, and ensures the
// local identity encryption key so the member can do E2E messaging. How the
// certificate was obtained (local mint / hosted accept / cross-machine fetch) stays
// with each caller; only these shared steps live here.
func recordAcceptedTeamMembership(workingDir string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, registryURL, awebURL string, opts recordMembershipOptions) error {
	identityHomeRoot, _, err := opts.IdentityHome.resolve()
	if err != nil {
		return err
	}
	if err := upsertAcceptedTeamMembershipState(workingDir, output, cert, registryURL, awebURL, opts.SetActive, identityHomeRoot); err != nil {
		return err
	}
	if opts.WriteWorkspaceBinding {
		if err := ensureAcceptedTeamWorkspaceBinding(workingDir, output, cert, awebURL); err != nil {
			return err
		}
	}
	return ensureAndPublishLocalIdentityEncryptionKeyForDir(workingDir, opts.IdentityHome)
}

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
