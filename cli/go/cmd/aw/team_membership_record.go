package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type membershipActivation uint8
type membershipWorkspaceBinding uint8
type membershipDuplicatePolicy uint8

const (
	membershipPreserveActive membershipActivation = iota
	membershipMakeActive
)

const (
	membershipLeaveWorkspaceBinding membershipWorkspaceBinding = iota
	membershipWriteWorkspaceBinding
)

const (
	membershipAllowExisting membershipDuplicatePolicy = iota
	membershipRejectDuplicate
)

// teamMembershipLocation identifies the credential store without changing the
// principal selected by a caller (docs/cli-identity-selection.md:13-33).
// An empty IdentityHome names the supplied worktree's .aw directory.
type teamMembershipLocation struct {
	WorkingDir   string
	IdentityHome string
}

type acceptedTeamMembershipRequest struct {
	WorkingDir   string
	IdentityHome encryptionKeyIdentityHomeIntent
	Output       *teamAcceptInviteOutput
	Certificate  *awid.TeamCertificate
	RegistryURL  string
	AwebURL      string
	Activation   membershipActivation
	Binding      membershipWorkspaceBinding

	RegistryOperatorOrigin string
}

type teamMembershipStateUpdate struct {
	Location    teamMembershipLocation
	Output      *teamAcceptInviteOutput
	Certificate *awid.TeamCertificate
	RegistryURL string
	AwebURL     string
	Activation  membershipActivation

	RegistryOperatorOrigin string
}

// recordAcceptedTeamMembership records the accepted certificate in the selected
// home and prepares its encryption key (docs/cli-identity-selection.md:26-30).
// Provisioning may also write a workspace binding; joining installs membership
// before its separate connection step (docs/cli-identity-selection.md:43-48).
func recordAcceptedTeamMembership(request acceptedTeamMembershipRequest) error {
	identityHomeRoot, _, err := request.IdentityHome.resolve()
	if err != nil {
		return err
	}
	if request.Binding != membershipLeaveWorkspaceBinding && request.Binding != membershipWriteWorkspaceBinding {
		return errors.New("membership workspace binding is unknown")
	}
	update := teamMembershipStateUpdate{
		Location:               teamMembershipLocation{WorkingDir: request.WorkingDir, IdentityHome: identityHomeRoot},
		Output:                 request.Output,
		Certificate:            request.Certificate,
		RegistryURL:            request.RegistryURL,
		RegistryOperatorOrigin: request.RegistryOperatorOrigin,
		AwebURL:                request.AwebURL,
		Activation:             request.Activation,
	}
	if err := update.validate(); err != nil {
		return err
	}
	if err := upsertAcceptedTeamMembershipState(update); err != nil {
		if request.Binding == membershipWriteWorkspaceBinding {
			home := awconfig.IdentityHome{Root: identityHomeRoot}
			if home.Root == "" {
				home.Root = awconfig.WorktreeIdentityHome(request.WorkingDir)
			}
			return retainProvisionedRecordFailure(provisionedRecordFailure{Home: home, Certificate: *request.Certificate, RegistryURL: request.RegistryURL, AwebURL: request.AwebURL, Cause: err})
		}
		return err
	}
	if request.Binding == membershipWriteWorkspaceBinding {
		home := awconfig.IdentityHome{Root: identityHomeRoot}
		if home.Root == "" {
			home.Root = awconfig.WorktreeIdentityHome(request.WorkingDir)
		}
		return completeProvisionedTeamMembership(provisionedTeamMembership{WorkingDir: request.WorkingDir, Home: home, AwebURL: request.AwebURL})
	}
	return ensureAndPublishLocalIdentityEncryptionKeyForDir(request.WorkingDir, request.IdentityHome)
}

// upsertAcceptedTeamMembershipState preserves routing and the original JoinedAt
// on reinstallation, activating a membership only on request or for an empty
// store (docs/cli-identity-selection.md:28-33).
func upsertAcceptedTeamMembershipState(request teamMembershipStateUpdate) error {
	if err := request.validate(); err != nil {
		return err
	}
	output, cert := request.Output, request.Certificate
	teamState, err := loadOptionalTeamState(request.Location)
	if err != nil {
		return err
	}
	if teamState == nil {
		teamState = &awconfig.TeamState{}
	}
	registryURL, awebURL := request.RegistryURL, request.AwebURL
	origin := request.RegistryOperatorOrigin
	keyEvidence := output.TeamKey
	joinedAt := strings.TrimSpace(cert.IssuedAt)
	if existing := teamState.Membership(strings.TrimSpace(output.TeamID)); existing != nil {
		if strings.TrimSpace(registryURL) == "" {
			registryURL = strings.TrimSpace(existing.RegistryURL)
		}
		if origin == "" {
			origin = existing.RegistryOperatorOrigin
		}
		if strings.TrimSpace(awebURL) == "" {
			awebURL = strings.TrimSpace(existing.AwebURL)
		}
		if keyEvidence == nil && existing.TeamKey != nil && existing.TeamKey.DIDKey == cert.TeamDIDKey {
			keyEvidence = existing.TeamKey
		}
		if strings.TrimSpace(existing.JoinedAt) != "" {
			joinedAt = strings.TrimSpace(existing.JoinedAt)
		}
	}
	teamState.AddMembership(awconfig.TeamMembership{
		TeamKey: keyEvidence,
		TeamID:  strings.TrimSpace(output.TeamID), Alias: strings.TrimSpace(output.Alias),
		CertPath: filepath.ToSlash(strings.TrimSpace(output.CertPath)), JoinedAt: joinedAt,
		RegistryURL: strings.TrimSpace(registryURL), AwebURL: strings.TrimSpace(awebURL),
		RegistryOperatorOrigin: matchingRegistryOrigin(registryURL, origin),
	})
	if request.Activation == membershipMakeActive || strings.TrimSpace(teamState.ActiveTeam) == "" {
		teamState.ActiveTeam = strings.TrimSpace(output.TeamID)
	}
	if strings.TrimSpace(request.Location.IdentityHome) != "" {
		return awconfig.SaveTeamStateToIdentityHome(request.Location.IdentityHome, teamState)
	}
	return awconfig.SaveTeamState(request.Location.WorkingDir, teamState)
}

func (request teamMembershipStateUpdate) validate() error {
	if err := request.Location.validate(); err != nil {
		return err
	}
	if request.Activation != membershipPreserveActive && request.Activation != membershipMakeActive {
		return errors.New("membership activation is unknown")
	}
	if request.Output == nil || request.Certificate == nil {
		return errors.New("accepted team membership is required")
	}
	return nil
}

func (location teamMembershipLocation) validate() error {
	if strings.TrimSpace(location.IdentityHome) == "" && strings.TrimSpace(location.WorkingDir) == "" {
		return errors.New("membership recording requires a working directory or identity home")
	}
	return nil
}

func loadOptionalTeamState(location teamMembershipLocation) (*awconfig.TeamState, error) {
	if err := location.validate(); err != nil {
		return nil, err
	}
	var teamState *awconfig.TeamState
	var err error
	if strings.TrimSpace(location.IdentityHome) != "" {
		teamState, err = awconfig.LoadTeamStateFromIdentityHome(location.IdentityHome)
	} else {
		teamState, err = awconfig.LoadTeamState(location.WorkingDir)
	}
	if err == nil {
		return teamState, nil
	}
	if os.IsNotExist(err) {
		return nil, nil
	}
	return nil, err
}
