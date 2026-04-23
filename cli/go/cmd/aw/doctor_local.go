package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

const (
	doctorCheckWorkspaceExists       = "local.workspace_yaml.exists"
	doctorCheckWorkspaceParse        = "local.workspace_yaml.parse"
	doctorCheckWorkspaceAwebURL      = "local.workspace.aweb_url_syntax"
	doctorCheckTeamsActiveTeam       = "local.teams.active_team"
	doctorCheckWorkspaceMembership   = "local.workspace.active_membership"
	doctorCheckWorkspaceWorkspaceID  = "local.workspace.active_membership.workspace_id"
	doctorCheckWorkspaceCertPath     = "local.workspace.membership_cert_path"
	doctorCheckCertificateExists     = "local.team_certificate.exists"
	doctorCheckCertificateParse      = "local.team_certificate.parse"
	doctorCheckCertificateTeam       = "local.team_certificate.team_matches_workspace"
	doctorCheckCertificateAlias      = "local.team_certificate.alias_matches_workspace"
	doctorCheckCertificateLifetime   = "local.team_certificate.lifetime_valid"
	doctorCheckCertificateTeamDIDKey = "local.team_certificate.team_did_key_valid"
	doctorCheckCertificateSignature  = "local.team_certificate.signature_valid"
	doctorCheckSigningKeyExists      = "local.signing_key.exists"
	doctorCheckSigningKeyParse       = "local.signing_key.parse"
	doctorCheckSigningKeyMatchesCert = "local.signing_key.matches_certificate"
	doctorCheckIdentityEphemeral     = "local.identity_yaml.ephemeral_not_required"
	doctorCheckIdentityPersistent    = "local.identity_yaml.persistent_exists"
	doctorCheckIdentityParse         = "local.identity_yaml.parse"
	doctorCheckIdentityLifetime      = "local.identity_yaml.lifetime_matches_certificate"
	doctorCheckIdentityDID           = "local.identity_yaml.did_matches_certificate"
	doctorCheckIdentityAddress       = "local.identity_yaml.address_matches_certificate"
	doctorCheckIdentityStableID      = "local.identity_yaml.stable_id_present"
	doctorCheckIdentityCustody       = "local.identity_yaml.custody_present"
	doctorCheckIdentityRegistryURL   = "local.identity_yaml.registry_url_syntax"
	doctorCheckRegistryCoherence     = "local.registry_url.local_coherence"
)

type doctorLocalState struct {
	workingDir string

	workspacePath string
	workspace     *awconfig.WorktreeWorkspace
	teamState     *awconfig.TeamState

	membership *awconfig.WorktreeMembership

	certPath string
	cert     *awid.TeamCertificate

	signingKeyPath string
	signingKey     ed25519.PrivateKey
	signingKeyDID  string

	identityPath string
	identity     *awconfig.WorktreeIdentity
}

type doctorWorkspaceYAML struct {
	AwebURL         string                          `yaml:"aweb_url,omitempty"`
	APIKey          string                          `yaml:"api_key,omitempty"`
	ActiveTeam      string                          `yaml:"active_team,omitempty"`
	Memberships     []doctorWorkspaceMembershipYAML `yaml:"memberships,omitempty"`
	HumanName       string                          `yaml:"human_name,omitempty"`
	AgentType       string                          `yaml:"agent_type,omitempty"`
	RepoID          string                          `yaml:"repo_id,omitempty"`
	CanonicalOrigin string                          `yaml:"canonical_origin,omitempty"`
	Hostname        string                          `yaml:"hostname,omitempty"`
	WorkspacePath   string                          `yaml:"workspace_path,omitempty"`
	UpdatedAt       string                          `yaml:"updated_at,omitempty"`
}

type doctorWorkspaceMembershipYAML struct {
	TeamID      string `yaml:"team_id,omitempty"`
	Alias       string `yaml:"alias,omitempty"`
	RoleName    string `yaml:"role_name,omitempty"`
	WorkspaceID string `yaml:"workspace_id,omitempty"`
	CertPath    string `yaml:"cert_path,omitempty"`
	JoinedAt    string `yaml:"joined_at,omitempty"`
}

type doctorTeamStateYAML struct {
	ActiveTeam  string                     `yaml:"active_team,omitempty"`
	Memberships []doctorTeamMembershipYAML `yaml:"memberships,omitempty"`
}

type doctorTeamMembershipYAML struct {
	TeamID   string `yaml:"team_id,omitempty"`
	Alias    string `yaml:"alias,omitempty"`
	CertPath string `yaml:"cert_path,omitempty"`
	JoinedAt string `yaml:"joined_at,omitempty"`
}

func (r *doctorRunner) runLocalChecks() {
	state := doctorLocalState{
		workingDir:     r.workingDir,
		workspacePath:  filepath.Join(r.workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath()),
		signingKeyPath: awconfig.WorktreeSigningKeyPath(r.workingDir),
		identityPath:   filepath.Join(r.workingDir, awconfig.DefaultWorktreeIdentityRelativePath()),
	}

	workspace, workspacePath, err := loadDoctorWorkspaceFromDir(r.workingDir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.add(localPathCheck(
				doctorCheckWorkspaceExists,
				doctorStatusInfo,
				state.workspacePath,
				"No local workspace binding was found.",
				"Run `aw init` or `aw run <provider>` when you are ready to connect this directory.",
				map[string]any{"state": "missing"},
			))
			return
		}
		r.add(localPathCheck(
			doctorCheckWorkspaceExists,
			doctorStatusOK,
			state.workspacePath,
			"Local workspace binding file is present.",
			"",
			map[string]any{"state": "present"},
		))
		r.add(localPathCheck(
			doctorCheckWorkspaceParse,
			doctorStatusFail,
			state.workspacePath,
			"Local workspace binding could not be parsed.",
			"Repair or recreate .aw/workspace.yaml before relying on local coordination state.",
			map[string]any{"error": err.Error()},
		))
		r.addWorkspaceDependentBlockedChecks(state.workspacePath, doctorCheckWorkspaceParse)
		r.runSigningKeyFileChecks(&state)
		r.runIdentityFileOnlyChecks(&state)
		return
	}

	state.workspace = workspace
	state.workspacePath = workspacePath
	if teamState, err := loadDoctorTeamStateFromDir(r.workingDir); err == nil {
		state.teamState = teamState
		state.membership = awconfig.ActiveMembershipFor(workspace, teamState)
	}

	r.add(localPathCheck(
		doctorCheckWorkspaceExists,
		doctorStatusOK,
		state.workspacePath,
		"Local workspace binding file is present.",
		"",
		map[string]any{"state": "present"},
	))
	r.add(localPathCheck(
		doctorCheckWorkspaceParse,
		doctorStatusOK,
		state.workspacePath,
		"Local workspace binding parsed successfully.",
		"",
		nil,
	))
	r.runWorkspaceChecks(&state)
	r.runCertificateChecks(&state)
	r.runSigningKeyChecks(&state)
	r.runIdentityChecks(&state)
}

func (r *doctorRunner) runWorkspaceChecks(state *doctorLocalState) {
	workspace := state.workspace
	if workspace == nil {
		return
	}

	awebURL, err := normalizeLocalURLForDoctor(workspace.AwebURL)
	if err != nil {
		r.add(localCheck(
			doctorCheckWorkspaceAwebURL,
			doctorStatusFail,
			&doctorTarget{Type: "workspace", ID: strings.TrimSpace(state.workspacePath), Display: abbreviateUserHome(state.workspacePath)},
			"Workspace aweb_url is not a valid local URL value.",
			"Update .aw/workspace.yaml with a valid http(s) aweb_url.",
			map[string]any{"error": err.Error()},
		))
	} else {
		check := localCheck(
			doctorCheckWorkspaceAwebURL,
			doctorStatusOK,
			&doctorTarget{Type: "workspace", ID: strings.TrimSpace(state.workspacePath), Display: abbreviateUserHome(state.workspacePath)},
			"Workspace aweb_url is present and syntactically valid.",
			"",
			doctorURLDetail("aweb_url", awebURL),
		)
		if awebURL.needsRewrite() {
			check.Fix = safeDoctorFixInfo(doctorCheckWorkspaceAwebURL)
		}
		r.add(check)
	}

	activeTeam := ""
	if state.teamState != nil {
		activeTeam = strings.TrimSpace(state.teamState.ActiveTeam)
	}
	if activeTeam == "" {
		check := localPathCheck(doctorCheckTeamsActiveTeam, doctorStatusFail, awconfig.TeamStatePath(state.workingDir), "teams.yaml active_team is missing.", "Recreate or repair .aw/teams.yaml.", nil)
		check.Fix = safeDoctorFixInfo(doctorCheckTeamsActiveTeam)
		r.add(check)
	} else {
		r.add(localCheck(doctorCheckTeamsActiveTeam, doctorStatusOK, &doctorTarget{Type: "team", ID: activeTeam}, "teams.yaml active_team is present.", "", map[string]any{"team_id": activeTeam}))
	}

	if state.membership == nil {
		check := localCheck(doctorCheckWorkspaceMembership, doctorStatusFail, &doctorTarget{Type: "team", ID: activeTeam}, "teams.yaml active_team is not present in workspace memberships.", "Run `aw id team switch <team>` or reinitialize the workspace binding.", nil)
		if activeTeam != "" {
			check.Fix = safeDoctorFixInfo(doctorCheckWorkspaceMembership)
		}
		r.add(check)
		r.add(blockedLocalCheck(doctorCheckWorkspaceWorkspaceID, "Active membership could not be selected.", doctorCheckWorkspaceMembership, nil))
		r.add(blockedLocalCheck(doctorCheckWorkspaceCertPath, "Active membership could not be selected.", doctorCheckWorkspaceMembership, nil))
		return
	}

	membership := state.membership
	r.add(localCheck(
		doctorCheckWorkspaceMembership,
		doctorStatusOK,
		&doctorTarget{Type: "team", ID: strings.TrimSpace(membership.TeamID)},
		"Workspace active membership is present.",
		"",
		map[string]any{
			"team_id": strings.TrimSpace(membership.TeamID),
			"alias":   strings.TrimSpace(membership.Alias),
		},
	))

	workspaceID := strings.TrimSpace(membership.WorkspaceID)
	if !validLocalWorkspaceID(workspaceID) {
		r.add(localCheck(
			doctorCheckWorkspaceWorkspaceID,
			doctorStatusFail,
			&doctorTarget{Type: "workspace", ID: workspaceID},
			"Active membership workspace_id is missing or malformed locally.",
			"Reinitialize the workspace binding or restore the server-issued workspace_id.",
			map[string]any{"workspace_id": workspaceID},
		))
	} else {
		r.add(localCheck(
			doctorCheckWorkspaceWorkspaceID,
			doctorStatusOK,
			&doctorTarget{Type: "workspace", ID: workspaceID},
			"Active membership workspace_id is present and locally well formed.",
			"",
			map[string]any{"workspace_id": workspaceID, "server_existence_checked": false},
		))
	}

	certPathValue := strings.TrimSpace(membership.CertPath)
	if certPathValue == "" {
		r.add(localCheck(
			doctorCheckWorkspaceCertPath,
			doctorStatusFail,
			&doctorTarget{Type: "team", ID: strings.TrimSpace(membership.TeamID)},
			"Active membership cert_path is missing.",
			"Reinitialize the workspace binding or restore the team certificate path.",
			nil,
		))
		return
	}
	state.certPath = resolveWorkspaceCertificatePath(state.workingDir, certPathValue)
	r.add(localPathCheck(
		doctorCheckWorkspaceCertPath,
		doctorStatusOK,
		state.certPath,
		"Active membership cert_path is present.",
		"",
		map[string]any{"cert_path": certPathValue},
	))
}

func (r *doctorRunner) runCertificateChecks(state *doctorLocalState) {
	if state.membership == nil {
		r.add(blockedLocalCheck(doctorCheckCertificateExists, "Certificate path depends on the active membership.", doctorCheckWorkspaceMembership, nil))
		r.addCertificateDependentBlockedChecks(doctorCheckCertificateExists)
		return
	}
	if strings.TrimSpace(state.certPath) == "" {
		r.add(blockedLocalCheck(doctorCheckCertificateExists, "Certificate path is missing from the active membership.", doctorCheckWorkspaceCertPath, nil))
		r.addCertificateDependentBlockedChecks(doctorCheckWorkspaceCertPath)
		return
	}

	if _, err := os.Stat(state.certPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			r.add(localPathCheck(
				doctorCheckCertificateExists,
				doctorStatusFail,
				state.certPath,
				"Active team certificate file is missing.",
				"Restore the certificate file or reconnect this worktree to the team.",
				map[string]any{"state": "missing"},
			))
		} else {
			r.add(localPathCheck(
				doctorCheckCertificateExists,
				doctorStatusFail,
				state.certPath,
				"Active team certificate file could not be inspected.",
				"Check file permissions for the team certificate.",
				map[string]any{"error": err.Error()},
			))
		}
		r.addCertificateDependentBlockedChecks(doctorCheckCertificateExists)
		return
	}
	r.add(localPathCheck(doctorCheckCertificateExists, doctorStatusOK, state.certPath, "Active team certificate file is present.", "", map[string]any{"state": "present"}))

	cert, err := awid.LoadTeamCertificate(state.certPath)
	if err != nil {
		r.add(localPathCheck(
			doctorCheckCertificateParse,
			doctorStatusFail,
			state.certPath,
			"Active team certificate could not be parsed.",
			"Restore a valid team certificate for the active membership.",
			map[string]any{"error": err.Error()},
		))
		r.addCertificateDependentBlockedChecks(doctorCheckCertificateParse)
		return
	}
	state.cert = cert
	r.add(localPathCheck(doctorCheckCertificateParse, doctorStatusOK, state.certPath, "Active team certificate parsed successfully.", "", nil))

	expectedTeam := strings.TrimSpace(state.membership.TeamID)
	if strings.TrimSpace(cert.Team) != expectedTeam {
		r.add(localCheck(
			doctorCheckCertificateTeam,
			doctorStatusFail,
			&doctorTarget{Type: "team", ID: expectedTeam},
			"Team certificate team_id does not match the active workspace membership.",
			"Restore the certificate for the active team or switch to the matching team.",
			map[string]any{"workspace_team_id": expectedTeam, "certificate_team_id": strings.TrimSpace(cert.Team)},
		))
	} else {
		r.add(localCheck(doctorCheckCertificateTeam, doctorStatusOK, &doctorTarget{Type: "team", ID: expectedTeam}, "Team certificate team_id matches the active workspace membership.", "", map[string]any{"team_id": expectedTeam}))
	}

	expectedAlias := strings.TrimSpace(state.membership.Alias)
	if strings.TrimSpace(cert.Alias) != expectedAlias {
		r.add(localCheck(
			doctorCheckCertificateAlias,
			doctorStatusFail,
			&doctorTarget{Type: "team", ID: expectedTeam},
			"Team certificate alias does not match the active workspace membership.",
			"Restore the certificate for this workspace alias or reinitialize the binding.",
			map[string]any{"workspace_alias": expectedAlias, "certificate_alias": strings.TrimSpace(cert.Alias)},
		))
	} else {
		r.add(localCheck(doctorCheckCertificateAlias, doctorStatusOK, &doctorTarget{Type: "team", ID: expectedTeam}, "Team certificate alias matches the active workspace membership.", "", map[string]any{"alias": expectedAlias}))
	}

	lifetime := strings.TrimSpace(cert.Lifetime)
	switch lifetime {
	case awid.LifetimeEphemeral, awid.LifetimePersistent:
		r.add(localCheck(doctorCheckCertificateLifetime, doctorStatusOK, &doctorTarget{Type: "team", ID: expectedTeam}, "Team certificate lifetime is recognized.", "", map[string]any{"lifetime": lifetime}))
	default:
		r.add(localCheck(
			doctorCheckCertificateLifetime,
			doctorStatusFail,
			&doctorTarget{Type: "team", ID: expectedTeam},
			"Team certificate lifetime is unknown.",
			"Replace the team certificate with one using a supported lifetime.",
			map[string]any{"lifetime": lifetime},
		))
	}

	teamDID := strings.TrimSpace(cert.TeamDIDKey)
	teamPub, err := awid.ExtractPublicKey(teamDID)
	if err != nil {
		r.add(localCheck(
			doctorCheckCertificateTeamDIDKey,
			doctorStatusFail,
			&doctorTarget{Type: "did", ID: teamDID},
			"Team certificate team_did_key is not a valid did:key.",
			"Replace the team certificate with a valid team-signed certificate.",
			map[string]any{"error": err.Error()},
		))
		r.add(blockedLocalCheck(doctorCheckCertificateSignature, "Certificate signature verification requires a valid team_did_key.", doctorCheckCertificateTeamDIDKey, &doctorTarget{Type: "did", ID: teamDID}))
		return
	}
	r.add(localCheck(doctorCheckCertificateTeamDIDKey, doctorStatusOK, &doctorTarget{Type: "did", ID: teamDID}, "Team certificate team_did_key is valid.", "", nil))

	if err := awid.VerifyTeamCertificate(cert, teamPub); err != nil {
		r.add(localCheck(
			doctorCheckCertificateSignature,
			doctorStatusFail,
			&doctorTarget{Type: "did", ID: teamDID},
			"Team certificate signature is invalid.",
			"Restore a certificate signed by the team controller key.",
			map[string]any{"error": err.Error()},
		))
	} else {
		r.add(localCheck(doctorCheckCertificateSignature, doctorStatusOK, &doctorTarget{Type: "did", ID: teamDID}, "Team certificate signature verifies with its team_did_key.", "", nil))
	}
}

func (r *doctorRunner) runSigningKeyFileChecks(state *doctorLocalState) {
	if _, err := os.Stat(state.signingKeyPath); err != nil {
		var check doctorCheck
		if errors.Is(err, os.ErrNotExist) {
			check = localPathCheck(doctorCheckSigningKeyExists, doctorStatusFail, state.signingKeyPath, "Signing key file is missing.", "Restore .aw/signing.key or reconnect this worktree.", map[string]any{"state": "missing"})
		} else {
			check = localPathCheck(doctorCheckSigningKeyExists, doctorStatusFail, state.signingKeyPath, "Signing key file could not be inspected.", "Check file permissions for .aw/signing.key.", map[string]any{"error": err.Error()})
		}
		if state.cert != nil && strings.TrimSpace(state.cert.Lifetime) == awid.LifetimePersistent {
			check.Handoff = persistentReplacementReviewHandoff(doctorAuthorityStatusNotDetected, nil)
		}
		r.add(check)
		r.add(blockedLocalCheck(doctorCheckSigningKeyParse, "Signing key parsing requires the key file to be readable.", doctorCheckSigningKeyExists, localPathTarget(state.signingKeyPath)))
		return
	}
	r.add(localPathCheck(doctorCheckSigningKeyExists, doctorStatusOK, state.signingKeyPath, "Signing key file is present.", "", map[string]any{"state": "present"}))

	signingKey, err := awid.LoadSigningKey(state.signingKeyPath)
	if err != nil {
		check := localPathCheck(
			doctorCheckSigningKeyParse,
			doctorStatusFail,
			state.signingKeyPath,
			"Signing key could not be parsed.",
			"Restore a valid Ed25519 signing key for this worktree.",
			map[string]any{"error": err.Error()},
		)
		if state.cert != nil && strings.TrimSpace(state.cert.Lifetime) == awid.LifetimePersistent {
			check.Handoff = suspectedKeyMismatchReviewHandoff(doctorAuthorityStatusNotDetected, nil)
		}
		r.add(check)
		return
	}
	state.signingKey = signingKey
	state.signingKeyDID = awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	r.add(localPathCheck(doctorCheckSigningKeyParse, doctorStatusOK, state.signingKeyPath, "Signing key parsed successfully.", "", map[string]any{"did_key": state.signingKeyDID}))
}

func (r *doctorRunner) runSigningKeyChecks(state *doctorLocalState) {
	r.runSigningKeyFileChecks(state)
	if state.cert == nil {
		r.add(blockedLocalCheck(doctorCheckSigningKeyMatchesCert, "Signing key comparison requires a parsed team certificate.", doctorCheckCertificateParse, localPathTarget(state.signingKeyPath)))
		return
	}
	if state.signingKey == nil {
		r.add(blockedLocalCheck(doctorCheckSigningKeyMatchesCert, "Signing key comparison requires a parsed signing key.", doctorCheckSigningKeyParse, localPathTarget(state.signingKeyPath)))
		return
	}

	expectedDID := strings.TrimSpace(state.cert.MemberDIDKey)
	if state.signingKeyDID != expectedDID {
		check := localCheck(
			doctorCheckSigningKeyMatchesCert,
			doctorStatusFail,
			&doctorTarget{Type: "did", ID: state.signingKeyDID},
			"Signing key did:key does not match the team certificate member_did_key.",
			"Restore the signing key that belongs to this certificate or reconnect the worktree.",
			map[string]any{"signing_key_did": state.signingKeyDID, "certificate_member_did_key": expectedDID},
		)
		check.Handoff = suspectedKeyMismatchReviewHandoff(doctorAuthorityStatusNotDetected, nil)
		r.add(check)
		return
	}
	r.add(localCheck(doctorCheckSigningKeyMatchesCert, doctorStatusOK, &doctorTarget{Type: "did", ID: state.signingKeyDID}, "Signing key did:key matches the team certificate member_did_key.", "", map[string]any{"did_key": state.signingKeyDID}))
}

func (r *doctorRunner) runIdentityFileOnlyChecks(state *doctorLocalState) {
	if _, err := os.Stat(state.identityPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return
		}
		r.add(localPathCheck(doctorCheckIdentityParse, doctorStatusFail, state.identityPath, "Identity file could not be inspected.", "Check file permissions for .aw/identity.yaml.", map[string]any{"error": err.Error()}))
		return
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(state.identityPath)
	if err != nil {
		r.add(localPathCheck(doctorCheckIdentityParse, doctorStatusFail, state.identityPath, "Identity file could not be parsed.", "Repair .aw/identity.yaml before relying on local identity state.", map[string]any{"error": err.Error()}))
		return
	}
	state.identity = identity
	r.add(localPathCheck(doctorCheckIdentityParse, doctorStatusOK, state.identityPath, "Identity file parsed successfully.", "", nil))
}

func (r *doctorRunner) runIdentityChecks(state *doctorLocalState) {
	if state.cert == nil {
		r.add(blockedLocalCheck(doctorCheckIdentityEphemeral, "Identity lifetime expectation requires a parsed team certificate.", doctorCheckCertificateParse, localPathTarget(state.identityPath)))
		r.add(blockedLocalCheck(doctorCheckIdentityPersistent, "Identity lifetime expectation requires a parsed team certificate.", doctorCheckCertificateParse, localPathTarget(state.identityPath)))
		r.addIdentityDependentBlockedChecks(doctorCheckCertificateParse)
		return
	}
	lifetime := strings.TrimSpace(state.cert.Lifetime)
	if lifetime != awid.LifetimeEphemeral && lifetime != awid.LifetimePersistent {
		r.add(blockedLocalCheck(doctorCheckIdentityEphemeral, "Identity lifetime expectation requires a supported certificate lifetime.", doctorCheckCertificateLifetime, localPathTarget(state.identityPath)))
		r.add(blockedLocalCheck(doctorCheckIdentityPersistent, "Identity lifetime expectation requires a supported certificate lifetime.", doctorCheckCertificateLifetime, localPathTarget(state.identityPath)))
		r.addIdentityDependentBlockedChecks(doctorCheckCertificateLifetime)
		return
	}

	identityExists := true
	if _, err := os.Stat(state.identityPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			identityExists = false
		} else {
			r.add(localPathCheck(doctorCheckIdentityParse, doctorStatusFail, state.identityPath, "Identity file could not be inspected.", "Check file permissions for .aw/identity.yaml.", map[string]any{"error": err.Error()}))
			r.addIdentityDependentBlockedChecks(doctorCheckIdentityParse)
			return
		}
	}

	if lifetime == awid.LifetimeEphemeral && !identityExists {
		r.add(localPathCheck(
			doctorCheckIdentityEphemeral,
			doctorStatusOK,
			state.identityPath,
			"Ephemeral workspace does not require identity.yaml.",
			"",
			map[string]any{"state": "absent", "lifetime": lifetime},
		))
		return
	}
	if lifetime == awid.LifetimePersistent && !identityExists {
		check := localPathCheck(
			doctorCheckIdentityPersistent,
			doctorStatusFail,
			state.identityPath,
			"Persistent workspace requires identity.yaml, but it is missing.",
			"Restore .aw/identity.yaml or reconnect this persistent identity.",
			map[string]any{"state": "missing", "lifetime": lifetime},
		)
		check.Handoff = persistentLifecycleReviewHandoff()
		r.add(check)
		r.add(blockedLocalCheck(doctorCheckIdentityParse, "Identity parsing requires identity.yaml to exist.", doctorCheckIdentityPersistent, localPathTarget(state.identityPath)))
		r.addIdentityDependentBlockedChecks(doctorCheckIdentityPersistent)
		return
	}

	if lifetime == awid.LifetimeEphemeral {
		r.add(localPathCheck(
			doctorCheckIdentityEphemeral,
			doctorStatusInfo,
			state.identityPath,
			"Ephemeral workspace has an optional identity.yaml file.",
			"Keep it only if you understand how identity commands use this reserved path.",
			map[string]any{"state": "present", "lifetime": lifetime},
		))
	} else {
		r.add(localPathCheck(
			doctorCheckIdentityPersistent,
			doctorStatusOK,
			state.identityPath,
			"Persistent workspace identity.yaml is present.",
			"",
			map[string]any{"state": "present", "lifetime": lifetime},
		))
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(state.identityPath)
	if err != nil {
		check := localPathCheck(
			doctorCheckIdentityParse,
			doctorStatusFail,
			state.identityPath,
			"Identity file could not be parsed.",
			"Repair .aw/identity.yaml before relying on local identity state.",
			map[string]any{"error": err.Error()},
		)
		if lifetime == awid.LifetimePersistent {
			check.Handoff = persistentLifecycleReviewHandoff()
		}
		r.add(check)
		r.addIdentityDependentBlockedChecks(doctorCheckIdentityParse)
		return
	}
	state.identity = identity
	r.add(localPathCheck(doctorCheckIdentityParse, doctorStatusOK, state.identityPath, "Identity file parsed successfully.", "", nil))
	r.runIdentityCoherenceChecks(state, lifetime)
}

func (r *doctorRunner) runIdentityCoherenceChecks(state *doctorLocalState, lifetime string) {
	identity := state.identity
	cert := state.cert
	if identity == nil || cert == nil {
		return
	}

	identityLifetime := strings.TrimSpace(identity.Lifetime)
	if identityLifetime != lifetime {
		r.add(localPathCheck(
			doctorCheckIdentityLifetime,
			doctorStatusFail,
			state.identityPath,
			"Identity lifetime does not match the team certificate lifetime.",
			"Repair identity.yaml or reconnect this worktree so lifetime metadata agrees.",
			map[string]any{"identity_lifetime": identityLifetime, "certificate_lifetime": lifetime},
		))
	} else {
		r.add(localPathCheck(doctorCheckIdentityLifetime, doctorStatusOK, state.identityPath, "Identity lifetime matches the team certificate lifetime.", "", map[string]any{"lifetime": lifetime}))
	}

	identityDID := strings.TrimSpace(identity.DID)
	certDID := strings.TrimSpace(cert.MemberDIDKey)
	if identityDID != certDID {
		check := localCheck(
			doctorCheckIdentityDID,
			doctorStatusFail,
			&doctorTarget{Type: "did", ID: identityDID},
			"Identity did does not match the team certificate member_did_key.",
			"Repair identity.yaml or restore the matching team certificate.",
			map[string]any{"identity_did": identityDID, "certificate_member_did_key": certDID},
		)
		check.Handoff = suspectedKeyMismatchReviewHandoff(doctorAuthorityStatusNotDetected, nil)
		r.add(check)
	} else {
		r.add(localCheck(doctorCheckIdentityDID, doctorStatusOK, &doctorTarget{Type: "did", ID: identityDID}, "Identity did matches the team certificate member_did_key.", "", map[string]any{"did": identityDID}))
	}

	identityAddress := strings.TrimSpace(identity.Address)
	certAddress := strings.TrimSpace(cert.MemberAddress)
	if identityAddress != certAddress {
		r.add(localPathCheck(
			doctorCheckIdentityAddress,
			doctorStatusFail,
			state.identityPath,
			"Identity address does not match the team certificate member_address.",
			"Repair identity.yaml or restore the matching team certificate.",
			map[string]any{"identity_address": identityAddress, "certificate_member_address": certAddress},
		))
	} else {
		r.add(localPathCheck(doctorCheckIdentityAddress, doctorStatusOK, state.identityPath, "Identity address matches the team certificate member_address.", "", map[string]any{"address": identityAddress}))
	}

	if lifetime == awid.LifetimePersistent {
		identityStableID := strings.TrimSpace(identity.StableID)
		certStableID := strings.TrimSpace(cert.MemberDIDAW)
		switch {
		case identityStableID == "":
			r.add(localPathCheck(doctorCheckIdentityStableID, doctorStatusFail, state.identityPath, "Persistent identity stable_id is missing.", "Restore the persistent identity stable_id.", nil))
		case certStableID != "" && identityStableID != certStableID:
			r.add(localPathCheck(
				doctorCheckIdentityStableID,
				doctorStatusFail,
				state.identityPath,
				"Persistent identity stable_id does not match the team certificate did:aw value.",
				"Repair identity.yaml or restore the matching team certificate.",
				map[string]any{"identity_stable_id": identityStableID, "certificate_member_did_aw": certStableID},
			))
		default:
			r.add(localPathCheck(doctorCheckIdentityStableID, doctorStatusOK, state.identityPath, "Persistent identity stable_id is present and locally coherent.", "", map[string]any{"stable_id": identityStableID}))
		}

		custody := strings.TrimSpace(identity.Custody)
		switch custody {
		case awid.CustodySelf, awid.CustodyCustodial:
			r.add(localPathCheck(doctorCheckIdentityCustody, doctorStatusOK, state.identityPath, "Persistent identity custody is present and recognized.", "", map[string]any{"custody": custody}))
		default:
			r.add(localPathCheck(
				doctorCheckIdentityCustody,
				doctorStatusFail,
				state.identityPath,
				"Persistent identity custody is missing or unknown.",
				"Repair identity.yaml with a supported custody value.",
				map[string]any{"custody": custody},
			))
		}
	}

	r.runIdentityRegistryChecks(state)
}

func (r *doctorRunner) runIdentityRegistryChecks(state *doctorLocalState) {
	identity := state.identity
	if identity == nil {
		r.add(blockedLocalCheck(doctorCheckIdentityRegistryURL, "Registry URL syntax requires a parsed identity.yaml.", doctorCheckIdentityParse, localPathTarget(state.identityPath)))
		r.add(blockedLocalCheck(doctorCheckRegistryCoherence, "Registry URL coherence requires a parsed identity.yaml.", doctorCheckIdentityParse, localPathTarget(state.identityPath)))
		return
	}

	registryURL := strings.TrimSpace(identity.RegistryURL)
	if registryURL == "" {
		r.add(localPathCheck(
			doctorCheckIdentityRegistryURL,
			doctorStatusInfo,
			state.identityPath,
			"Identity registry_url is not set.",
			"Registry authority checks are reserved for a later doctor slice.",
			map[string]any{"state": "missing"},
		))
		r.add(localCheck(
			doctorCheckRegistryCoherence,
			doctorStatusInfo,
			nil,
			"No local registry_url value is available to compare.",
			"Registry authority checks are reserved for a later doctor slice.",
			map[string]any{"sources": []string{}},
		))
		return
	}

	safeRegistryURL, err := normalizeLocalURLForDoctor(registryURL)
	if err != nil {
		r.add(localPathCheck(
			doctorCheckIdentityRegistryURL,
			doctorStatusFail,
			state.identityPath,
			"Identity registry_url is not syntactically valid.",
			"Repair identity.yaml with a valid http(s) registry_url.",
			map[string]any{"error": err.Error()},
		))
		r.add(blockedLocalCheck(doctorCheckRegistryCoherence, "Registry URL coherence requires a syntactically valid identity registry_url.", doctorCheckIdentityRegistryURL, nil))
		return
	}
	registryCheck := localPathCheck(doctorCheckIdentityRegistryURL, doctorStatusOK, state.identityPath, "Identity registry_url is syntactically valid.", "", doctorURLDetail("registry_url", safeRegistryURL))
	if safeRegistryURL.needsRewrite() {
		registryCheck.Fix = safeDoctorFixInfo(doctorCheckIdentityRegistryURL)
	}
	r.add(registryCheck)

	detail := map[string]any{
		"registry_url": safeRegistryURL.URL,
		"sources":      []string{awconfig.DefaultWorktreeIdentityRelativePath()},
	}
	if state.workspace != nil {
		if safeAwebURL, err := sanitizeLocalURLForOutput(state.workspace.AwebURL); err == nil && safeAwebURL == safeRegistryURL.URL {
			detail["same_as_aweb_url"] = true
		}
	}
	r.add(localCheck(
		doctorCheckRegistryCoherence,
		doctorStatusOK,
		nil,
		"Local registry_url values are coherent where present.",
		"",
		detail,
	))
}

func loadDoctorWorkspaceFromDir(startDir string) (*awconfig.WorktreeWorkspace, string, error) {
	path, err := awconfig.FindWorktreeWorkspacePath(startDir)
	if err != nil {
		return nil, "", err
	}
	workspace, err := loadDoctorWorkspaceFrom(path)
	if err != nil {
		return nil, "", err
	}
	return workspace, path, nil
}

func loadDoctorTeamStateFromDir(workingDir string) (*awconfig.TeamState, error) {
	data, err := os.ReadFile(awconfig.TeamStatePath(workingDir))
	if err != nil {
		return nil, err
	}
	var raw doctorTeamStateYAML
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	state := &awconfig.TeamState{
		ActiveTeam: strings.TrimSpace(raw.ActiveTeam),
	}
	for _, membership := range raw.Memberships {
		state.Memberships = append(state.Memberships, awconfig.TeamMembership{
			TeamID:   strings.TrimSpace(membership.TeamID),
			Alias:    strings.TrimSpace(membership.Alias),
			CertPath: filepath.ToSlash(strings.TrimSpace(membership.CertPath)),
			JoinedAt: strings.TrimSpace(membership.JoinedAt),
		})
	}
	return state, nil
}

func loadDoctorWorkspaceFrom(path string) (*awconfig.WorktreeWorkspace, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw doctorWorkspaceYAML
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}

	memberships := make([]awconfig.WorktreeMembership, 0, len(raw.Memberships))
	for _, membership := range raw.Memberships {
		memberships = append(memberships, awconfig.WorktreeMembership{
			TeamID:      strings.TrimSpace(membership.TeamID),
			Alias:       strings.TrimSpace(membership.Alias),
			RoleName:    strings.TrimSpace(membership.RoleName),
			WorkspaceID: strings.TrimSpace(membership.WorkspaceID),
			CertPath:    filepath.ToSlash(strings.TrimSpace(membership.CertPath)),
			JoinedAt:    strings.TrimSpace(membership.JoinedAt),
		})
	}
	return &awconfig.WorktreeWorkspace{
		AwebURL:         strings.TrimSpace(raw.AwebURL),
		APIKey:          strings.TrimSpace(raw.APIKey),
		Memberships:     memberships,
		HumanName:       strings.TrimSpace(raw.HumanName),
		AgentType:       strings.TrimSpace(raw.AgentType),
		RepoID:          strings.TrimSpace(raw.RepoID),
		CanonicalOrigin: strings.TrimSpace(raw.CanonicalOrigin),
		Hostname:        strings.TrimSpace(raw.Hostname),
		WorkspacePath:   strings.TrimSpace(raw.WorkspacePath),
		UpdatedAt:       strings.TrimSpace(raw.UpdatedAt),
	}, nil
}

func (r *doctorRunner) addWorkspaceDependentBlockedChecks(workspacePath, prerequisite string) {
	target := localPathTarget(workspacePath)
	for _, id := range []string{
		doctorCheckWorkspaceAwebURL,
		doctorCheckTeamsActiveTeam,
		doctorCheckWorkspaceMembership,
		doctorCheckWorkspaceWorkspaceID,
		doctorCheckWorkspaceCertPath,
		doctorCheckCertificateExists,
		doctorCheckCertificateParse,
		doctorCheckCertificateTeam,
		doctorCheckCertificateAlias,
		doctorCheckCertificateLifetime,
		doctorCheckCertificateTeamDIDKey,
		doctorCheckCertificateSignature,
		doctorCheckSigningKeyMatchesCert,
		doctorCheckIdentityEphemeral,
		doctorCheckIdentityPersistent,
	} {
		r.add(blockedLocalCheck(id, "This check requires a parsed workspace binding.", prerequisite, target))
	}
	r.addIdentityDependentBlockedChecks(prerequisite)
}

func (r *doctorRunner) addCertificateDependentBlockedChecks(prerequisite string) {
	for _, id := range []string{
		doctorCheckCertificateParse,
		doctorCheckCertificateTeam,
		doctorCheckCertificateAlias,
		doctorCheckCertificateLifetime,
		doctorCheckCertificateTeamDIDKey,
		doctorCheckCertificateSignature,
	} {
		if id == prerequisite {
			continue
		}
		r.add(blockedLocalCheck(id, "This check requires a parsed active team certificate.", prerequisite, nil))
	}
}

func (r *doctorRunner) addIdentityDependentBlockedChecks(prerequisite string) {
	for _, id := range []string{
		doctorCheckIdentityLifetime,
		doctorCheckIdentityDID,
		doctorCheckIdentityAddress,
		doctorCheckIdentityStableID,
		doctorCheckIdentityCustody,
		doctorCheckIdentityRegistryURL,
		doctorCheckRegistryCoherence,
	} {
		r.add(blockedLocalCheck(id, "This check requires parsed prerequisite local identity state.", prerequisite, nil))
	}
}

func localPathCheck(id string, status doctorStatus, path, message, nextStep string, detail map[string]any) doctorCheck {
	return localCheck(id, status, localPathTarget(path), message, nextStep, detail)
}

func localCheck(id string, status doctorStatus, target *doctorTarget, message, nextStep string, detail map[string]any) doctorCheck {
	return doctorCheck{
		ID:            id,
		Status:        status,
		Source:        doctorSourceLocal,
		Authority:     doctorAuthorityCaller,
		Target:        target,
		Authoritative: true,
		Message:       message,
		Detail:        detail,
		NextStep:      nextStep,
	}
}

func blockedLocalCheck(id, message, prerequisite string, target *doctorTarget) doctorCheck {
	if strings.TrimSpace(message) == "" {
		message = "Check is blocked by a prerequisite local state failure."
	}
	return localCheck(id, doctorStatusBlocked, target, message, "Resolve the prerequisite check first.", map[string]any{"prerequisite": prerequisite})
}

func localPathTarget(path string) *doctorTarget {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil
	}
	return &doctorTarget{Type: "local_path", ID: path, Display: abbreviateUserHome(path)}
}

func resolveWorkspaceCertificatePath(workingDir, certPath string) string {
	certPath = filepath.FromSlash(strings.TrimSpace(certPath))
	if certPath == "" {
		return ""
	}
	if filepath.IsAbs(certPath) {
		return filepath.Clean(certPath)
	}
	return filepath.Join(workingDir, ".aw", certPath)
}

func sanitizeLocalURLForOutput(raw string) (string, error) {
	normalization, err := normalizeLocalURLForDoctor(raw)
	if err != nil {
		return "", err
	}
	return normalization.URL, nil
}

func validLocalWorkspaceID(workspaceID string) bool {
	if strings.TrimSpace(workspaceID) == "" || strings.TrimSpace(workspaceID) != workspaceID {
		return false
	}
	for _, r := range workspaceID {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == '/' || r == '\\' {
			return false
		}
	}
	return true
}
