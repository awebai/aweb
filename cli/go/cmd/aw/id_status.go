package main

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type initRecoveryStage string
type initializationRegistryObservation string

const offlineIdentityInspectionAnnotation = "aw.offline-identity-inspection"

const (
	initRecoveryAbsent   initRecoveryStage = "absent"
	initRecoveryPrepared initRecoveryStage = "identity_prepared"
	initRecoveryResponse initRecoveryStage = "response_received"
)

const (
	initializationRegistryUnknown    initializationRegistryObservation = "unknown"
	initializationRegistryPending    initializationRegistryObservation = "pending"
	initializationRegistryRegistered initializationRegistryObservation = "registered"
	initializationRegistryLocal      initializationRegistryObservation = "not_applicable"
)

type initRecoveryStatus struct {
	Present bool              `json:"present"`
	Stage   initRecoveryStage `json:"stage"`
}

type identityStatusOutput struct {
	TeamID              string                            `json:"team_id"`
	SigningKeyPresent   bool                              `json:"signing_key_present"`
	IdentityPresent     bool                              `json:"identity_present"`
	IdentityRegistered  bool                              `json:"identity_registered"`
	RegistryStatus      initializationRegistryObservation `json:"registry_status"`
	DID                 string                            `json:"did"`
	StableID            string                            `json:"stable_id"`
	Address             string                            `json:"address"`
	Alias               string                            `json:"alias"`
	CertificatePresent  bool                              `json:"certificate_present"`
	CertificateID       string                            `json:"certificate_id"`
	WorkspaceBound      bool                              `json:"workspace_bound"`
	WorkspaceID         string                            `json:"workspace_id"`
	Service             string                            `json:"service"`
	PartialInit         initRecoveryStatus                `json:"partial_init"`
	PendingHostedAccept bool                              `json:"pending_hosted_accept"`
	MintComplete        bool                              `json:"mint_complete"`
}

var idStatusCmd = &cobra.Command{
	Use:               "status",
	Short:             "Inspect local identity, membership, binding and unfinished initialization",
	Long:              "Read recorded local initialization state without contacting a service. This does not prove live registry or server status. Missing state is reported as incomplete; unreadable or invalid state is an error.",
	Args:              cobra.NoArgs,
	PersistentPreRunE: prepareOfflineIdentityInspection,
	RunE:              runIdentityStatus,
}

// Offline inspection uses the same principal precedence (docs/cli-identity-selection.md:3-13)
// without credential renewal: incomplete state is precisely what it must inspect.
func prepareOfflineIdentityInspection(cmd *cobra.Command, args []string) error {
	_, err := awconfig.ResolveIdentityHome("", identityHomeFlag)
	return err
}

func runIdentityStatus(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	out, err := inspectIdentityInitialization(home)
	if err != nil {
		return fmt.Errorf("inspect identity home %s: %w; repair that home's recorded state before retrying initialization", home.Root, err)
	}
	return printJSON(out)
}

// inspectIdentityInitialization implements the reconciliation requirement in
// docs/orchestrator-integration.md:95-98. Completeness is local evidence, not a
// new authority to mint, join, reuse, recover or revoke an identity.
func inspectIdentityInitialization(home awconfig.IdentityHome) (identityStatusOutput, error) {
	out := identityStatusOutput{TeamID: strings.TrimSpace(teamFlag), RegistryStatus: initializationRegistryUnknown, PartialInit: initRecoveryStatus{Stage: initRecoveryAbsent}}
	keyPath, err := awconfig.IdentityHomePath(home, "signing.key")
	if err != nil {
		return out, err
	}
	key, err := awid.LoadSigningKey(keyPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if len(key) != 0 {
		out.SigningKeyPresent = true
		out.DID = awid.ComputeDIDKey(ed25519.PublicKey(key[ed25519.SeedSize:]))
	}
	identityPath, err := awconfig.IdentityHomePath(home, "identity.yaml")
	if err != nil {
		return out, err
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if identity != nil {
		if out.DID != "" && out.DID != identity.DID {
			return out, fmt.Errorf("identity DID does not match its signing key")
		}
		out.IdentityPresent = identity.DID != ""
		switch identity.RegistryStatus {
		case string(initializationRegistryRegistered):
			out.RegistryStatus = initializationRegistryRegistered
		case string(initializationRegistryPending):
			out.RegistryStatus = initializationRegistryPending
		case string(initializationRegistryLocal):
			out.RegistryStatus = initializationRegistryLocal
		}
		out.IdentityRegistered = out.RegistryStatus == initializationRegistryRegistered
		out.DID, out.StableID, out.Address = identity.DID, identity.StableID, identity.Address
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home.Root)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	if state != nil && out.TeamID == "" {
		out.TeamID = state.ActiveTeam
	}
	if out.TeamID != "" {
		if err := inspectInitializationMembership(home, state, &out); err != nil {
			return out, err
		}
	}
	partialPath, err := awconfig.IdentityHomePath(home, "partial-init.yaml")
	if err != nil {
		return out, err
	}
	partial, err := loadAPIKeyPartialInit(partialPath)
	if err != nil {
		return out, err
	}
	if partial != nil {
		out.PartialInit = initRecoveryStatus{Present: true, Stage: initRecoveryPrepared}
		if partial.ResponseJSON != "" || (partial.IDTree != nil && partial.IDTree.ResponseJSON != "") {
			out.PartialInit.Stage = initRecoveryResponse
		}
	}
	pendingPath, err := awconfig.IdentityHomePath(home, "pending-hosted-accept")
	if err != nil {
		return out, err
	}
	_, err = os.Stat(pendingPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return out, err
	}
	out.PendingHostedAccept = err == nil
	out.MintComplete = out.SigningKeyPresent && out.IdentityPresent && out.IdentityRegistered && out.CertificatePresent && out.WorkspaceBound && !out.PartialInit.Present && !out.PendingHostedAccept
	return out, nil
}

func inspectInitializationMembership(home awconfig.IdentityHome, state *awconfig.TeamState, out *identityStatusOutput) error {
	certPath, err := awconfig.TeamCertificatePathFromIdentityHome(home.Root, out.TeamID)
	if err != nil {
		return err
	}
	if state != nil {
		if member := state.Membership(out.TeamID); member != nil {
			certPath, err = awconfig.IdentityHomeStoredPath(home, member.CertPath)
			if err != nil {
				return err
			}
		}
	}
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if cert != nil {
		if !strings.EqualFold(cert.Team, out.TeamID) {
			return fmt.Errorf("certificate names another team")
		}
		if out.DID != "" && cert.MemberDIDKey != out.DID {
			return fmt.Errorf("certificate member does not match the selected identity")
		}
		if err := awid.CheckDecodedTeamCertificate(cert, cert.TeamDIDKey); err != nil {
			return err
		}
		out.CertificatePresent = cert.CertificateID != ""
		out.CertificateID, out.Alias = cert.CertificateID, cert.Alias
		if out.DID == "" {
			out.DID = cert.MemberDIDKey
		}
		if awid.NormalizeIdentityScope(cert.IdentityScope) == awid.IdentityModeLocal {
			out.IdentityPresent = cert.MemberDIDKey != ""
			out.IdentityRegistered = out.IdentityPresent
			out.RegistryStatus = initializationRegistryLocal
		} else if out.StableID != cert.MemberDIDAW || out.Address != cert.MemberAddress {
			return fmt.Errorf("global identity does not match its team certificate")
		}
	}
	workspacePath, err := awconfig.IdentityHomePath(home, "workspace.yaml")
	if err != nil {
		return err
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if workspace != nil {
		if member := workspace.Membership(out.TeamID); member != nil {
			out.WorkspaceID, out.Service = member.WorkspaceID, workspace.AwebURL
			out.WorkspaceBound = out.WorkspaceID != "" && out.Service != ""
		}
	}
	return nil
}

func init() {
	bindTeamSelector(idStatusCmd)
	identityCmd.AddCommand(idStatusCmd)
	teamListCmd.PersistentPreRunE = prepareOfflineIdentityInspection
	certShowCmd.PersistentPreRunE = prepareOfflineIdentityInspection
	for _, cmd := range []*cobra.Command{idStatusCmd, teamListCmd, certShowCmd} {
		if cmd.Annotations == nil {
			cmd.Annotations = map[string]string{}
		}
		cmd.Annotations[offlineIdentityInspectionAnnotation] = "true"
	}
}
