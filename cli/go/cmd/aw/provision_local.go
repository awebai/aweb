package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
)

var (
	provisionLocalOperationID       string
	provisionLocalTeamID            string
	provisionLocalAlias             string
	provisionLocalAuthorityHome     string
	provisionLocalTargetHome        string
	provisionLocalAuthorityAddress  string
	provisionLocalAuthorityStableID string
	provisionLocalControllerDID     string

	cleanupLocalOperationID       string
	cleanupLocalTeamID            string
	cleanupLocalAlias             string
	cleanupLocalAuthorityHome     string
	cleanupLocalTargetHome        string
	cleanupLocalAuthorityAddress  string
	cleanupLocalAuthorityStableID string
	cleanupLocalControllerDID     string
)

var localProvisionOperationPattern = regexp.MustCompile(`^oas-[A-Za-z0-9_-]{21}[AQgw]$`)

type localProvisionOutput struct {
	Status        string `json:"status"`
	OperationID   string `json:"operation_id"`
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	IdentityHome  string `json:"identity_home"`
	DIDKey        string `json:"did_key"`
	CertificateID string `json:"certificate_id"`
	AgentID       string `json:"agent_id"`
	WorkspaceID   string `json:"workspace_id"`
	RegistryURL   string `json:"registry_url"`
	AwebURL       string `json:"aweb_url"`
}

type localProvisionCleanup struct {
	Grants      string `json:"grants"`
	Workspace   string `json:"workspace"`
	Certificate string `json:"certificate"`
	Credentials string `json:"credentials"`
}

type localProvisionTargetRecord struct {
	SchemaVersion int                    `json:"schema_version"`
	OperationID   string                 `json:"operation_id"`
	TeamID        string                 `json:"team_id"`
	Alias         string                 `json:"alias"`
	Status        string                 `json:"status"`
	Result        *localProvisionOutput  `json:"result,omitempty"`
	Cleanup       *localProvisionCleanup `json:"cleanup,omitempty"`
}

type localProvisionCleanupOutput struct {
	Status      string `json:"status"`
	OperationID string `json:"operation_id"`
	Grants      string `json:"grants"`
	Workspace   string `json:"workspace"`
	Identity    string `json:"identity"`
	Certificate string `json:"certificate"`
	Credentials string `json:"credentials"`
	Audit       string `json:"audit"`
}

type localProvisionOptions struct {
	WorkingDir       string
	OperationID      string
	TeamID           string
	Alias            string
	AuthorityHome    string
	TargetHome       string
	AuthorityAddress string
	AuthorityStable  string
	ControllerDID    string
}

var teamProvisionLocalCmd = &cobra.Command{
	Use:    "provision-local",
	Short:  "Provision one local identity through explicit controller authority",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   runTeamProvisionLocal,
}

var teamCleanupLocalProvisionCmd = &cobra.Command{
	Use:    "cleanup-local-provision",
	Short:  "Reconcile and clean one explicitly provisioned local identity",
	Hidden: true,
	Args:   cobra.NoArgs,
	RunE:   runTeamCleanupLocalProvision,
}

func runTeamProvisionLocal(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
	defer cancel()
	out, err := provisionLocalTeamMember(ctx, localProvisionOptions{
		WorkingDir:       workingDir,
		OperationID:      provisionLocalOperationID,
		TeamID:           provisionLocalTeamID,
		Alias:            provisionLocalAlias,
		AuthorityHome:    provisionLocalAuthorityHome,
		TargetHome:       provisionLocalTargetHome,
		AuthorityAddress: provisionLocalAuthorityAddress,
		AuthorityStable:  provisionLocalAuthorityStableID,
		ControllerDID:    provisionLocalControllerDID,
	})
	if err != nil {
		return err
	}
	printOutput(out, func(value any) string {
		result := value.(localProvisionOutput)
		return fmt.Sprintf("Provisioned local identity %s in %s", result.Alias, result.TeamID)
	})
	return nil
}

func runTeamCleanupLocalProvision(cmd *cobra.Command, args []string) error {
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(cmd.Context(), 90*time.Second)
	defer cancel()
	out, err := cleanupLocalProvision(ctx, localProvisionOptions{
		WorkingDir:       workingDir,
		OperationID:      cleanupLocalOperationID,
		TeamID:           cleanupLocalTeamID,
		Alias:            cleanupLocalAlias,
		AuthorityHome:    cleanupLocalAuthorityHome,
		TargetHome:       cleanupLocalTargetHome,
		AuthorityAddress: cleanupLocalAuthorityAddress,
		AuthorityStable:  cleanupLocalAuthorityStableID,
		ControllerDID:    cleanupLocalControllerDID,
	})
	if err != nil {
		return err
	}
	printOutput(out, func(value any) string {
		result := value.(localProvisionCleanupOutput)
		return fmt.Sprintf("Cleaned local provision operation %s", result.OperationID)
	})
	return nil
}

func provisionLocalTeamMember(ctx context.Context, opts localProvisionOptions) (localProvisionOutput, error) {
	operationID := strings.TrimSpace(opts.OperationID)
	if !localProvisionOperationPattern.MatchString(operationID) {
		return localProvisionOutput{}, usageError("--operation-id must be an opaque oas provision identifier")
	}
	domain, team, err := awid.ParseTeamID(strings.TrimSpace(opts.TeamID))
	if err != nil {
		return localProvisionOutput{}, usageError("invalid --team-id: %v", err)
	}
	teamID := awid.BuildTeamID(domain, team)
	alias, err := normalizeIDCreateName(strings.TrimSpace(opts.Alias))
	if err != nil {
		return localProvisionOutput{}, err
	}
	authorityHome, err := strictProvisionIdentityHome(opts.AuthorityHome, "authority identity home")
	if err != nil {
		return localProvisionOutput{}, err
	}
	targetHome, err := strictProvisionIdentityHome(opts.TargetHome, "target identity home")
	if err != nil {
		return localProvisionOutput{}, err
	}
	if authorityHome == targetHome {
		return localProvisionOutput{}, usageError("authority and target identity homes must differ")
	}
	if err := requireExternalProvisionHome(opts.WorkingDir, authorityHome, "authority identity home"); err != nil {
		return localProvisionOutput{}, err
	}
	if err := requireExternalProvisionHome(opts.WorkingDir, targetHome, "target identity home"); err != nil {
		return localProvisionOutput{}, err
	}

	identity, err := awconfig.ResolveIdentityFromHome(opts.WorkingDir, authorityHome)
	if err != nil {
		return localProvisionOutput{}, fmt.Errorf("resolve declared authority: %w", err)
	}
	if strings.TrimSpace(identity.Address) != strings.TrimSpace(opts.AuthorityAddress) {
		return localProvisionOutput{}, fmt.Errorf("declared authority address changed before local provision")
	}
	if strings.TrimSpace(identity.StableID) != strings.TrimSpace(opts.AuthorityStable) {
		return localProvisionOutput{}, fmt.Errorf("declared authority stable identity changed before local provision")
	}
	teamState, err := awconfig.LoadTeamStateFromIdentityHome(authorityHome)
	if err != nil {
		return localProvisionOutput{}, fmt.Errorf("load declared authority team state: %w", err)
	}
	if strings.TrimSpace(teamState.ActiveTeam) != teamID || teamState.Membership(teamID) == nil {
		return localProvisionOutput{}, fmt.Errorf("declared authority is not active in %s at local provision", teamID)
	}
	_, selection, err := resolveClientSelectionAtIdentityHomeWithTeamOverride(
		opts.WorkingDir,
		teamID,
		awconfig.IdentityHome{Root: authorityHome, Source: awconfig.IdentityHomeFlag},
	)
	if err != nil {
		return localProvisionOutput{}, fmt.Errorf("recheck declared authority at local provision side effect: %w", err)
	}
	if selection.TeamID != teamID || selectionAddress(selection) != strings.TrimSpace(opts.AuthorityAddress) || strings.TrimSpace(selection.StableID) != strings.TrimSpace(opts.AuthorityStable) {
		return localProvisionOutput{}, fmt.Errorf("declared authority selection changed before local provision")
	}
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return localProvisionOutput{}, fmt.Errorf("load local controller authority for %s: %w", teamID, err)
	}
	controllerDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	if controllerDID != strings.TrimSpace(opts.ControllerDID) {
		return localProvisionOutput{}, fmt.Errorf("local controller authority changed before provision")
	}

	awebURL := strings.TrimSpace(awebURLForTeamInviteAt(opts.WorkingDir, authorityHome, teamID))
	if awebURL == "" {
		return localProvisionOutput{}, fmt.Errorf("declared authority has no aweb URL for %s; refusing before grant creation", teamID)
	}
	registry, err := newConfiguredRegistryClient(nil, awebURL)
	if err != nil {
		return localProvisionOutput{}, err
	}
	registryURL := strings.TrimSpace(registryURLForTeamInviteAt(opts.WorkingDir, authorityHome, domain, awebURL))
	if registryURL == "" {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	if registryURL == "" {
		return localProvisionOutput{}, fmt.Errorf("declared authority has no registry URL for %s; refusing before grant creation", teamID)
	}

	targetRecord, err := ensureLocalProvisionTargetRecord(targetHome, operationID, teamID, alias)
	if err != nil {
		return localProvisionOutput{}, err
	}
	if targetRecord.Status == "complete" {
		return localProvisionOutput{}, fmt.Errorf("local provision operation %s is already cleaned", operationID)
	}
	if targetRecord.Status == "provisioned" {
		if targetRecord.Result == nil {
			return localProvisionOutput{}, fmt.Errorf("completed local provision target is missing its resource tuple")
		}
		remaining, err := awconfig.ListTeamInvitesByOperation(operationID)
		if err != nil {
			return localProvisionOutput{}, err
		}
		if len(remaining) != 0 {
			return localProvisionOutput{}, fmt.Errorf("completed operation %s still has a usable local grant", operationID)
		}
		if err := verifyCompletedLocalProvision(targetHome, *targetRecord.Result); err != nil {
			return localProvisionOutput{}, err
		}
		return *targetRecord.Result, nil
	}

	matches, err := awconfig.ListTeamInvitesByOperation(operationID)
	if err != nil {
		return localProvisionOutput{}, fmt.Errorf("enumerate local provision grants: %w", err)
	}
	if len(matches) > 1 {
		return localProvisionOutput{}, fmt.Errorf("operation %s has %d local grants; refusing ambiguous provision", operationID, len(matches))
	}
	var inviteID, token string
	if len(matches) == 1 {
		invite := matches[0]
		if awid.BuildTeamID(invite.Domain, invite.TeamName) != teamID || !invite.Ephemeral {
			return localProvisionOutput{}, fmt.Errorf("operation %s local grant contradicts the requested team or lifetime", operationID)
		}
		inviteID = invite.InviteID
		token, err = awconfig.EncodeInviteToken(invite)
	} else {
		inviteID, token, err = createTeamInviteTokenWithOperation(domain, team, registryURL, awebURL, true, operationID)
	}
	if err != nil {
		return localProvisionOutput{}, err
	}

	accepted, recovered, err := recoverAcceptedLocalProvision(ctx, opts.WorkingDir, targetHome, registry, registryURL, awebURL, domain, team, alias, operationID)
	if err != nil {
		return localProvisionOutput{}, err
	}
	if !recovered {
		accepted, err = acceptAndStoreTeamInvite(opts.WorkingDir, token, teamAcceptInviteOptions{
			IdentityHome: targetHome,
			Name:         alias,
			Scope:        awid.IdentityModeLocal,
		}, teamInviteStoreOptions{IdentityHome: explicitEncryptionKeyIdentityHome(targetHome), SetActive: true})
		if err != nil {
			return localProvisionOutput{}, fmt.Errorf("accept local provision grant %s: %w", inviteID, err)
		}
	}
	connected, err := initCertificateConnectWithOptions(opts.WorkingDir, awebURL, certificateConnectOptions{IdentityHome: targetHome})
	if err != nil {
		return localProvisionOutput{}, fmt.Errorf("connect provisioned local identity: %w", err)
	}
	remaining, err := awconfig.ListTeamInvitesByOperation(operationID)
	if err != nil {
		return localProvisionOutput{}, err
	}
	if len(remaining) != 0 {
		return localProvisionOutput{}, fmt.Errorf("operation %s completed with a usable local grant still present", operationID)
	}
	signingKey, err := awid.LoadSigningKey(filepath.Join(targetHome, "signing.key"))
	if err != nil {
		return localProvisionOutput{}, err
	}
	result := localProvisionOutput{
		Status:        "provisioned",
		OperationID:   operationID,
		TeamID:        teamID,
		Alias:         alias,
		IdentityHome:  targetHome,
		DIDKey:        awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)),
		CertificateID: strings.TrimSpace(accepted.Certificate.CertificateID),
		AgentID:       strings.TrimSpace(connected.AgentID),
		WorkspaceID:   strings.TrimSpace(connected.WorkspaceID),
		RegistryURL:   registryURL,
		AwebURL:       awebURL,
	}
	if err := writeLocalProvisionTargetRecord(targetHome, localProvisionTargetRecord{
		SchemaVersion: 1,
		OperationID:   operationID,
		TeamID:        teamID,
		Alias:         alias,
		Status:        "provisioned",
		Result:        &result,
		Cleanup: &localProvisionCleanup{
			Grants: "pending", Workspace: "pending", Certificate: "pending", Credentials: "pending",
		},
	}); err != nil {
		return localProvisionOutput{}, err
	}
	return result, nil
}

func cleanupLocalProvision(ctx context.Context, opts localProvisionOptions) (localProvisionCleanupOutput, error) {
	operation := strings.TrimSpace(opts.OperationID)
	if !localProvisionOperationPattern.MatchString(operation) {
		return localProvisionCleanupOutput{}, usageError("--operation-id must be an opaque oas provision identifier")
	}
	domain, team, err := awid.ParseTeamID(strings.TrimSpace(opts.TeamID))
	if err != nil {
		return localProvisionCleanupOutput{}, usageError("invalid --team-id: %v", err)
	}
	teamID := awid.BuildTeamID(domain, team)
	alias, err := normalizeIDCreateName(strings.TrimSpace(opts.Alias))
	if err != nil {
		return localProvisionCleanupOutput{}, err
	}
	authorityHome, err := strictProvisionIdentityHome(opts.AuthorityHome, "authority identity home")
	if err != nil {
		return localProvisionCleanupOutput{}, err
	}
	targetHome, err := strictProvisionIdentityHome(opts.TargetHome, "target identity home")
	if err != nil {
		return localProvisionCleanupOutput{}, err
	}
	if err := requireExternalProvisionHome(opts.WorkingDir, authorityHome, "authority identity home"); err != nil {
		return localProvisionCleanupOutput{}, err
	}
	if err := requireExternalProvisionHome(opts.WorkingDir, targetHome, "target identity home"); err != nil {
		return localProvisionCleanupOutput{}, err
	}
	record, err := ensureLocalProvisionTargetRecord(targetHome, operation, teamID, alias)
	if err != nil {
		return localProvisionCleanupOutput{}, err
	}
	if record.Status == "pending" || record.Result == nil || record.Cleanup == nil {
		return localProvisionCleanupOutput{}, fmt.Errorf("local provision operation %s has no completed resource to clean", operation)
	}
	if record.Status == "complete" {
		return cleanupOutputForRecord(*record), nil
	}
	if err := verifyCompletedLocalProvision(targetHome, *record.Result); err != nil {
		return localProvisionCleanupOutput{}, err
	}

	identity, err := awconfig.ResolveIdentityFromHome(opts.WorkingDir, authorityHome)
	if err != nil {
		return localProvisionCleanupOutput{}, fmt.Errorf("resolve cleanup authority: %w", err)
	}
	if identity.Address != strings.TrimSpace(opts.AuthorityAddress) || identity.StableID != strings.TrimSpace(opts.AuthorityStable) {
		return localProvisionCleanupOutput{}, fmt.Errorf("declared cleanup authority changed before cleanup")
	}
	client, selection, err := resolveClientSelectionAtIdentityHomeWithTeamOverride(
		opts.WorkingDir, teamID, awconfig.IdentityHome{Root: authorityHome, Source: awconfig.IdentityHomeFlag},
	)
	if err != nil {
		return localProvisionCleanupOutput{}, fmt.Errorf("recheck cleanup authority: %w", err)
	}
	if selection.TeamID != teamID || selectionAddress(selection) != identity.Address || selection.StableID != identity.StableID {
		return localProvisionCleanupOutput{}, fmt.Errorf("declared cleanup authority selection changed before cleanup")
	}
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return localProvisionCleanupOutput{}, err
	}
	if awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)) != strings.TrimSpace(opts.ControllerDID) {
		return localProvisionCleanupOutput{}, fmt.Errorf("local controller authority changed before cleanup")
	}

	if record.Cleanup.Grants != "physically-absent" {
		matches, err := awconfig.ListTeamInvitesByOperation(operation)
		if err != nil {
			return localProvisionCleanupOutput{}, err
		}
		for _, invite := range matches {
			if err := awconfig.DeleteTeamInvite(invite.InviteID); err != nil {
				return localProvisionCleanupOutput{}, err
			}
		}
		record.Cleanup.Grants = "physically-absent"
		record.Status = "cleaning"
		if err := writeLocalProvisionTargetRecord(targetHome, *record); err != nil {
			return localProvisionCleanupOutput{}, err
		}
	}

	if record.Cleanup.Workspace != "soft-deleted" {
		deleted, err := client.WorkspaceDelete(ctx, record.Result.WorkspaceID)
		if err != nil {
			if status, ok := awid.HTTPStatusCode(err); !ok || status != 404 {
				return localProvisionCleanupOutput{}, fmt.Errorf("soft-delete provisioned workspace: %w", err)
			}
		} else if deleted != nil && deleted.WorkspaceID != record.Result.WorkspaceID {
			return localProvisionCleanupOutput{}, fmt.Errorf("workspace cleanup response does not match provisioned resource")
		}
		record.Cleanup.Workspace = "soft-deleted"
		record.Status = "cleaning"
		if err := writeLocalProvisionTargetRecord(targetHome, *record); err != nil {
			return localProvisionCleanupOutput{}, err
		}
	}

	if record.Cleanup.Certificate != "revoked" {
		registry, err := newConfiguredRegistryClient(nil, record.Result.AwebURL)
		if err != nil {
			return localProvisionCleanupOutput{}, err
		}
		if err := registry.SetFallbackRegistryURL(record.Result.RegistryURL); err != nil {
			return localProvisionCleanupOutput{}, err
		}
		certificates, err := registry.ListCertificates(ctx, record.Result.RegistryURL, domain, team, false)
		if err != nil {
			return localProvisionCleanupOutput{}, fmt.Errorf("list provisioned certificate for cleanup: %w", err)
		}
		var certificate *awid.RegistryCertificate
		for index := range certificates {
			if certificates[index].CertificateID == record.Result.CertificateID {
				certificate = &certificates[index]
				break
			}
		}
		if certificate != nil {
			if certificate.TeamID != teamID || certificate.Alias != alias || certificate.MemberDIDKey != record.Result.DIDKey {
				return localProvisionCleanupOutput{}, fmt.Errorf("registry certificate does not match provisioned cleanup tuple")
			}
			if strings.TrimSpace(certificate.RevokedAt) == "" {
				if err := registry.RevokeCertificate(ctx, record.Result.RegistryURL, domain, team, record.Result.CertificateID, teamKey); err != nil {
					return localProvisionCleanupOutput{}, fmt.Errorf("revoke provisioned certificate: %w", err)
				}
			}
		}
		record.Cleanup.Certificate = "revoked"
		record.Status = "cleaning"
		if err := writeLocalProvisionTargetRecord(targetHome, *record); err != nil {
			return localProvisionCleanupOutput{}, err
		}
	}

	if record.Cleanup.Credentials != "physically-absent" {
		entries, err := os.ReadDir(targetHome)
		if err != nil {
			return localProvisionCleanupOutput{}, err
		}
		for _, entry := range entries {
			if entry.Name() == filepath.Base(localProvisionTargetRecordPath(targetHome)) {
				continue
			}
			if err := os.RemoveAll(filepath.Join(targetHome, entry.Name())); err != nil {
				return localProvisionCleanupOutput{}, err
			}
		}
		remaining, err := os.ReadDir(targetHome)
		if err != nil {
			return localProvisionCleanupOutput{}, err
		}
		if len(remaining) != 1 || remaining[0].Name() != filepath.Base(localProvisionTargetRecordPath(targetHome)) {
			return localProvisionCleanupOutput{}, fmt.Errorf("provisioned credential tree still contains material after cleanup")
		}
		record.Cleanup.Credentials = "physically-absent"
	}
	record.Status = "complete"
	if err := writeLocalProvisionTargetRecord(targetHome, *record); err != nil {
		return localProvisionCleanupOutput{}, err
	}
	return cleanupOutputForRecord(*record), nil
}

func cleanupOutputForRecord(record localProvisionTargetRecord) localProvisionCleanupOutput {
	return localProvisionCleanupOutput{
		Status: "complete", OperationID: record.OperationID,
		Grants: record.Cleanup.Grants, Workspace: record.Cleanup.Workspace, Identity: "soft-deleted",
		Certificate: record.Cleanup.Certificate, Credentials: record.Cleanup.Credentials,
		Audit: "intentionally-retained-operation-record",
	}
}

func recoverAcceptedLocalProvision(
	ctx context.Context,
	workingDir, targetHome string,
	registry *awid.RegistryClient,
	registryURL, awebURL, domain, team, alias, operationID string,
) (*acceptedTeamInvite, bool, error) {
	keyPath := filepath.Join(targetHome, "signing.key")
	if err := pathpreflight.PreflightFile(keyPath, "provisioned local signing key", pathpreflight.Options{}); err != nil {
		return nil, false, err
	}
	if _, err := os.Lstat(keyPath); os.IsNotExist(err) {
		return nil, false, nil
	} else if err != nil {
		return nil, false, err
	}
	signingKey, err := awid.LoadSigningKey(keyPath)
	if err != nil {
		return nil, false, err
	}
	member, err := registry.ResolveTeamMember(ctx, registryURL, domain, team, alias)
	if err != nil {
		if status, ok := awid.HTTPStatusCode(err); ok && status == 404 {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("reconcile provisioned local member: %w", err)
	}
	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	teamID := awid.BuildTeamID(domain, team)
	if member.TeamID != teamID || member.Alias != alias || member.MemberDIDKey != didKey || awid.NormalizeIdentityScope(member.IdentityScope) != awid.IdentityModeLocal {
		return nil, false, fmt.Errorf("remote local member for operation %s does not match its target key and alias (team=%q alias=%q did=%q scope=%q)", operationID, member.TeamID, member.Alias, member.MemberDIDKey, member.IdentityScope)
	}
	cert, err := registry.FetchTeamCertificate(ctx, registryURL, domain, team, member.CertificateID, signingKey)
	if err != nil {
		return nil, false, fmt.Errorf("fetch reconciled local certificate: %w", err)
	}
	certPath, err := saveAcceptedTeamCertificate(workingDir, targetHome, teamID, cert)
	if err != nil {
		return nil, false, err
	}
	accepted := &acceptedTeamInvite{
		Output:      &teamAcceptInviteOutput{Status: "accepted", TeamID: teamID, Alias: alias, CertPath: certPath},
		Certificate: cert,
		RegistryURL: registryURL,
		AwebURL:     awebURL,
		Domain:      domain,
		TeamName:    team,
	}
	if err := recordAcceptedTeamMembership(workingDir, accepted.Output, cert, registryURL, awebURL, recordMembershipOptions{IdentityHome: explicitEncryptionKeyIdentityHome(targetHome), SetActive: true}); err != nil {
		return nil, false, err
	}
	matches, err := awconfig.ListTeamInvitesByOperation(operationID)
	if err != nil {
		return nil, false, err
	}
	for _, invite := range matches {
		if err := awconfig.DeleteTeamInvite(invite.InviteID); err != nil {
			return nil, false, fmt.Errorf("remove reconciled local grant %s: %w", invite.InviteID, err)
		}
	}
	return accepted, true, nil
}

func localProvisionTargetRecordPath(targetHome string) string {
	return filepath.Join(targetHome, "provision-operation.json")
}

func ensureLocalProvisionTargetRecord(targetHome, operationID, teamID, alias string) (*localProvisionTargetRecord, error) {
	if err := os.MkdirAll(targetHome, 0o700); err != nil {
		return nil, err
	}
	path := localProvisionTargetRecordPath(targetHome)
	if err := pathpreflight.PreflightFile(path, "local provision target record", pathpreflight.Options{}); err != nil {
		return nil, err
	}
	encoded, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		record := localProvisionTargetRecord{SchemaVersion: 1, OperationID: operationID, TeamID: teamID, Alias: alias, Status: "pending"}
		if err := writeLocalProvisionTargetRecord(targetHome, record); err != nil {
			return nil, err
		}
		return &record, nil
	}
	if err != nil {
		return nil, err
	}
	var record localProvisionTargetRecord
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return nil, fmt.Errorf("parse local provision target record: %w", err)
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		return nil, fmt.Errorf("parse local provision target record: trailing JSON content")
	}
	if record.SchemaVersion != 1 || record.OperationID != operationID || record.TeamID != teamID || record.Alias != alias ||
		(record.Status != "pending" && record.Status != "provisioned" && record.Status != "cleaning" && record.Status != "complete") {
		return nil, fmt.Errorf("local provision target record contradicts the requested operation")
	}
	if record.Status == "pending" {
		if record.Result != nil || record.Cleanup != nil {
			return nil, fmt.Errorf("local provision target record has a contradictory pending status")
		}
	} else if record.Result == nil || record.Cleanup == nil {
		return nil, fmt.Errorf("local provision target record has contradictory cleanup state")
	} else if record.Result.Status != "provisioned" || record.Result.OperationID != record.OperationID ||
		record.Result.TeamID != record.TeamID || record.Result.Alias != record.Alias ||
		record.Result.IdentityHome != targetHome || !strings.HasPrefix(record.Result.DIDKey, "did:key:z") ||
		record.Result.CertificateID == "" || record.Result.AgentID == "" || record.Result.WorkspaceID == "" ||
		record.Result.RegistryURL == "" || record.Result.AwebURL == "" {
		return nil, fmt.Errorf("local provision target record nested resource tuple contradicts its operation")
	} else if (record.Cleanup.Grants != "physically-absent" && record.Cleanup.Grants != "pending") ||
		(record.Cleanup.Workspace != "pending" && record.Cleanup.Workspace != "soft-deleted") ||
		(record.Cleanup.Certificate != "pending" && record.Cleanup.Certificate != "revoked") ||
		(record.Cleanup.Credentials != "pending" && record.Cleanup.Credentials != "physically-absent") {
		return nil, fmt.Errorf("local provision target record has contradictory cleanup state")
	}
	return &record, nil
}

func writeLocalProvisionTargetRecord(targetHome string, record localProvisionTargetRecord) error {
	encoded, err := json.MarshalIndent(record, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	temp, err := os.CreateTemp(targetHome, ".provision-operation-*.tmp")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		temp.Close()
		return err
	}
	if _, err := temp.Write(encoded); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return os.Rename(tempPath, localProvisionTargetRecordPath(targetHome))
}

func verifyCompletedLocalProvision(targetHome string, result localProvisionOutput) error {
	if result.Status != "provisioned" || result.IdentityHome != targetHome || result.CertificateID == "" || result.WorkspaceID == "" || result.AgentID == "" {
		return fmt.Errorf("completed local provision resource tuple is incomplete")
	}
	key, err := awid.LoadSigningKey(filepath.Join(targetHome, "signing.key"))
	if err != nil {
		return err
	}
	if awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) != result.DIDKey {
		return fmt.Errorf("completed local provision signing key does not match its resource tuple")
	}
	certPath, err := awconfig.TeamCertificatePathFromIdentityHome(targetHome, result.TeamID)
	if err != nil {
		return err
	}
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return err
	}
	if cert.CertificateID != result.CertificateID || cert.MemberDIDKey != result.DIDKey || cert.Team != result.TeamID || cert.Alias != result.Alias {
		return fmt.Errorf("completed local provision certificate does not match its resource tuple")
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(targetHome, "workspace.yaml"))
	if err != nil {
		return err
	}
	membership := workspace.Membership(result.TeamID)
	if membership == nil || membership.WorkspaceID != result.WorkspaceID || membership.Alias != result.Alias {
		return fmt.Errorf("completed local provision workspace does not match its resource tuple")
	}
	return nil
}

func strictProvisionIdentityHome(value, label string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" || !filepath.IsAbs(value) {
		return "", usageError("%s must be absolute", label)
	}
	cleaned := filepath.Clean(value)
	if cleaned != value {
		return "", usageError("%s must be canonical", label)
	}
	if err := pathpreflight.PreflightDir(cleaned, label, pathpreflight.Options{}); err != nil {
		return "", err
	}
	return cleaned, nil
}

func requireExternalProvisionHome(workingDir, identityHome, label string) error {
	workingDir, err := filepath.Abs(workingDir)
	if err != nil {
		return err
	}
	rel, err := filepath.Rel(filepath.Clean(workingDir), identityHome)
	if err != nil {
		return err
	}
	if rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))) {
		return usageError("%s must be outside the disposable working directory", label)
	}
	return nil
}

func init() {
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalOperationID, "operation-id", "", "Opaque provision operation identifier")
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalTeamID, "team-id", "", "Canonical team id")
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalAlias, "name", "", "Explicit provisioned member name")
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalAuthorityHome, "authority-identity-home", "", "Declared authority identity home")
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalTargetHome, "target-identity-home", "", "External target identity home")
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalAuthorityAddress, "authority-address", "", "Expected declared authority address")
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalAuthorityStableID, "authority-stable-id", "", "Expected declared authority stable identity")
	teamProvisionLocalCmd.Flags().StringVar(&provisionLocalControllerDID, "controller-did", "", "Expected local controller DID")
	teamCmd.AddCommand(teamProvisionLocalCmd)

	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalOperationID, "operation-id", "", "Opaque provision operation identifier")
	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalTeamID, "team-id", "", "Canonical team id")
	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalAlias, "name", "", "Explicit provisioned member name")
	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalAuthorityHome, "authority-identity-home", "", "Declared authority identity home")
	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalTargetHome, "target-identity-home", "", "External target identity home")
	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalAuthorityAddress, "authority-address", "", "Expected declared authority address")
	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalAuthorityStableID, "authority-stable-id", "", "Expected declared authority stable identity")
	teamCleanupLocalProvisionCmd.Flags().StringVar(&cleanupLocalControllerDID, "controller-did", "", "Expected local controller DID")
	teamCmd.AddCommand(teamCleanupLocalProvisionCmd)
}
