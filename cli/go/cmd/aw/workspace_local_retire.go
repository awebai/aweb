package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

type retirementOutcome string

const (
	retiredAndRevoked        retirementOutcome = "retired_and_revoked"
	retiredRevocationPending retirementOutcome = "retired_revocation_pending"
	retiredKeyHolderRequired retirementOutcome = "retired_key_holder_required"
)

const localRetirementReceiptVersion = 1

type localRetirementRequest struct {
	Command    *cobra.Command
	WorkingDir string
	Target     string
	Client     *aweb.Client
	Selection  *awconfig.Selection
}

type localRetirementReceipt struct {
	Version       int                   `json:"version"`
	TeamID        string                `json:"team_id"`
	CertificateID string                `json:"certificate_id"`
	MemberDIDKey  string                `json:"member_did_key"`
	RegistryURL   string                `json:"registry_url"`
	Revoked       bool                  `json:"revoked"`
	Delete        workspaceDeleteOutput `json:"delete"`
}

func localRetirementReceiptPath(home awconfig.IdentityHome, workspaceID string) (string, error) {
	if !workspaceIDPattern.MatchString(workspaceID) {
		return "", usageError("retirement receipt requires a workspace UUID; retry with the exact workspace ID")
	}
	return awconfig.IdentityHomePath(home, "retirements/"+strings.ToLower(workspaceID)+".json")
}

// Local self-retirement keeps two authorities separate (docs/aweb-sot.md:233-248,
// docs/awid-sot.md:853-858): delete under the member credential, persist the exact
// remaining revocation, then sign that revocation with the team controller key.
func retireLocalControllerMember(request localRetirementRequest) (bool, error) {
	sel := request.Selection
	if sel == nil || !strings.EqualFold(sel.WorkspaceID, request.Target) || sel.IdentityScope != awid.IdentityModeLocal {
		return false, nil
	}
	domain, _, err := awid.ParseTeamID(sel.TeamID)
	if err != nil {
		return true, err
	}
	if isAwebHostedNamespace(domain) {
		return false, nil
	}
	home, err := identityHomeForDir(request.WorkingDir)
	if err != nil {
		return true, err
	}
	cert, err := loadTeamCertificateAt(request.WorkingDir, externalIdentityHomeRoot(home), sel.TeamID)
	if err != nil {
		return true, fmt.Errorf("read own membership certificate: %w; restore this member's certificate before retiring it", err)
	}
	if cert.MemberDIDKey != sel.DID || cert.Alias != sel.Alias || cert.Team != sel.TeamID || awid.NormalizeIdentityScope(cert.IdentityScope) != awid.IdentityModeLocal {
		return true, fmt.Errorf("selected certificate does not identify this local member; reconcile its team and identity before retiring it")
	}
	state, err := awconfig.LoadTeamStateFromIdentityHome(home.Root)
	if err != nil {
		return true, err
	}
	membership := state.Membership(sel.TeamID)
	if membership == nil {
		return true, fmt.Errorf("selected team has no membership record; restore it before retiring this member")
	}
	registry, err := newRegistryClientWithPreferredBaseURL(membership.RegistryURL)
	if err != nil {
		return true, err
	}
	path, err := localRetirementReceiptPath(home, sel.WorkspaceID)
	if err != nil {
		return true, err
	}
	ctx, cancel := commandAPIContext(request.Command)
	deleted, deleteErr := request.Client.WorkspaceDelete(ctx, sel.WorkspaceID)
	cancel()
	if deleteErr != nil {
		return true, deleteErr
	}
	if deleted == nil {
		return true, fmt.Errorf("workspace deletion was not confirmed; retain this identity home and inspect the workspace before retrying")
	}
	if deleted.WorkspaceID != sel.WorkspaceID || deleted.Alias != sel.Alias {
		return true, fmt.Errorf("workspace delete did not confirm this exact member and workspace; retain the identity home and reconcile the server result before revoking its certificate")
	}
	if !deleted.IdentityDeleted {
		return true, withErrorCode("workspace_cleanup_incomplete", fmt.Errorf("workspace %s was deleted but local identity cleanup was not confirmed; retain this home and have the service operator reconcile it before certificate revocation", sel.WorkspaceID))
	}
	receipt := localRetirementReceipt{
		Version: localRetirementReceiptVersion, TeamID: sel.TeamID,
		CertificateID: cert.CertificateID, MemberDIDKey: cert.MemberDIDKey,
		RegistryURL: registry.DefaultRegistryURL,
		Delete: workspaceDeleteOutput{
			WorkspaceID: deleted.WorkspaceID, Alias: deleted.Alias,
			DeletedAt: deleted.DeletedAt, IdentityDeleted: deleted.IdentityDeleted,
		},
	}
	if err := saveLocalRetirementReceipt(path, receipt); err != nil {
		out := receipt.Delete
		out.RetirementCode, out.AliasReleasedReason = retiredRevocationPending, string(retiredRevocationPending)
		out.NextStep = "Retain this identity home and have the key holder run " + localRetirementRevokeCommand(receipt)
		printOutput(out, formatWorkspaceDelete)
		return true, withErrorCode(string(retiredRevocationPending), fmt.Errorf("workspace was deleted but its retirement receipt could not be saved: %w; %s", err, out.NextStep))
	}
	return true, finishLocalControllerRevocation(request.Command, path, receipt)
}

func saveLocalRetirementReceipt(path string, receipt localRetirementReceipt) error {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, encoded)
}

// Retry consults only the retained local mapping and the controller-signed
// registry operation. A deleted member's credential is never sent to a server.
func resumeLocalControllerRetirement(request localRetirementRequest) (bool, error) {
	home, err := identityHomeForDir(request.WorkingDir)
	if err != nil {
		return false, err
	}
	sel, err := resolveSelectionAtIdentityHome(request.WorkingDir, strings.TrimSpace(teamFlag), home)
	if err != nil {
		return false, err
	}
	target := request.Target
	if strings.EqualFold(target, sel.Alias) {
		target = sel.WorkspaceID
	}
	if !workspaceIDPattern.MatchString(target) {
		return false, nil
	}
	path, err := localRetirementReceiptPath(home, target)
	if err != nil {
		return false, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("read retirement receipt: %w; retain this identity home and repair the receipt before retrying", err)
	}
	var receipt localRetirementReceipt
	if err := json.Unmarshal(data, &receipt); err != nil {
		return true, fmt.Errorf("read retirement receipt: %w; retain this identity home and repair the receipt before retrying", err)
	}
	cert, err := loadTeamCertificateAt(request.WorkingDir, externalIdentityHomeRoot(home), sel.TeamID)
	if err != nil {
		return true, err
	}
	if receipt.Version != localRetirementReceiptVersion || receipt.TeamID != sel.TeamID || receipt.Delete.WorkspaceID != sel.WorkspaceID || receipt.Delete.Alias != sel.Alias || receipt.CertificateID != cert.CertificateID || receipt.MemberDIDKey != cert.MemberDIDKey || cert.MemberDIDKey != sel.DID || sel.IdentityScope != awid.IdentityModeLocal {
		return true, fmt.Errorf("retirement receipt does not match this exact local member, workspace and certificate; select its original identity home before retrying")
	}
	return true, finishLocalControllerRevocation(request.Command, path, receipt)
}

func localRetirementRevokeCommand(receipt localRetirementReceipt) string {
	domain, team, err := awid.ParseTeamID(receipt.TeamID)
	if err != nil {
		return "aw id team remove-member --team <team> --namespace <domain> --cert-id <certificate-id>"
	}
	return formatShellCommand([]string{"aw", "id", "team", "remove-member", "--team", team, "--namespace", domain, "--cert-id", receipt.CertificateID, "--registry", receipt.RegistryURL})
}

func finishLocalControllerRevocation(cmd *cobra.Command, path string, receipt localRetirementReceipt) error {
	out := receipt.Delete
	out.ReceiptPath = path
	out.NextStep = "Retain this identity home and retry aw workspace delete " + out.WorkspaceID + "; the key holder can instead run " + localRetirementRevokeCommand(receipt)
	if receipt.Revoked {
		out.AliasReleased, out.AliasReleasedReason, out.RetirementCode, out.NextStep = true, string(retiredAndRevoked), retiredAndRevoked, ""
		printOutput(out, formatWorkspaceDelete)
		return nil
	}
	ctx, cancel := commandAPIContext(cmd)
	err := revokeRetiredCertificate(ctx, receipt)
	cancel()
	if errorCodeOf(err) == codeControllerKeyMissing {
		out.RetirementCode, out.AliasReleasedReason = retiredKeyHolderRequired, codeControllerKeyMissing
		printOutput(out, formatWorkspaceDelete)
		return withErrorCode(string(retiredKeyHolderRequired), fmt.Errorf("workspace was deleted but certificate revocation is not confirmed; give the key holder this command: %s", localRetirementRevokeCommand(receipt)))
	}

	if err != nil {
		out.RetirementCode, out.AliasReleasedReason = retiredRevocationPending, string(retiredRevocationPending)
		printOutput(out, formatWorkspaceDelete)
		return withErrorCode(string(retiredRevocationPending), fmt.Errorf("workspace was deleted but certificate revocation is unconfirmed: %w; receipt retained at %s; retry aw workspace delete %s", err, path, out.WorkspaceID))
	}
	out.AliasReleased, out.AliasReleasedReason, out.RetirementCode = true, string(retiredAndRevoked), retiredAndRevoked
	out.NextStep = ""
	receipt.Revoked = true
	if saveErr := saveLocalRetirementReceipt(path, receipt); saveErr != nil {
		return fmt.Errorf("certificate revocation was confirmed but saving its receipt failed: %w; retain this identity home and verify the certificate before retrying", saveErr)
	}
	printOutput(out, formatWorkspaceDelete)
	return nil
}

// The registry, not a local key filename, verifies controller authority. A prior
// independently completed revocation needs no controller key to be confirmed.
func revokeRetiredCertificate(ctx context.Context, receipt localRetirementReceipt) error {
	domain, team, err := awid.ParseTeamID(receipt.TeamID)
	if err != nil {
		return err
	}
	registry, err := newRegistryClientWithPreferredBaseURL(receipt.RegistryURL)
	if err != nil {
		return err
	}
	status, err := registry.GetTeamCertificateStatus(ctx, receipt.RegistryURL, domain, team, receipt.CertificateID)
	if err != nil {
		return err
	}
	if status.Status == certificateRevoked {
		return nil
	}
	key, err := awconfig.LoadTeamKey(domain, team)
	if errors.Is(err, os.ErrNotExist) {
		return withErrorCode(codeControllerKeyMissing, err)
	}
	if err != nil {
		return err
	}
	if _, err := revokeRegistryTeamCertificate(ctx, registry, receipt.RegistryURL, domain, team, receipt.CertificateID, key); err != nil {
		return err
	}
	status, err = registry.GetTeamCertificateStatus(ctx, receipt.RegistryURL, domain, team, receipt.CertificateID)
	if err != nil {
		return err
	}
	if status.Status != certificateRevoked {
		return fmt.Errorf("registry did not confirm certificate revocation")
	}
	return nil
}
