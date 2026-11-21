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
// docs/awid-sot.md:853-858): prepare the exact receipt, delete under the member
// credential, then sign the revocation with the team controller key.
func retireLocalControllerMember(request localRetirementRequest) (bool, error) {
	sel := request.Selection
	if sel == nil || !strings.EqualFold(sel.WorkspaceID, request.Target) || sel.IdentityScope != awid.IdentityModeLocal {
		return false, nil
	}
	domain, team, err := awid.ParseTeamID(sel.TeamID)
	if err != nil {
		return true, err
	}
	if isAwebHostedNamespace(domain) {
		return false, nil
	}
	if _, err := awconfig.LoadTeamKey(domain, team); errors.Is(err, os.ErrNotExist) {
		// Without controller custody, keep the released external-home refusal
		// or the implicit workspace-only delete. Neither claims alias release.
		return false, nil
	} else if err != nil {
		return true, fmt.Errorf("read team controller key: %w; repair the team key before retrying retirement", err)
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
	prepared := localRetirementReceipt{
		Version: localRetirementReceiptVersion, TeamID: sel.TeamID,
		CertificateID: cert.CertificateID, MemberDIDKey: cert.MemberDIDKey,
		RegistryURL: registry.DefaultRegistryURL,
		Delete:      workspaceDeleteOutput{WorkspaceID: sel.WorkspaceID, Alias: sel.Alias},
	}
	return true, runLocalRetirementReceipt(request, path, cert, &prepared)
}

func saveLocalRetirementReceipt(path string, receipt localRetirementReceipt) error {
	encoded, err := json.Marshal(receipt)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, encoded)
}

// A confirmed delete retries only the controller operation. A prepared receipt
// retries the exact workspace delete until the service confirms its cascade.
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
	_, err = os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return true, fmt.Errorf("read retirement receipt: %w; retain this identity home and repair the receipt before retrying", err)
	}
	cert, err := loadTeamCertificateAt(request.WorkingDir, externalIdentityHomeRoot(home), sel.TeamID)
	if err != nil {
		return true, err
	}
	request.Selection = sel
	return true, runLocalRetirementReceipt(request, path, cert, nil)
}

// Serialize the receipt across preparation, confirmation and revocation. A
// second command may advance the receipt before this one acquires the lock.
func runLocalRetirementReceipt(request localRetirementRequest, path string, cert *awid.TeamCertificate, prepared *localRetirementReceipt) (result error) {
	lock, err := awconfig.TryLockExclusive(path + ".lock")
	if err != nil {
		return withErrorCode("retirement_receipt_unavailable", fmt.Errorf("lock retirement receipt: %w; check its directory or let the active retirement finish, then retry", err))
	}
	defer func() { result = errors.Join(result, lock.Close()) }()

	var receipt localRetirementReceipt
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist) && prepared != nil:
		receipt = *prepared
		if err := saveLocalRetirementReceipt(path, receipt); err != nil {
			return withErrorCode("retirement_receipt_unavailable", fmt.Errorf("save prepared retirement receipt: %w; repair its directory before retrying retirement", err))
		}
	case err != nil:
		return fmt.Errorf("read retirement receipt: %w; retain this identity home and repair the receipt before retrying", err)
	default:
		if err := json.Unmarshal(data, &receipt); err != nil {
			return fmt.Errorf("read retirement receipt: %w; retain this identity home and repair the receipt before retrying", err)
		}
	}

	sel := request.Selection
	if receipt.Version != localRetirementReceiptVersion || receipt.TeamID != sel.TeamID || receipt.Delete.WorkspaceID != sel.WorkspaceID || receipt.Delete.Alias != sel.Alias || receipt.CertificateID != cert.CertificateID || receipt.MemberDIDKey != cert.MemberDIDKey || cert.MemberDIDKey != sel.DID || sel.IdentityScope != awid.IdentityModeLocal || (receipt.Revoked && !receipt.Delete.IdentityDeleted) {
		return fmt.Errorf("retirement receipt does not match this exact local member, workspace and certificate; select its original identity home before retrying")
	}
	if !receipt.Delete.IdentityDeleted {
		if err := confirmLocalRetirementDelete(request, path, &receipt); err != nil {
			return err
		}
	}
	return finishLocalControllerRevocation(request.Command, path, receipt)
}

func confirmLocalRetirementDelete(request localRetirementRequest, path string, receipt *localRetirementReceipt) error {
	client := request.Client
	if client == nil {
		current, sel, err := resolveClientSelectionForDir(request.WorkingDir)
		if err != nil {
			return fmt.Errorf("reopen prepared retirement: %w; retain this identity home and restore its member credentials before retrying", err)
		}
		if sel.TeamID != receipt.TeamID || sel.DID != receipt.MemberDIDKey || sel.WorkspaceID != receipt.Delete.WorkspaceID {
			return fmt.Errorf("prepared retirement no longer matches this member; select its original identity home before retrying")
		}
		client = current
	}
	ctx, cancel := commandAPIContext(request.Command)
	deleted, err := client.WorkspaceDelete(ctx, receipt.Delete.WorkspaceID)
	cancel()
	if err != nil {
		return fmt.Errorf("workspace cleanup is not confirmed: %w; retain the prepared receipt and retry the same workspace delete or ask the service operator to reconcile it", err)
	}
	if deleted == nil || deleted.WorkspaceID != receipt.Delete.WorkspaceID || deleted.Alias != receipt.Delete.Alias || !deleted.IdentityDeleted {
		return withErrorCode("workspace_cleanup_incomplete", fmt.Errorf("workspace delete did not confirm cleanup of this exact local member and workspace; retain the prepared receipt and have the service operator reconcile it before certificate revocation"))
	}
	receipt.Delete.DeletedAt = deleted.DeletedAt
	receipt.Delete.IdentityDeleted = true
	if err := saveLocalRetirementReceipt(path, *receipt); err != nil {
		return withErrorCode("retirement_receipt_unavailable", fmt.Errorf("save confirmed workspace cleanup: %w; retain the prepared receipt, repair its directory and retry the same workspace delete", err))
	}
	return nil
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
		return writeWorkspaceDeleteOutput(out)
	}
	ctx, cancel := commandAPIContext(cmd)
	err := revokeRetiredCertificate(ctx, receipt)
	cancel()
	if errorCodeOf(err) == codeControllerKeyMissing {
		out.RetirementCode, out.AliasReleasedReason = retiredKeyHolderRequired, codeControllerKeyMissing
		outputErr := writeWorkspaceDeleteOutput(out)
		return errors.Join(withErrorCode(string(retiredKeyHolderRequired), fmt.Errorf("workspace was deleted but certificate revocation is not confirmed; give the key holder this command: %s", localRetirementRevokeCommand(receipt))), outputErr)
	}

	if err != nil {
		out.RetirementCode, out.AliasReleasedReason = retiredRevocationPending, string(retiredRevocationPending)
		outputErr := writeWorkspaceDeleteOutput(out)
		return errors.Join(withErrorCode(string(retiredRevocationPending), fmt.Errorf("workspace was deleted but certificate revocation is unconfirmed: %w; receipt retained at %s; retry aw workspace delete %s", err, path, out.WorkspaceID)), outputErr)
	}
	out.AliasReleased, out.AliasReleasedReason, out.RetirementCode = true, string(retiredAndRevoked), retiredAndRevoked
	out.NextStep = ""
	receipt.Revoked = true
	if saveErr := saveLocalRetirementReceipt(path, receipt); saveErr != nil {
		return fmt.Errorf("certificate revocation was confirmed but saving its receipt failed: %w; retain this identity home and verify the certificate before retrying", saveErr)
	}
	return writeWorkspaceDeleteOutput(out)
}

// writeWorkspaceDeleteOutput preserves the outcome's recovery before another
// retirement attempt; output failure does not change certificate state
// (docs/cli-integration-contract.md:203-207).
func writeWorkspaceDeleteOutput(out workspaceDeleteOutput) error {
	if err := printOutput(out, formatWorkspaceDelete); err != nil {
		if out.RetirementCode == "" && !out.AliasReleased {
			return fmt.Errorf("write workspace delete result: %w. Check the output destination and inspect the workspace before retrying deletion.", err)
		}
		return fmt.Errorf("write retirement result: %w. Check the output destination and retain this identity home; follow any retirement recovery instructions before retrying.", err)
	}
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
