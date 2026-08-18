package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
)

const hostedRemovalRecoveryDir = "hosted-removals"

type hostedRemovalOperation struct {
	OperationID                   string `json:"operation_id"`
	Status                        string `json:"status"`
	TeamID                        string `json:"team_id"`
	CanonicalTeamID               string `json:"canonical_team_id"`
	WorkspaceID                   string `json:"workspace_id"`
	AgentID                       string `json:"agent_id"`
	CertificateID                 string `json:"certificate_id"`
	Alias                         string `json:"alias,omitempty"`
	MemberAddress                 string `json:"member_address,omitempty"`
	IdentityScope                 string `json:"identity_scope"`
	RegistryRevokeOutcome         string `json:"registry_revoke_outcome,omitempty"`
	GrantsRevoked                 int    `json:"grants_revoked,omitempty"`
	CertificateBoundGrantsRevoked int    `json:"certificate_bound_grants_revoked,omitempty"`
	LegacyUnboundGrantsRevoked    int    `json:"legacy_unbound_grants_revoked,omitempty"`
	AuditID                       string `json:"audit_id,omitempty"`
}

type hostedRemovalRecovery struct {
	OperationID     string `json:"operation_id"`
	Status          string `json:"status"`
	CanonicalTeamID string `json:"canonical_team_id"`
	WorkspaceID     string `json:"workspace_id"`
	AgentID         string `json:"agent_id"`
	CertificateID   string `json:"certificate_id"`
	Alias           string `json:"alias,omitempty"`
	MemberAddress   string `json:"member_address,omitempty"`
	CreatedAt       string `json:"created_at"`
}

func prepareHostedRemoval(ctx context.Context, awebURL, apiKey, teamID, workspaceID, agentID string) (*hostedRemovalOperation, error) {
	return doHostedRemovalRequest(ctx, http.MethodPost, awebURL, apiKey, teamID, "/agents/removals/prepare", map[string]string{
		"workspace_id": workspaceID,
		"agent_id":     agentID,
	})
}

func getHostedRemoval(ctx context.Context, awebURL, apiKey, teamID, operationID string) (*hostedRemovalOperation, error) {
	return doHostedRemovalRequest(ctx, http.MethodGet, awebURL, apiKey, teamID, "/agents/removals/"+urlPathSegmentEscape(operationID), nil)
}

func commitHostedRemoval(ctx context.Context, awebURL, apiKey, teamID, operationID string) (*hostedRemovalOperation, error) {
	return doHostedRemovalRequest(ctx, http.MethodPost, awebURL, apiKey, teamID, "/agents/removals/"+urlPathSegmentEscape(operationID)+"/commit", nil)
}

func abortHostedRemoval(ctx context.Context, awebURL, apiKey, teamID, operationID string) (*hostedRemovalOperation, error) {
	return doHostedRemovalRequest(ctx, http.MethodPost, awebURL, apiKey, teamID, "/agents/removals/"+urlPathSegmentEscape(operationID)+"/abort", nil)
}

func listHostedRemovals(ctx context.Context, awebURL, apiKey, teamID string) ([]hostedRemovalOperation, error) {
	path := hostedRemovalAPIPath(awebURL, teamID, "/agents/removals")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(awebURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	body, err := executeHostedRemovalRequest(req, apiKey, "list hosted removals")
	if err != nil {
		return nil, err
	}
	var operations []hostedRemovalOperation
	if err := json.Unmarshal(body, &operations); err != nil {
		return nil, fmt.Errorf("decode hosted removal list: %w", err)
	}
	for i := range operations {
		if err := validateHostedRemovalOperation(&operations[i], teamID, "", "", ""); err != nil {
			return nil, fmt.Errorf("invalid hosted removal list item: %w", err)
		}
	}
	return operations, nil
}

func doHostedRemovalRequest(ctx context.Context, method, awebURL, apiKey, teamID, suffix string, payload any) (*hostedRemovalOperation, error) {
	var body []byte
	var err error
	if payload != nil {
		body, err = json.Marshal(payload)
		if err != nil {
			return nil, err
		}
	}
	path := hostedRemovalAPIPath(awebURL, teamID, suffix)
	req, err := http.NewRequestWithContext(ctx, method, strings.TrimRight(awebURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	responseBody, err := executeHostedRemovalRequest(req, apiKey, "hosted removal")
	if err != nil {
		return nil, err
	}
	var operation hostedRemovalOperation
	if err := json.Unmarshal(responseBody, &operation); err != nil {
		return nil, fmt.Errorf("decode hosted removal response: %w", err)
	}
	return &operation, nil
}

func hostedRemovalAPIPath(awebURL, teamID, suffix string) string {
	path := "/api/v1/teams/" + urlPathSegmentEscape(teamID) + suffix
	if strings.HasSuffix(strings.TrimRight(strings.TrimSpace(awebURL), "/"), "/api") {
		path = strings.TrimPrefix(path, "/api")
	}
	return path
}

func executeHostedRemovalRequest(req *http.Request, apiKey, label string) ([]byte, error) {
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Accept", "application/json")
	resp, err := awid.DoNoRedirect(&http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	limit := int64(awid.MaxResponseSize)
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		limit = awid.MaxErrorResponseSize
	}
	body, err := awid.ReadAllBounded(resp.Body, limit)
	if err != nil {
		return nil, fmt.Errorf("read %s response: %w", label, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("%s returned %d: %s", label, resp.StatusCode, strings.TrimSpace(string(body)))
	}
	return body, nil
}

func validateHostedRemovalOperation(operation *hostedRemovalOperation, teamID, workspaceID, agentID, certificateID string) error {
	if operation == nil {
		return fmt.Errorf("empty operation response")
	}
	for label, value := range map[string]string{
		"operation_id":      operation.OperationID,
		"team_id":           operation.TeamID,
		"canonical_team_id": operation.CanonicalTeamID,
		"workspace_id":      operation.WorkspaceID,
		"agent_id":          operation.AgentID,
		"certificate_id":    operation.CertificateID,
		"status":            operation.Status,
	} {
		if strings.TrimSpace(value) == "" {
			return fmt.Errorf("response is missing %s", label)
		}
	}
	if strings.ContainsAny(operation.OperationID, `/\\`) || strings.Contains(operation.OperationID, "..") {
		return fmt.Errorf("response operation_id is not a safe opaque identifier")
	}
	if teamID != "" && operation.CanonicalTeamID != teamID {
		return fmt.Errorf("response canonical team %q does not match requested team %q", operation.CanonicalTeamID, teamID)
	}
	if workspaceID != "" && operation.WorkspaceID != workspaceID {
		return fmt.Errorf("response workspace %q does not match requested workspace %q", operation.WorkspaceID, workspaceID)
	}
	if agentID != "" && operation.AgentID != agentID {
		return fmt.Errorf("response agent %q does not match requested agent %q", operation.AgentID, agentID)
	}
	if certificateID != "" && operation.CertificateID != certificateID {
		return fmt.Errorf("response certificate %q does not match prepared certificate %q", operation.CertificateID, certificateID)
	}
	return nil
}

func hostedRemovalRecoveryRoot(workingDir string) string {
	return filepath.Join(interactionLogRoot(workingDir), ".aw", hostedRemovalRecoveryDir)
}

func hostedRemovalRecoveryPath(workingDir, operationID string) (string, error) {
	operationID = strings.TrimSpace(operationID)
	if operationID == "" || strings.ContainsAny(operationID, `/\\`) || strings.Contains(operationID, "..") {
		return "", fmt.Errorf("invalid hosted removal operation id")
	}
	return filepath.Join(hostedRemovalRecoveryRoot(workingDir), operationID+".json"), nil
}

func saveHostedRemovalRecovery(workingDir string, recovery hostedRemovalRecovery) (string, error) {
	path, err := hostedRemovalRecoveryPath(workingDir, recovery.OperationID)
	if err != nil {
		return "", err
	}
	if err := pathpreflight.PreflightDir(filepath.Dir(path), "hosted removal recovery directory", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return "", err
	}
	if err := pathpreflight.PreflightFile(path, "hosted removal recovery file", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return "", err
	}
	payload, err := json.MarshalIndent(recovery, "", "  ")
	if err != nil {
		return "", err
	}
	payload = append(payload, '\n')
	if err := awid.AtomicWriteFile(path, payload); err != nil {
		return "", err
	}
	return path, nil
}

func clearHostedRemovalRecovery(workingDir, operationID string) error {
	path, err := hostedRemovalRecoveryPath(workingDir, operationID)
	if err != nil {
		return err
	}
	if err := pathpreflight.PreflightFile(path, "hosted removal recovery file", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func resolveExactRetirementWorkspace(ctx context.Context, client *aweb.Client, alias string) (*aweb.WorkspaceInfo, error) {
	listCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	resp, err := client.WorkspaceList(listCtx, aweb.WorkspaceListParams{Alias: alias, IncludePresence: false, Limit: 2})
	if err != nil {
		return nil, fmt.Errorf("could not resolve hosted removal workspace for %s: %w", alias, err)
	}
	matches := make([]aweb.WorkspaceInfo, 0, len(resp.Workspaces))
	for _, workspace := range resp.Workspaces {
		if strings.EqualFold(strings.TrimSpace(workspace.Alias), alias) {
			matches = append(matches, workspace)
		}
	}
	if len(matches) != 1 {
		return nil, fmt.Errorf("hosted removal requires exactly one live workspace for %s; found %d", alias, len(matches))
	}
	if strings.TrimSpace(matches[0].WorkspaceID) == "" || strings.TrimSpace(matches[0].AgentID) == "" {
		return nil, fmt.Errorf("hosted removal workspace is missing immutable workspace or agent id")
	}
	return &matches[0], nil
}

func releaseExactHostedWorkspace(ctx context.Context, client *aweb.Client, workspace aweb.WorkspaceInfo) (retireStoreOutcome, *aweb.DeleteWorkspaceResponse) {
	deleteCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	deleted, err := client.WorkspaceDelete(deleteCtx, workspace.WorkspaceID)
	if err != nil {
		if code, reason := workspaceDeleteProtectiveReason(err); code != "" {
			return retireStoreOutcome{Store: storeCoordination, Result: storeBlocked, Detail: fmt.Sprintf("released nothing: %s", reason)}, nil
		}
		return retireStoreOutcome{Store: storeCoordination, Result: storeFailed, Detail: fmt.Sprintf("could not delete exact workspace %s: %v", workspace.WorkspaceID, err)}, nil
	}
	if deleted == nil {
		return retireStoreOutcome{Store: storeCoordination, Result: storeUnchanged, Detail: fmt.Sprintf("exact workspace %s was already released", workspace.WorkspaceID)}, nil
	}
	if deleted.WorkspaceID != workspace.WorkspaceID {
		return retireStoreOutcome{Store: storeCoordination, Result: storeFailed, Detail: fmt.Sprintf("workspace delete returned %s, expected exact %s", deleted.WorkspaceID, workspace.WorkspaceID)}, deleted
	}
	if deleted.ClaimsReleased == nil {
		return retireStoreOutcome{Store: storeCoordination, Result: storeChanged, Detail: fmt.Sprintf("deleted exact workspace %s; server did not report the claim count", deleted.WorkspaceID)}, deleted
	}
	return retireStoreOutcome{Store: storeCoordination, Result: storeChanged, Detail: fmt.Sprintf("deleted exact workspace %s and released %d task claim(s)", deleted.WorkspaceID, *deleted.ClaimsReleased)}, deleted
}

func runHostedLocalRemoval(ctx context.Context, client *aweb.Client, workingDir, teamID, memberAddress string, workspace aweb.WorkspaceInfo) (teamRemoveAgentOutput, error) {
	awebURL, apiKey, err := resolveHostedTeamRemoveAuth(workingDir, teamID)
	if err != nil {
		return teamRemoveAgentOutput{}, err
	}
	prepared, err := prepareHostedRemoval(ctx, awebURL, apiKey, teamID, workspace.WorkspaceID, workspace.AgentID)
	if err != nil {
		return teamRemoveAgentOutput{}, fmt.Errorf("hosted removal prepare failed before coordination release: %w", err)
	}
	if err := validateHostedRemovalOperation(prepared, teamID, workspace.WorkspaceID, workspace.AgentID, ""); err != nil {
		return teamRemoveAgentOutput{}, fmt.Errorf("hosted removal prepare response refused before coordination release: %w", err)
	}
	if prepared.Status != "prepared" || prepared.IdentityScope != "local" || strings.TrimSpace(prepared.MemberAddress) != "" || !strings.EqualFold(strings.TrimSpace(prepared.Alias), strings.TrimSpace(workspace.Alias)) {
		return teamRemoveAgentOutput{}, fmt.Errorf("hosted removal prepare returned an ineligible subject (status=%s scope=%s address=%q alias=%q)", prepared.Status, prepared.IdentityScope, prepared.MemberAddress, prepared.Alias)
	}
	recovery := hostedRemovalRecovery{
		OperationID: prepared.OperationID, Status: "prepared", CanonicalTeamID: teamID,
		WorkspaceID: prepared.WorkspaceID, AgentID: prepared.AgentID, CertificateID: prepared.CertificateID,
		Alias: prepared.Alias, MemberAddress: memberAddress, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	}
	recoveryPath, err := saveHostedRemovalRecovery(workingDir, recovery)
	if err != nil {
		return teamRemoveAgentOutput{}, fmt.Errorf("persist hosted removal recovery before coordination release: %w", err)
	}
	out := teamRemoveAgentOutput{
		TeamID: teamID, MemberAddress: memberAddress, Alias: prepared.Alias,
		WorkspaceID: prepared.WorkspaceID, CertificateID: prepared.CertificateID,
		OperationID: prepared.OperationID, RecoveryPath: recoveryPath,
	}
	coordination, deleted := releaseExactHostedWorkspace(ctx, client, workspace)
	out.Stores = append(out.Stores, coordination)
	if deleted != nil {
		out.ClaimsReleased = deleted.ClaimsReleased
	}
	if !coordination.terminal() {
		out.Status = retirementIncomplete
		out.Stores = append(out.Stores, retireStoreOutcome{Store: storeCertificate, Result: storeNotAttempted, Detail: "not attempted; abort or resume the prepared hosted removal using operation " + prepared.OperationID})
		return out, fmt.Errorf("coordination release failed; recovery retained at %s", recoveryPath)
	}
	recovery.Status = "released"
	if _, err := saveHostedRemovalRecovery(workingDir, recovery); err != nil {
		out.Status = retirementIncomplete
		out.Stores = append(out.Stores, retireStoreOutcome{Store: storeCertificate, Result: storeNotAttempted, Detail: "not attempted because recovery checkpoint after release could not be persisted"})
		return out, fmt.Errorf("workspace released but recovery checkpoint failed; operation %s remains recoverable from AC: %w", prepared.OperationID, err)
	}
	committed, err := commitHostedRemoval(ctx, awebURL, apiKey, teamID, prepared.OperationID)
	if err != nil {
		out.Status = retirementIncomplete
		out.Stores = append(out.Stores, retireStoreOutcome{Store: storeCertificate, Result: storeFailed, Detail: fmt.Sprintf("commit pending for operation %s: %v; resume with --resume-operation %s", prepared.OperationID, err, prepared.OperationID)})
		return out, err
	}
	if err := validateHostedRemovalOperation(committed, teamID, prepared.WorkspaceID, prepared.AgentID, prepared.CertificateID); err != nil || committed.Status != "committed" {
		out.Status = retirementIncomplete
		out.Stores = append(out.Stores, retireStoreOutcome{Store: storeCertificate, Result: storeFailed, Detail: "commit response did not match the prepared operation; recovery retained"})
		if err != nil {
			return out, err
		}
		return out, fmt.Errorf("hosted removal commit returned status %q", committed.Status)
	}
	out.CertificateResult = committed.RegistryRevokeOutcome
	switch committed.RegistryRevokeOutcome {
	case "revoked":
		out.Stores = append(out.Stores, retireStoreOutcome{Store: storeCertificate, Result: storeChanged, Detail: "AWID revocation and terminal hosted cleanup committed"})
	case "already_revoked":
		out.Stores = append(out.Stores, retireStoreOutcome{Store: storeCertificate, Result: storeUnchanged, Detail: "AWID read-back proved the exact certificate was already revoked; terminal hosted cleanup committed"})
	default:
		out.Status = retirementIncomplete
		out.Stores = append(out.Stores, retireStoreOutcome{Store: storeCertificate, Result: storeFailed, Detail: "committed response carried an unknown registry revoke outcome; recovery retained"})
		return out, fmt.Errorf("hosted removal commit returned unknown registry outcome %q", committed.RegistryRevokeOutcome)
	}
	out.Status = retirementRetired
	if err := clearHostedRemovalRecovery(workingDir, prepared.OperationID); err != nil {
		return out, fmt.Errorf("hosted removal committed but local recovery cleanup failed at %s: %w", recoveryPath, err)
	}
	out.RecoveryPath = ""
	return out, nil
}

func resumeHostedRemoval(ctx context.Context, client *aweb.Client, workingDir, teamID, operationID string) (*hostedRemovalOperation, error) {
	awebURL, apiKey, err := resolveHostedTeamRemoveAuth(workingDir, teamID)
	if err != nil {
		return nil, err
	}
	operation, err := getHostedRemoval(ctx, awebURL, apiKey, teamID, operationID)
	if err != nil {
		return nil, err
	}
	if err := validateHostedRemovalOperation(operation, teamID, "", "", ""); err != nil {
		return nil, err
	}
	if operation.OperationID != operationID {
		return nil, fmt.Errorf("hosted removal get returned a different operation")
	}
	switch operation.Status {
	case "committed":
		if err := clearHostedRemovalRecovery(workingDir, operationID); err != nil {
			return nil, fmt.Errorf("hosted removal committed but local recovery cleanup failed: %w", err)
		}
		return operation, nil
	case "prepared", "revocation_pending":
		// These are the only states whose durable operation can still converge.
	case "aborted":
		return nil, fmt.Errorf("hosted removal %s was aborted; refusing to release coordination state", operationID)
	default:
		return nil, fmt.Errorf("hosted removal %s has unknown status %q; refusing to release coordination state", operationID, operation.Status)
	}
	workspace := aweb.WorkspaceInfo{WorkspaceID: operation.WorkspaceID, AgentID: operation.AgentID, Alias: operation.Alias}
	_, _ = releaseExactHostedWorkspace(ctx, client, workspace)
	committed, err := commitHostedRemoval(ctx, awebURL, apiKey, teamID, operationID)
	if err != nil {
		return nil, fmt.Errorf("hosted removal %s remains pending; retry --resume-operation: %w", operationID, err)
	}
	if err := validateHostedRemovalOperation(committed, teamID, operation.WorkspaceID, operation.AgentID, operation.CertificateID); err != nil {
		return nil, err
	}
	if committed.Status != "committed" {
		return nil, fmt.Errorf("hosted removal %s returned status %q", operationID, committed.Status)
	}
	if err := clearHostedRemovalRecovery(workingDir, operationID); err != nil {
		return nil, fmt.Errorf("hosted removal committed but local recovery cleanup failed: %w", err)
	}
	return committed, nil
}

func validateTeamRemoveAgentArgs(_ *cobra.Command, args []string) error {
	modes := 0
	if strings.TrimSpace(teamHumanRemoveResumeOperation) != "" {
		modes++
	}
	if strings.TrimSpace(teamHumanRemoveAbortOperation) != "" {
		modes++
	}
	if teamHumanRemoveListPending {
		modes++
	}
	if modes > 1 {
		return usageError("--resume-operation, --abort-operation, and --list-pending are mutually exclusive")
	}
	if modes == 1 {
		if len(args) != 0 {
			return usageError("recovery operations do not accept a member address")
		}
		return nil
	}
	if len(args) != 1 {
		return usageError("remove-agent requires exactly one member address")
	}
	return nil
}

func formatHostedRemovalOperation(value any) string {
	operation, ok := value.(*hostedRemovalOperation)
	if !ok || operation == nil {
		return fmt.Sprint(value)
	}
	return fmt.Sprintf("Hosted removal %s: %s\nTeam: %s\nWorkspace: %s\nAgent: %s\nCertificate: %s\n", operation.OperationID, operation.Status, operation.CanonicalTeamID, operation.WorkspaceID, operation.AgentID, operation.CertificateID)
}

func formatHostedRemovalList(value any) string {
	operations, ok := value.([]hostedRemovalOperation)
	if !ok {
		return fmt.Sprint(value)
	}
	if len(operations) == 0 {
		return "No pending hosted removal operations.\n"
	}
	var b strings.Builder
	for i := range operations {
		b.WriteString(formatHostedRemovalOperation(&operations[i]))
	}
	return b.String()
}
