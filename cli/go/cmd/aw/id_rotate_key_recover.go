package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/crashtest"
	"github.com/spf13/cobra"
)

type idRotationRecoveryOutput struct {
	Status        string `json:"status"`
	OperationID   string `json:"operation_id,omitempty"`
	StableID      string `json:"stable_id,omitempty"`
	OldDID        string `json:"old_did,omitempty"`
	NewDID        string `json:"new_did,omitempty"`
	RegistryURL   string `json:"registry_url,omitempty"`
	StatePath     string `json:"state_path,omitempty"`
	Detail        string `json:"detail,omitempty"`
	RerunRequired bool   `json:"rerun_required,omitempty"`
}

var idRotateKeyRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Reconcile and safely finish a pending identity key rotation",
	Args:  cobra.NoArgs,
	RunE:  runIDRotateKeyRecover,
}

var idRotateKeyStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Inspect pending identity key rotation state without changing it",
	Args:  cobra.NoArgs,
	RunE:  runIDRotateKeyStatus,
}

func init() {
	idRotateKeyCmd.AddCommand(idRotateKeyRecoverCmd, idRotateKeyStatusCmd)
}

func runIDRotateKeyRecover(cmd *cobra.Command, args []string) error {
	identity, rotationDir, lockPath, err := prepareRotationIdentity(false)
	if err != nil {
		return err
	}
	transactionLock, err := awconfig.LockExclusive(lockPath)
	if err != nil {
		return fmt.Errorf("lock identity key rotation: %w", err)
	}
	defer func() { _ = transactionLock.Close() }()

	identity, err = reloadRotationIdentity(identity, rotationDir)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := recoverPendingRotation(ctx, identity, rotationDir)
	if err != nil {
		return err
	}
	if out.Status == "no_pending" {
		if err := validateResolvedIdentity(identity); err != nil {
			return err
		}
	}
	printOutput(out, formatIDRotationRecovery)
	return nil
}

func runIDRotateKeyStatus(cmd *cobra.Command, args []string) error {
	identity, rotationDir, lockPath, err := prepareRotationIdentity(false)
	if err != nil {
		return err
	}
	// Status is inspection-only: fail immediately rather than queue behind a
	// mutating rotation whose network request may take tens of seconds.
	transactionLock, err := awconfig.TryLockExistingExclusive(lockPath)
	if errors.Is(err, awconfig.ErrLockUnavailable) {
		printOutput(idRotationRecoveryOutput{
			Status: "operation_in_progress", StableID: identity.StableID,
			StatePath: pendingRotationStatePath(rotationDir, identity.StableID),
			Detail:    "another identity key rotation holds the transaction lock",
		}, formatIDRotationRecovery)
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect identity key rotation lock: %w", err)
	}
	if transactionLock != nil {
		defer func() { _ = transactionLock.Close() }()
	}

	state, err := loadPendingRotationState(rotationDir, identity.StableID)
	if err != nil {
		return err
	}
	if state == nil {
		if err := validateResolvedIdentity(identity); err != nil {
			return err
		}
		printOutput(idRotationRecoveryOutput{
			Status: "no_pending", StableID: identity.StableID,
			StatePath: pendingRotationStatePath(rotationDir, identity.StableID),
		}, formatIDRotationRecovery)
		return nil
	}
	if err := validatePendingRotationState(rotationDir, identity.StableID, state); err != nil {
		return fmt.Errorf("invalid pending rotation state: %w", err)
	}
	printOutput(rotationRecoveryOutput("pending", rotationDir, state), formatIDRotationRecovery)
	return nil
}

func prepareRotationIdentity(requireSigningKey bool) (*awconfig.ResolvedIdentity, string, string, error) {
	identity, err := resolveRotationIdentity()
	if err != nil {
		return nil, "", "", err
	}
	if strings.TrimSpace(identity.IdentityScope) != awid.IdentityModeGlobal {
		return nil, "", "", usageError("this command requires a global identity")
	}
	if strings.TrimSpace(identity.Custody) != awid.CustodySelf {
		return nil, "", "", usageError("this command requires a self-custodial identity")
	}
	if strings.TrimSpace(identity.StableID) == "" {
		return nil, "", "", fmt.Errorf("current identity is missing a did:aw stable identifier")
	}
	if requireSigningKey {
		if err := validateResolvedIdentity(identity); err != nil {
			return nil, "", "", err
		}
		signingKey, err := resolveIdentitySigningKey(identity)
		if err != nil {
			return nil, "", "", err
		}
		if err := requirePersistentSelfCustodialIdentity(identity, signingKey); err != nil {
			return nil, "", "", err
		}
	}
	rotationDir, err := rotationStateDirForIdentity(identity)
	if err != nil {
		return nil, "", "", err
	}
	lockPath := pendingRotationStatePath(rotationDir, identity.StableID) + ".lock"
	if err := preflightRotationFile(lockPath); err != nil {
		return nil, "", "", err
	}
	return identity, rotationDir, lockPath, nil
}

func resolveRotationIdentity() (*awconfig.ResolvedIdentity, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return nil, err
	}
	identityHome, err := identityHomeForDir(workingDir)
	if err != nil {
		return nil, err
	}
	identity, err := awconfig.ResolveIdentityFromHome(workingDir, identityHome.Root)
	if errors.Is(err, os.ErrNotExist) {
		return resolveEphemeralIdentityWithoutState(workingDir)
	}
	if err != nil {
		return nil, err
	}
	identity.ExternalIdentityHome = identityHome.External()
	if strings.TrimSpace(identity.DID) == "" {
		return nil, usageError("current identity is invalid: .aw/identity.yaml is missing did")
	}
	return identity, nil
}

func reloadRotationIdentity(lockIdentity *awconfig.ResolvedIdentity, rotationDir string) (*awconfig.ResolvedIdentity, error) {
	identity, err := resolveRotationIdentity()
	if err != nil {
		return nil, err
	}
	currentRotationDir, err := rotationStateDirForIdentity(identity)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(identity.StableID) != strings.TrimSpace(lockIdentity.StableID) || filepath.Clean(currentRotationDir) != filepath.Clean(rotationDir) {
		return nil, fmt.Errorf("active identity changed while waiting for the rotation lock; retry the command")
	}
	return identity, nil
}

func recoverPendingRotation(ctx context.Context, identity *awconfig.ResolvedIdentity, rotationDir string) (idRotationRecoveryOutput, error) {
	state, err := loadPendingRotationState(rotationDir, identity.StableID)
	if err != nil {
		return idRotationRecoveryOutput{}, err
	}
	if state == nil {
		return idRotationRecoveryOutput{
			Status: "no_pending", StableID: identity.StableID,
			StatePath: pendingRotationStatePath(rotationDir, identity.StableID),
		}, nil
	}
	if err := validatePendingRotationState(rotationDir, identity.StableID, state); err != nil {
		return idRotationRecoveryOutput{}, fmt.Errorf("invalid pending rotation state: %w", err)
	}
	out := rotationRecoveryOutput("unknown_preserved", rotationDir, state)
	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		out.Detail = err.Error()
		return out, nil
	}
	registryURL := strings.TrimSpace(state.RegistryURL)
	if registryURL == "" {
		registryURL, err = currentIdentityRegistryURL(ctx, identity, registry)
		if err != nil {
			out.Detail = err.Error()
			return out, nil
		}
	}
	out.RegistryURL = registryURL
	resolution, err := registry.ResolveKeyAt(ctx, registryURL, identity.StableID)
	if err != nil {
		out.Detail = fmt.Sprintf("authoritative registry state is unknown; replacement key preserved: %v", err)
		return out, nil
	}
	if err := validateRotationResolutionIdentity(resolution, state.StableID); err != nil {
		out.Detail = fmt.Sprintf("authoritative registry identity is unknown; replacement key and state preserved: %v", err)
		return out, nil
	}
	switch strings.TrimSpace(resolution.CurrentDIDKey) {
	case strings.TrimSpace(state.NewDID):
		if err := finalizePendingRotation(identity, rotationDir, state); err != nil {
			return idRotationRecoveryOutput{}, err
		}
		out.Status = "finalized"
		out.Detail = "registry uses the replacement key; local identity was finalized"
	case strings.TrimSpace(state.OldDID):
		if safe, detail := localRotationMatchesDID(identity, state.OldDID); !safe {
			out.Detail = "registry uses the old key, but " + detail + "; replacement key and state preserved"
			return out, nil
		}
		if err := cleanupPendingRotationKeypair(state.PendingKey, state.NewDID); err != nil {
			return idRotationRecoveryOutput{}, fmt.Errorf("discard unapplied replacement key for operation %s: %w", state.OperationID, err)
		}
		if err := removePendingRotationStateOwned(rotationDir, state.StableID, state.OperationID); err != nil {
			return idRotationRecoveryOutput{}, fmt.Errorf("remove rolled-back rotation state: %w", err)
		}
		out.Status = "rolled_back"
		out.Detail = "registry still uses the old key; unapplied replacement was discarded"
	default:
		out.Detail = fmt.Sprintf("registry uses unexpected did:key %s; replacement key and state preserved", strings.TrimSpace(resolution.CurrentDIDKey))
	}
	return out, nil
}

func validateRotationResolutionIdentity(resolution *awid.DidKeyResolution, expectedDIDAW string) error {
	if resolution == nil {
		return fmt.Errorf("registry returned no DID resolution")
	}
	responseDIDAW := strings.TrimSpace(resolution.DIDAW)
	if responseDIDAW == "" {
		return fmt.Errorf("registry resolution is missing did:aw")
	}
	if responseDIDAW != strings.TrimSpace(expectedDIDAW) {
		return fmt.Errorf("registry resolved did:aw %s, expected %s", responseDIDAW, strings.TrimSpace(expectedDIDAW))
	}
	return nil
}

func finalizePendingRotation(identity *awconfig.ResolvedIdentity, rotationDir string, state *pendingRotationState) error {
	newSigningKey, alreadyPromoted, err := loadRotationSigningKey(identity.SigningKeyPath, state)
	if err != nil {
		return fmt.Errorf("load replacement signing key for operation %s: %w", state.OperationID, err)
	}
	if got := awid.ComputeDIDKey(newSigningKey.Public().(ed25519.PublicKey)); strings.TrimSpace(got) != strings.TrimSpace(state.NewDID) {
		return fmt.Errorf("replacement signing key belongs to %s, not %s", got, state.NewDID)
	}
	if !alreadyPromoted {
		oldSigningKey, err := awid.LoadSigningKey(identity.SigningKeyPath)
		if err != nil {
			return err
		}
		if got := awid.ComputeDIDKey(oldSigningKey.Public().(ed25519.PublicKey)); strings.TrimSpace(got) != strings.TrimSpace(state.OldDID) {
			return fmt.Errorf("active signing key %s is neither the old nor replacement key", got)
		}
		if err := awid.ArchiveKey(filepath.Dir(identity.SigningKeyPath), state.OldDID, oldSigningKey.Public().(ed25519.PublicKey), oldSigningKey); err != nil {
			return fmt.Errorf("archive previous signing key: %w", err)
		}
		if _, err := promotePendingRotationKeypair(identity.SigningKeyPath, state.PendingKey, state.NewDID); err != nil {
			return fmt.Errorf("activate replacement signing key: %w", err)
		}
	}

	local, err := awconfig.LoadWorktreeIdentityFrom(identity.IdentityPath)
	if err != nil {
		return fmt.Errorf("reload local identity state: %w", err)
	}
	if strings.TrimSpace(local.StableID) != strings.TrimSpace(state.StableID) {
		return fmt.Errorf("local identity stable_id changed while finalizing operation %s", state.OperationID)
	}
	if localDID := strings.TrimSpace(local.DID); localDID != strings.TrimSpace(state.OldDID) && localDID != strings.TrimSpace(state.NewDID) {
		return fmt.Errorf("local identity did:key %s is neither the old nor replacement key", localDID)
	}
	local.DID = state.NewDID
	local.RegistryStatus = "registered"
	if strings.TrimSpace(state.RegistryURL) != "" {
		local.RegistryURL = state.RegistryURL
	}
	if err := awconfig.SaveWorktreeIdentityTo(identity.IdentityPath, local); err != nil {
		return fmt.Errorf("update local identity state: %w", err)
	}
	// Crash-test observation only; active key files and identity now agree.
	crashtest.Checkpoint("after-identity-state-commit", identity.IdentityPath)
	if err := cleanupPendingRotationKeypair(state.PendingKey, state.NewDID); err != nil {
		return fmt.Errorf("clean pending rotation key material: %w", err)
	}
	activeDir := filepath.Dir(identity.SigningKeyPath)
	if err := cleanupMatchingRotationPrivateTemps(activeDir, state.NewDID); err != nil {
		return fmt.Errorf("clean promoted rotation key temp material: %w", err)
	}
	if err := cleanupMatchingRotationPrivateTemps(filepath.Join(activeDir, "rotated"), state.OldDID); err != nil {
		return fmt.Errorf("clean archived rotation key temp material: %w", err)
	}
	if err := removePendingRotationStateOwned(rotationDir, state.StableID, state.OperationID); err != nil {
		return fmt.Errorf("remove finalized rotation state: %w", err)
	}
	return nil
}

func localRotationMatchesDID(identity *awconfig.ResolvedIdentity, expectedDID string) (bool, string) {
	active, err := awid.LoadSigningKey(identity.SigningKeyPath)
	if err != nil {
		return false, fmt.Sprintf("the active signing key cannot be read: %v", err)
	}
	activeDID := awid.ComputeDIDKey(active.Public().(ed25519.PublicKey))
	if strings.TrimSpace(activeDID) != strings.TrimSpace(expectedDID) {
		return false, fmt.Sprintf("the active signing key is %s, not %s", activeDID, expectedDID)
	}
	local, err := awconfig.LoadWorktreeIdentityFrom(identity.IdentityPath)
	if err != nil {
		return false, fmt.Sprintf("the local identity cannot be read: %v", err)
	}
	if strings.TrimSpace(local.DID) != strings.TrimSpace(expectedDID) {
		return false, fmt.Sprintf("the local identity records %s, not %s", local.DID, expectedDID)
	}
	return true, ""
}

func rotationRecoveryOutput(status, rotationDir string, state *pendingRotationState) idRotationRecoveryOutput {
	return idRotationRecoveryOutput{
		Status: status, OperationID: state.OperationID, StableID: state.StableID,
		OldDID: state.OldDID, NewDID: state.NewDID, RegistryURL: state.RegistryURL,
		StatePath: pendingRotationStatePath(rotationDir, state.StableID),
	}
}

func formatIDRotationRecovery(value any) string {
	out := value.(idRotationRecoveryOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Status:       %s\n", out.Status)
	if out.OperationID != "" {
		fmt.Fprintf(&b, "Operation:    %s\n", out.OperationID)
	}
	if out.StableID != "" {
		fmt.Fprintf(&b, "Stable DID:   %s\n", out.StableID)
	}
	if out.OldDID != "" {
		fmt.Fprintf(&b, "Old DID:      %s\n", out.OldDID)
	}
	if out.NewDID != "" {
		fmt.Fprintf(&b, "New DID:      %s\n", out.NewDID)
	}
	if out.StatePath != "" {
		fmt.Fprintf(&b, "State:        %s\n", out.StatePath)
	}
	if out.Detail != "" {
		fmt.Fprintf(&b, "Detail:       %s\n", out.Detail)
	}
	if out.RerunRequired {
		b.WriteString("Next:         rerun `aw id rotate-key` after reviewing this recovery result\n")
	}
	return b.String()
}
