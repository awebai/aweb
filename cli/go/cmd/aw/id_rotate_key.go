package main

import (
	"context"
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

var idRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate the current global identity signing key at the registry",
	Args:  cobra.NoArgs,
	RunE:  runIDRotateKey,
}

func init() {
	identityCmd.AddCommand(idRotateKeyCmd)
}

func runIDRotateKey(cmd *cobra.Command, args []string) error {
	// A crash may have promoted the private key before identity.yaml. Resolve
	// only the stable transaction scope until pending recovery has had a chance
	// to reconcile that intentionally split state under the lock.
	lockIdentity, rotationDir, lockPath, err := prepareRotationIdentity(false)
	if err != nil {
		return err
	}
	transactionLock, err := awconfig.LockExclusive(lockPath)
	if err != nil {
		return fmt.Errorf("lock identity key rotation: %w", err)
	}
	defer func() { _ = transactionLock.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// A preceding lock holder may have completed a rotation while this process
	// waited. Reload both the identity and its signing key inside the transaction
	// so a waiter cannot create recovery state from the retired key.
	identity, err := resolveRotationIdentity()
	if err != nil {
		return err
	}
	currentRotationDir, err := rotationStateDirForIdentity(identity)
	if err != nil {
		return err
	}
	if strings.TrimSpace(identity.StableID) != strings.TrimSpace(lockIdentity.StableID) || filepath.Clean(currentRotationDir) != filepath.Clean(rotationDir) {
		return fmt.Errorf("active identity changed while waiting for the rotation lock; retry the rotation")
	}
	if pending, err := loadPendingRotationState(rotationDir, identity.StableID); err != nil {
		return err
	} else if pending != nil {
		out, recoverErr := recoverPendingRotation(ctx, identity, rotationDir)
		if recoverErr != nil {
			return recoverErr
		}
		out.RerunRequired = true
		printOutput(out, formatIDRotationRecovery)
		return nil
	}
	if err := validateResolvedIdentity(identity); err != nil {
		return err
	}
	signingKey, err := resolveIdentitySigningKey(identity)
	if err != nil {
		return err
	}
	if err := requirePersistentSelfCustodialIdentity(identity, signingKey); err != nil {
		return err
	}
	registry, err := resolveIdentityRegistryClient(identity)
	if err != nil {
		return err
	}
	registryURL, err := currentIdentityRegistryURL(ctx, identity, registry)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(rotationDir, "pending"), 0o700); err != nil {
		return err
	}

	operationID, err := awid.GenerateUUID4()
	if err != nil {
		return err
	}
	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	// Crash-test observation only; inert without the inherited pipe capability.
	crashtest.Checkpoint("after-key-generation")
	oldDID := strings.TrimSpace(identity.DID)
	newDID := awid.ComputeDIDKey(newPub)
	if oldDID == newDID {
		return fmt.Errorf("generated replacement did:key unexpectedly matched the current did:key")
	}

	pendingKeyPath, _ := pendingRotationKeyPaths(rotationDir, operationID)
	pendingState := &pendingRotationState{
		OperationID: operationID,
		StableID:    identity.StableID,
		OldDID:      oldDID,
		NewDID:      newDID,
		RegistryURL: registryURL,
		PendingKey:  pendingKeyPath,
	}
	// Persist transaction ownership before key material. A crash in between is
	// recoverable as definitely-not-submitted; the reverse order leaves an
	// undiscoverable private key with no operation record.
	if err := savePendingRotationState(rotationDir, pendingState); err != nil {
		return err
	}
	// Crash-test observation only; the state rename is now visible to recovery.
	crashtest.Checkpoint("after-pending-state-commit")
	if _, err := savePendingRotationKeypair(rotationDir, operationID, newPub, newPriv); err != nil {
		_ = cleanupPendingRotationKeypair(pendingKeyPath, newDID)
		_ = removePendingRotationStateOwned(rotationDir, identity.StableID, operationID)
		return err
	}

	mapping, err := registry.RotateDIDKey(ctx, registryURL, identity.StableID, signingKey, newPriv)
	if err != nil {
		var outcomeErr *awid.DIDRotationError
		if errors.As(err, &outcomeErr) && outcomeErr.Outcome == awid.DIDRotationDefinitelyNotApplied {
			if cleanupErr := cleanupPendingRotationKeypair(pendingKeyPath, newDID); cleanupErr != nil {
				return fmt.Errorf("%w; failed to discard the unused replacement signing key: %v", err, cleanupErr)
			}
			if cleanupErr := removePendingRotationStateOwned(rotationDir, identity.StableID, operationID); cleanupErr != nil {
				return fmt.Errorf("%w; failed to remove pending rotation state: %v", err, cleanupErr)
			}
			return err
		}
		return fmt.Errorf(
			"%w; replacement signing key retained at %s with pending recovery state at %s; verify the authoritative registry current key before retrying or recovering",
			err,
			pendingKeyPath,
			pendingRotationStatePath(rotationDir, identity.StableID),
		)
	}
	if mapping == nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "registry rotation returned no mapping", nil)
	}
	if strings.TrimSpace(mapping.DIDAW) != strings.TrimSpace(identity.StableID) {
		return rotationFinalizeError(
			rotationDir,
			identity.StableID,
			fmt.Sprintf("registry rotation returned did:aw %q, expected %q", mapping.DIDAW, identity.StableID),
			nil,
		)
	}
	if strings.TrimSpace(mapping.CurrentDIDKey) != newDID {
		return rotationFinalizeError(
			rotationDir,
			identity.StableID,
			fmt.Sprintf("registry rotation returned current did:key %q, expected %q", mapping.CurrentDIDKey, newDID),
			nil,
		)
	}
	if err := finalizePendingRotation(identity, rotationDir, pendingState); err != nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "failed to finalize the applied rotation", err)
	}

	printOutput(idRotateOutput{
		Status:      "rotated",
		RegistryURL: registryURL,
		OldDID:      oldDID,
		NewDID:      newDID,
	}, formatIDRotate)
	return nil
}

func rotationFinalizeError(rotationDir, stableID, message string, err error) error {
	statePath := pendingRotationStatePath(rotationDir, stableID)
	if err == nil {
		return fmt.Errorf("registry rotation succeeded but local finalize failed: %s (pending recovery state at %s)", message, statePath)
	}
	return fmt.Errorf("registry rotation succeeded but local finalize failed: %s: %w (pending recovery state at %s)", message, err, statePath)
}
