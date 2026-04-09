package main

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var idRotateKeyCmd = &cobra.Command{
	Use:   "rotate-key",
	Short: "Rotate the current persistent identity signing key at the registry",
	RunE:  runIDRotateKey,
}

func init() {
	identityCmd.AddCommand(idRotateKeyCmd)
}

func runIDRotateKey(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	identity, err := resolveIdentity()
	if err != nil {
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

	rotationDir, err := rotationStateDirForCurrentWorktree()
	if err != nil {
		return err
	}
	if pending, err := loadPendingRotationState(rotationDir, identity.StableID); err != nil {
		return err
	} else if pending != nil {
		return usageError(
			"pending rotation exists for %s at %s; resolve it before starting another key rotation",
			identity.StableID,
			pendingRotationStatePath(rotationDir, identity.StableID),
		)
	}
	if err := os.MkdirAll(filepath.Join(rotationDir, "pending"), 0o700); err != nil {
		return err
	}

	newPub, newPriv, err := awid.GenerateKeypair()
	if err != nil {
		return err
	}
	oldDID := strings.TrimSpace(identity.DID)
	newDID := awid.ComputeDIDKey(newPub)
	if oldDID == newDID {
		return fmt.Errorf("generated replacement did:key unexpectedly matched the current did:key")
	}

	pendingKeyPath, err := savePendingRotationKeypair(rotationDir, newDID, newPub, newPriv)
	if err != nil {
		return err
	}
	pendingState := &pendingRotationState{
		StableID:    identity.StableID,
		OldDID:      oldDID,
		NewDID:      newDID,
		RegistryURL: registryURL,
		PendingKey:  pendingKeyPath,
	}
	if err := savePendingRotationState(rotationDir, pendingState); err != nil {
		_ = cleanupPendingRotationKeypair(pendingKeyPath)
		return err
	}

	mapping, err := registry.RotateDIDKey(ctx, registryURL, identity.StableID, signingKey, newPriv)
	if err != nil {
		_ = removePendingRotationState(rotationDir, identity.StableID)
		_ = cleanupPendingRotationKeypair(pendingKeyPath)
		return err
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

	if _, err := promotePendingRotationKeypair(identity.SigningKeyPath, pendingKeyPath, newDID); err != nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "failed to activate the new local signing key", err)
	}

	state, err := awconfig.LoadWorktreeIdentityFrom(identity.IdentityPath)
	if err != nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "failed to reload local identity state", err)
	}
	state.DID = newDID
	state.RegistryStatus = "registered"
	if strings.TrimSpace(registryURL) != "" {
		state.RegistryURL = registryURL
	}
	if err := awconfig.SaveWorktreeIdentityTo(identity.IdentityPath, state); err != nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "failed to update local identity state", err)
	}

	if err := awid.ArchiveKey(filepath.Dir(identity.SigningKeyPath), oldDID, signingKey.Public().(ed25519.PublicKey), signingKey); err != nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "failed to archive the previous signing key", err)
	}

	if err := removePendingRotationState(rotationDir, identity.StableID); err != nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "failed to remove pending rotation state", err)
	}
	if err := cleanupPendingRotationKeypair(pendingKeyPath); err != nil {
		return rotationFinalizeError(rotationDir, identity.StableID, "failed to clean pending rotation key material", err)
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
