package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/crashtest"
	"github.com/awebai/aw/internal/pathpreflight"
	"gopkg.in/yaml.v3"
)

type pendingRotationState struct {
	OperationID string `yaml:"operation_id,omitempty"`
	StableID    string `yaml:"stable_id"`
	OldDID      string `yaml:"old_did"`
	NewDID      string `yaml:"new_did"`
	RegistryURL string `yaml:"registry_url,omitempty"`
	PendingKey  string `yaml:"pending_key"`
	legacy      bool
}

func rotationStateDirForIdentity(identity *awconfig.ResolvedIdentity) (string, error) {
	if identity == nil || strings.TrimSpace(identity.IdentityHome) == "" {
		return "", fmt.Errorf("identity home is required for rotation recovery")
	}
	rotationDir := filepath.Join(identity.IdentityHome, "rotation")
	if err := pathpreflight.PreflightDir(rotationDir, "identity rotation directory", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return "", err
	}
	return rotationDir, nil
}

func pendingRotationStatePath(rotationDir, stableID string) string {
	return filepath.Join(rotationDir, "pending", pendingFileBase(stableID)+".yaml")
}

func pendingRotationKeyPaths(rotationDir, did string) (string, string) {
	base := filepath.Join(rotationDir, "pending", pendingFileBase(did))
	return base + ".signing.key", base + ".signing.pub"
}

func pendingFileBase(value string) string {
	replacer := strings.NewReplacer(":", "-", "/", "-", "\\", "-")
	return replacer.Replace(strings.TrimSpace(value))
}

func loadPendingRotationState(rotationDir, stableID string) (*pendingRotationState, error) {
	path := pendingRotationStatePath(rotationDir, stableID)
	if err := preflightRotationFile(path); err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state pendingRotationState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("decode pending rotation state %s: %w", path, err)
	}
	if strings.TrimSpace(state.OperationID) == "" {
		state.legacy = true
		digest := sha256.Sum256([]byte(strings.Join([]string{state.StableID, state.OldDID, state.NewDID, state.PendingKey}, "\x00")))
		state.OperationID = fmt.Sprintf("legacy-%x", digest[:12])
	}
	return &state, nil
}

func savePendingRotationState(rotationDir string, state *pendingRotationState) error {
	if state == nil {
		return fmt.Errorf("nil pending rotation state")
	}
	if strings.TrimSpace(state.OperationID) == "" {
		return fmt.Errorf("pending rotation operation_id is required")
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	path := pendingRotationStatePath(rotationDir, state.StableID)
	if err := preflightRotationFile(path); err != nil {
		return err
	}
	if _, err := os.Lstat(path); err == nil {
		return fmt.Errorf("pending rotation state already exists at %s", path)
	} else if !os.IsNotExist(err) {
		return err
	}
	return awid.AtomicWriteFile(path, data)
}

func removePendingRotationStateOwned(rotationDir, stableID, operationID string) error {
	state, err := loadPendingRotationState(rotationDir, stableID)
	if err != nil {
		return err
	}
	if state == nil {
		return nil
	}
	if strings.TrimSpace(state.OperationID) != strings.TrimSpace(operationID) {
		return fmt.Errorf("pending rotation state is owned by operation %s, not %s", state.OperationID, operationID)
	}
	path := pendingRotationStatePath(rotationDir, stableID)
	if err := preflightRotationFile(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	// Crash-test observation only; owned state removal is the transaction end.
	crashtest.Checkpoint("after-pending-state-removal", path)
	return nil
}

func savePendingRotationKeypair(rotationDir, did string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (string, error) {
	keyPath, pubPath := pendingRotationKeyPaths(rotationDir, did)
	if err := preflightRotationFile(keyPath); err != nil {
		return "", err
	}
	if err := preflightRotationFile(pubPath); err != nil {
		return "", err
	}
	if err := awid.SaveKeypairAt(keyPath, pubPath, pub, priv); err != nil {
		return "", err
	}
	return keyPath, nil
}

func preflightRotationFile(path string) error {
	return pathpreflight.PreflightFile(path, "rotation recovery file", pathpreflight.AllowTempAmbientSymlinkPrefix())
}

func cleanupPendingRotationKeypair(keyPath, expectedDID string) error {
	for index, path := range []string{keyPath, awid.PublicKeyPath(keyPath)} {
		if err := preflightRotationFile(path); err != nil {
			return err
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		// Crash-test observation only; each removal exposes a distinct recovery state.
		point := "after-pending-private-removal"
		if index == 1 {
			point = "after-pending-public-removal"
		}
		crashtest.Checkpoint(point, path)
	}
	return cleanupMatchingRotationPrivateTemps(filepath.Dir(keyPath), expectedDID)
}

func cleanupMatchingRotationPrivateTemps(dir, expectedDID string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.HasPrefix(entry.Name(), ".tmp.") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		if err := preflightRotationFile(path); err != nil {
			return err
		}
		key, err := awid.LoadSigningKey(path)
		if err != nil {
			continue
		}
		// Atomic temp names do not encode their destination. Bind residue to this
		// operation by key identity; preserve every unknown or foreign temp.
		did := awid.ComputeDIDKey(key.Public().(ed25519.PublicKey))
		if strings.TrimSpace(did) != strings.TrimSpace(expectedDID) {
			continue
		}
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func validatePendingRotationState(rotationDir, stableID string, state *pendingRotationState) error {
	if state == nil {
		return fmt.Errorf("missing pending rotation state")
	}
	if strings.TrimSpace(state.OperationID) == "" {
		return fmt.Errorf("pending rotation operation_id is required")
	}
	if strings.TrimSpace(state.StableID) != strings.TrimSpace(stableID) {
		return fmt.Errorf("pending rotation stable_id %q does not match active identity %q", state.StableID, stableID)
	}
	if strings.TrimSpace(state.OldDID) == "" || strings.TrimSpace(state.NewDID) == "" || strings.TrimSpace(state.OldDID) == strings.TrimSpace(state.NewDID) {
		return fmt.Errorf("pending rotation has invalid old_did/new_did")
	}
	expectedKey, _ := pendingRotationKeyPaths(rotationDir, state.OperationID)
	if state.legacy {
		expectedKey, _ = pendingRotationKeyPaths(rotationDir, state.NewDID)
	}
	owned, err := sameRotationPath(state.PendingKey, expectedKey)
	if err != nil {
		return err
	}
	if !owned {
		return fmt.Errorf("pending rotation key path %q is not owned by operation %s", state.PendingKey, state.OperationID)
	}
	if err := preflightRotationFile(state.PendingKey); err != nil {
		return err
	}
	if err := preflightRotationFile(awid.PublicKeyPath(state.PendingKey)); err != nil {
		return err
	}
	priv, err := awid.LoadSigningKey(state.PendingKey)
	if errors.Is(err, os.ErrNotExist) {
		return nil // Promotion may have moved the private key before state cleanup.
	}
	if err != nil {
		return fmt.Errorf("load pending rotation key: %w", err)
	}
	derivedPublic := priv.Public().(ed25519.PublicKey)
	if got := awid.ComputeDIDKey(derivedPublic); strings.TrimSpace(got) != strings.TrimSpace(state.NewDID) {
		return fmt.Errorf("pending rotation key belongs to %s, not %s", got, state.NewDID)
	}
	storedPublic, err := awid.LoadPublicKey(awid.PublicKeyPath(state.PendingKey))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("load pending rotation public key: %w", err)
	}
	if err == nil && !derivedPublic.Equal(storedPublic) {
		return fmt.Errorf("pending rotation public key does not match its private key")
	}
	return nil
}

func sameRotationPath(first, second string) (bool, error) {
	resolve := func(path string) (string, error) {
		parent, err := filepath.EvalSymlinks(filepath.Dir(path))
		if err != nil {
			return "", err
		}
		absolute, err := filepath.Abs(filepath.Join(parent, filepath.Base(path)))
		if err != nil {
			return "", err
		}
		return filepath.Clean(absolute), nil
	}
	firstResolved, err := resolve(first)
	if err != nil {
		return false, err
	}
	secondResolved, err := resolve(second)
	if err != nil {
		return false, err
	}
	return firstResolved == secondResolved, nil
}

func promotePendingRotationKeypair(activeKeyPath string, pendingKeyPath string, expectedDID string) (string, error) {
	if matches, err := activeKeyMatchesDID(activeKeyPath, expectedDID); err == nil && matches {
		if err := ensurePublicKeyMatchesPrivate(activeKeyPath); err != nil {
			return "", err
		}
		return activeKeyPath, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := os.Rename(pendingKeyPath, activeKeyPath); err != nil {
		return "", err
	}
	// Crash-test observation only; the active key pair is intentionally split here.
	crashtest.Checkpoint("after-active-private-rename", activeKeyPath)
	if err := os.Rename(awid.PublicKeyPath(pendingKeyPath), awid.PublicKeyPath(activeKeyPath)); err != nil {
		if recoverErr := ensurePublicKeyMatchesPrivate(activeKeyPath); recoverErr == nil {
			return activeKeyPath, nil
		}
		return "", err
	}
	crashtest.Checkpoint("after-active-public-rename", awid.PublicKeyPath(activeKeyPath))
	return activeKeyPath, nil
}

func activeKeyMatchesDID(signingKeyPath, expectedDID string) (bool, error) {
	priv, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))) == strings.TrimSpace(expectedDID), nil
}

func ensurePublicKeyMatchesPrivate(signingKeyPath string) error {
	priv, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return err
	}
	pub := priv.Public().(ed25519.PublicKey)
	return awid.SaveKeypairAt(signingKeyPath, awid.PublicKeyPath(signingKeyPath), pub, priv)
}

func loadRotationSigningKey(activeKeyPath string, pending *pendingRotationState) (ed25519.PrivateKey, bool, error) {
	if pending == nil {
		return nil, false, fmt.Errorf("missing pending rotation state")
	}
	newPriv, err := awid.LoadSigningKey(pending.PendingKey)
	if err == nil {
		return newPriv, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("load pending rotation key: %w", err)
	}
	activePriv, activeErr := awid.LoadSigningKey(activeKeyPath)
	if activeErr != nil {
		return nil, false, fmt.Errorf("load active signing key: %w", activeErr)
	}
	if strings.TrimSpace(awid.ComputeDIDKey(activePriv.Public().(ed25519.PublicKey))) != strings.TrimSpace(pending.NewDID) {
		return nil, false, fmt.Errorf("load pending rotation key: %w", err)
	}
	// A crash may have moved the pending private key onto the active path but
	// not its public sibling. Repair the pair before cleanup removes the only
	// remaining copy of the replacement public key.
	if err := ensurePublicKeyMatchesPrivate(activeKeyPath); err != nil {
		return nil, false, fmt.Errorf("repair promoted signing key pair: %w", err)
	}
	return activePriv, true, nil
}
