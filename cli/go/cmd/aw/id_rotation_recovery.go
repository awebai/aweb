package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

type pendingRotationState struct {
	StableID    string `yaml:"stable_id"`
	OldDID      string `yaml:"old_did"`
	NewDID      string `yaml:"new_did"`
	RegistryURL string `yaml:"registry_url,omitempty"`
	PendingKey  string `yaml:"pending_key"`
}

func rotationStateDirForCurrentWorktree() (string, error) {
	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return filepath.Join(wd, ".aw", "rotation"), nil
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
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state pendingRotationState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, err
	}
	return &state, nil
}

func savePendingRotationState(rotationDir string, state *pendingRotationState) error {
	if state == nil {
		return fmt.Errorf("nil pending rotation state")
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(pendingRotationStatePath(rotationDir, state.StableID), data)
}

func removePendingRotationState(rotationDir, stableID string) error {
	path := pendingRotationStatePath(rotationDir, stableID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func savePendingRotationKeypair(rotationDir, did string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (string, error) {
	keyPath, pubPath := pendingRotationKeyPaths(rotationDir, did)
	if err := awid.SaveKeypairAt(keyPath, pubPath, pub, priv); err != nil {
		return "", err
	}
	return keyPath, nil
}

func cleanupPendingRotationKeypair(keyPath string) error {
	if err := os.Remove(keyPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.Remove(awid.PublicKeyPath(keyPath)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func promotePendingRotationKeypair(activeKeyPath string, pendingKeyPath string, expectedDID string) (string, error) {
	if matches, err := activeKeyMatchesDID(activeKeyPath, expectedDID); err == nil && matches {
		if err := ensurePublicKeyMatchesPrivate(activeKeyPath); err != nil {
			return "", err
		}
		return activeKeyPath, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if err := os.Rename(pendingKeyPath, activeKeyPath); err != nil {
		return "", err
	}
	if err := os.Rename(awid.PublicKeyPath(pendingKeyPath), awid.PublicKeyPath(activeKeyPath)); err != nil {
		if recoverErr := ensurePublicKeyMatchesPrivate(activeKeyPath); recoverErr == nil {
			return activeKeyPath, nil
		}
		return "", err
	}
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
	if !os.IsNotExist(err) {
		return nil, false, fmt.Errorf("load pending rotation key: %w", err)
	}
	activePriv, activeErr := awid.LoadSigningKey(activeKeyPath)
	if activeErr != nil {
		return nil, false, fmt.Errorf("load active signing key: %w", activeErr)
	}
	if strings.TrimSpace(awid.ComputeDIDKey(activePriv.Public().(ed25519.PublicKey))) != strings.TrimSpace(pending.NewDID) {
		return nil, false, fmt.Errorf("load pending rotation key: %w", err)
	}
	return activePriv, true, nil
}
