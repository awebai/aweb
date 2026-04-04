package main

import (
	"crypto/ed25519"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

func keysDirForCurrentConfig() (string, error) {
	configPath, err := defaultGlobalPath()
	if err != nil {
		return "", err
	}
	return awconfig.KeysDir(configPath), nil
}

func pendingRotationStatePath(keysDir, stableID string) string {
	return filepath.Join(keysDir, "pending", pendingFileBase(stableID)+".yaml")
}

func pendingRotationKeyPaths(keysDir, did string) (string, string) {
	base := filepath.Join(keysDir, "pending", pendingFileBase(did))
	return base + ".signing.key", base + ".signing.pub"
}

func pendingFileBase(value string) string {
	replacer := strings.NewReplacer(":", "-", "/", "-", "\\", "-")
	return replacer.Replace(strings.TrimSpace(value))
}

func loadPendingRotationState(keysDir, stableID string) (*pendingRotationState, error) {
	path := pendingRotationStatePath(keysDir, stableID)
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

func savePendingRotationState(keysDir string, state *pendingRotationState) error {
	if state == nil {
		return fmt.Errorf("nil pending rotation state")
	}
	if strings.TrimSpace(state.CreatedAt) == "" {
		state.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(pendingRotationStatePath(keysDir, state.StableID), data)
}

func removePendingRotationState(keysDir, stableID string) error {
	path := pendingRotationStatePath(keysDir, stableID)
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func savePendingRotationKeypair(keysDir, did string, pub ed25519.PublicKey, priv ed25519.PrivateKey) (string, error) {
	keyPath, pubPath := pendingRotationKeyPaths(keysDir, did)
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

func promotePendingRotationKeypair(keysDir, address string, pendingKeyPath string) (string, error) {
	activeKeyPath := awid.SigningKeyPath(keysDir, address)
	activePubPath := awid.PublicKeyPath(activeKeyPath)
	if err := os.Rename(pendingKeyPath, activeKeyPath); err != nil {
		return "", err
	}
	if err := os.Rename(awid.PublicKeyPath(pendingKeyPath), activePubPath); err != nil {
		return "", err
	}
	return activeKeyPath, nil
}
