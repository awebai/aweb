package main

import (
	"fmt"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/pathpreflight"
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func apiKeyPartialInitPath(workingDir string, identityHomes ...string) string {
	root := filepath.Join(filepath.Clean(workingDir), ".aw")
	if len(identityHomes) > 0 && strings.TrimSpace(identityHomes[0]) != "" {
		root = filepath.Clean(identityHomes[0])
	}
	return filepath.Join(root, "partial-init.yaml")
}

func preflightAPIKeyPartialInit(path string) error {
	return pathpreflight.PreflightFile(path, "API-key recovery state", pathpreflight.AllowTempAmbientSymlinkPrefix())
}

func loadAPIKeyPartialInit(path string) (*apiKeyPartialInitState, error) {
	if err := preflightAPIKeyPartialInit(path); err != nil {
		return nil, err
	}
	data, err := (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(path)}, Name: filepath.Base(path)}).Read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state apiKeyPartialInitState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read partial API-key init state %s: %w", path, err)
	}
	if state.Version != apiKeyPartialInitVersion {
		return nil, usageError(
			"partial API-key init state at %s has unsupported version %d; retry with a matching aw version or remove the file explicitly",
			path,
			state.Version,
		)
	}
	return &state, nil
}

func saveAPIKeyPartialInit(workingDir string, state *apiKeyPartialInitState, identityHomes ...string) error {
	if state == nil {
		return fmt.Errorf("nil partial API-key init state")
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	path := apiKeyPartialInitPath(workingDir, identityHomes...)
	if err := preflightAPIKeyPartialInit(path); err != nil {
		return err
	}
	return (awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: filepath.Dir(path)}, Name: filepath.Base(path)}).Write(data)
}

// Rejected material is evidence, not an implicit choice of identity. Even an
// otherwise resumable partial cannot bypass this reconciliation requirement.
func refuseRejectedAPIKeyPartialInit(path string) error {
	if err := preflightAPIKeyPartialInit(path); err != nil {
		return err
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), filepath.Base(path)+".") && strings.HasSuffix(entry.Name(), ".rejected") {
			return usageError("partial_init_reconciliation_required: rejected signing material at %s; use a different directory for a new identity or obtain operator reconciliation; rejected material is never restored automatically", filepath.Join(filepath.Dir(path), entry.Name()))
		}
	}
	return nil
}

func quarantineAPIKeyPartialInit(workingDir string, identityHomes ...string) (string, error) {
	path := apiKeyPartialInitPath(workingDir, identityHomes...)
	if err := preflightAPIKeyPartialInit(path); err != nil {
		return "", err
	}
	// Reserve a unique private destination so repeated timestamps cannot replace
	// an earlier key. Rename only over the empty file created by this call.
	file, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+"."+time.Now().UTC().Format("20060102T150405.000000000Z")+".*.rejected")
	if err != nil {
		return "", err
	}
	destination := file.Name()
	if err := file.Close(); err != nil {
		_ = os.Remove(destination)
		return "", err
	}
	if err := os.Chmod(path, 0600); err != nil {
		_ = os.Remove(destination)
		return "", err
	}
	if err := os.Rename(path, destination); err != nil {
		_ = os.Remove(destination) // Only our empty reservation; original is intact.
		return "", err
	}
	return destination, nil
}

func removeAPIKeyPartialInit(workingDir string, identityHomes ...string) error {
	path := apiKeyPartialInitPath(workingDir, identityHomes...)
	if err := preflightAPIKeyPartialInit(path); err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
