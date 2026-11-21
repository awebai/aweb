package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
)

// snapshotAwTree records the selected home's paths before installation. It
// preserves the recovery material that docs/hosted-global-bootstrap.md requires
// across local completion failures.
func snapshotAwTree(home awconfig.IdentityHome) (map[string]bool, error) {
	if _, err := (awconfig.RecoveryFile{Home: home, Name: "partial-init.yaml"}).Path(); err != nil {
		return nil, err
	}
	if _, err := os.Stat(home.Root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	existing := map[string]bool{}
	err := filepath.WalkDir(home.Root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		existing[path] = true
		return nil
	})
	return existing, err
}

// rollbackAwTree removes only this installation's additions to its selected
// home. Failure to inspect or remove a path is reported with the original
// installation error; it never becomes a successful rollback.
func rollbackAwTree(home awconfig.IdentityHome, snapshot map[string]bool) error {
	if _, err := (awconfig.RecoveryFile{Home: home, Name: "partial-init.yaml"}).Path(); err != nil {
		return err
	}
	if _, err := os.Stat(home.Root); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	var created []string
	if err := filepath.WalkDir(home.Root, func(path string, _ os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !snapshot[path] {
			created = append(created, path)
		}
		return nil
	}); err != nil {
		return fmt.Errorf("inspect local installation for rollback: %w", err)
	}
	var result error
	for i := len(created) - 1; i >= 0; i-- {
		if err := os.Remove(created[i]); err != nil && !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, fmt.Errorf("rollback could not remove %s: %w", created[i], err))
		}
	}
	return result
}
