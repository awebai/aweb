package main

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/pathpreflight"
)

// withHookSettingsLock implements docs/runtime-hook-configuration.md:22-26.
// All aw settings editors lock the same stable sidecar before reading the
// snapshot they will replace; renaming the settings file does not drop the lock.
func withHookSettingsLock(path string, change func() error) (err error) {
	lockPath := hookSettingsLockPath(path)
	if err := pathpreflight.PreflightFile(lockPath, "runtime hook settings lock", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return fmt.Errorf("cannot lock %s: %w. Repair the lock path and retry the command", path, err)
	}
	lock, err := awconfig.LockExclusive(lockPath)
	if err != nil {
		return fmt.Errorf("cannot lock %s: %w. Check the directory permissions and retry the command", path, err)
	}
	defer func() {
		if closeErr := lock.Close(); closeErr != nil {
			err = errors.Join(err, fmt.Errorf("releasing the settings lock for %s: %w. Retry the command", path, closeErr))
		}
	}()
	return change()
}

func hookSettingsLockPath(path string) string {
	return filepath.Join(filepath.Dir(path), "."+filepath.Base(path)+".aw-lock")
}
