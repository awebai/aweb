package wake

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
)

// removeStaleRunnerSnapshots implements docs/wake-runner-integrity.md:17-21.
// The held OS lock protects an older snapshot still used by another broker.
func removeStaleRunnerSnapshots(parent string, cutoff time.Time) error {
	entries, err := os.ReadDir(parent)
	if err != nil {
		return err
	}
	var failures []error
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), "aw-wake-runner-") || !entry.IsDir() {
			continue
		}
		path := filepath.Join(parent, entry.Name())
		info, err := entry.Info()
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !info.ModTime().Before(cutoff) {
			continue
		}
		owned, err := runnerSnapshotOwnedByCurrentUser(info)
		if err != nil {
			failures = append(failures, err)
			continue
		}
		if !owned {
			continue
		}
		if err := removeUnheldRunnerSnapshot(path); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

func removeUnheldRunnerSnapshot(path string) error {
	held, err := awconfig.TryLockExistingExclusive(filepath.Join(path, "in-use.lock"))
	if errors.Is(err, awconfig.ErrLockUnavailable) {
		return nil
	}
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("inspect runner snapshot %s: %w", path, err)
	}
	removeErr := os.RemoveAll(path)
	var closeErr error
	if held != nil {
		closeErr = held.Close()
	}
	if err := errors.Join(removeErr, closeErr); err != nil {
		return fmt.Errorf("remove stale runner snapshot %s: %w", path, err)
	}
	return nil
}
