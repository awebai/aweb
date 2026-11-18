package wake

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/internal/atomicfile"
)

type runnerSnapshot struct {
	Path      string
	directory string
}

func (snapshot runnerSnapshot) close() error {
	if snapshot.directory == "" {
		return nil
	}
	if err := os.RemoveAll(snapshot.directory); err != nil {
		return fmt.Errorf("remove private runner snapshot %s: %w. Check temporary-directory permissions before retrying aw wake.", snapshot.directory, err)
	}
	return nil
}

// executableSnapshot implements docs/wake-runner-integrity.md:8-18.
// Shared cache permissions cannot authorize code: Node opens this private copy.
func (runner *ChannelCoreRunner) executableSnapshot() (snapshot runnerSnapshot, resultErr error) {
	if _, err := runner.bundlePath(); err != nil {
		return snapshot, err
	}
	root := runnerSnapshotRoot()
	if err := checkRunnerSnapshotParent(root); err != nil {
		return snapshot, err
	}
	directory, err := os.MkdirTemp(root, "aw-wake-runner-")
	if err != nil {
		return snapshot, fmt.Errorf("create private runner snapshot in %s: %w. Check system temporary-directory access and retry aw wake.", root, err)
	}
	snapshot = runnerSnapshot{directory: directory, Path: filepath.Join(directory, "runner.mjs")}
	defer func() {
		if resultErr != nil {
			resultErr = errors.Join(resultErr, snapshot.close())
		}
	}()
	if err := checkRunnerSnapshotDirectory(directory); err != nil {
		return snapshot, err
	}
	content, err := channelCoreRunnerFS.ReadFile("channel_core_runner_bundle.mjs")
	if err != nil {
		return snapshot, err
	}
	if err := atomicfile.WriteExclusive(snapshot.Path, content, 0o600); err != nil {
		return snapshot, fmt.Errorf("stage private runner snapshot %s: %w. Check system temporary-directory access and retry aw wake.", snapshot.Path, err)
	}
	return snapshot, nil
}
