package wake

import (
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/atomicfile"
)

type runnerSnapshot struct {
	Path      string
	directory string
	held      io.Closer
}

func (snapshot *runnerSnapshot) close() error {
	if snapshot.directory == "" {
		return nil
	}
	var closeErr error
	if snapshot.held != nil {
		closeErr = snapshot.held.Close()
		snapshot.held = nil
	}
	removeErr := os.RemoveAll(snapshot.directory)
	if err := errors.Join(closeErr, removeErr); err != nil {
		return fmt.Errorf("remove private runner snapshot %s: %w. Check temporary-directory permissions before retrying aw wake.", snapshot.directory, err)
	}
	snapshot.directory = ""
	return nil
}

// invalidateLegacyRunnerStamp implements docs/wake-runner-integrity.md:3-6.
// Only a downgraded aw reads this cache. No runner bytes are created or rewritten.
func (runner *ChannelCoreRunner) invalidateLegacyRunnerStamp() error {
	stamp := filepath.Join(runner.store.Dir(), "channel-core", "runner.sha256")
	if err := os.Remove(stamp); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("remove legacy runner stamp %s: %w. Restore write access to %s and retry aw wake.", stamp, err, filepath.Dir(stamp))
	}
	return nil
}

// executableSnapshot implements docs/wake-runner-integrity.md:13-21.
// Shared cache permissions cannot authorize code: Node opens this private copy.
func (runner *ChannelCoreRunner) executableSnapshot() (snapshot runnerSnapshot, resultErr error) {
	if err := runner.invalidateLegacyRunnerStamp(); err != nil {
		log.Printf("Warning: %v Runner execution uses a private snapshot.", err)
	}
	root := os.TempDir()
	if err := checkRunnerSnapshotParent(root); err != nil {
		return snapshot, err
	}
	runner.snapshotCleanup.Do(func() {
		if err := removeStaleRunnerSnapshots(root, time.Now().Add(-24*time.Hour)); err != nil {
			log.Printf("Warning: stale runner snapshot cleanup: %v. Review temporary-directory access and retry aw wake.", err)
		}
	})
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
	held, err := awconfig.TryLockExclusive(filepath.Join(directory, "in-use.lock"))
	if err != nil {
		return snapshot, fmt.Errorf("lock private runner snapshot %s: %w. Check temporary-directory access and retry aw wake.", directory, err)
	}
	snapshot.held = held
	content, err := channelCoreRunnerFS.ReadFile("channel_core_runner_bundle.mjs")
	if err != nil {
		return snapshot, err
	}
	if err := atomicfile.WriteExclusive(snapshot.Path, content, 0o600); err != nil {
		return snapshot, fmt.Errorf("stage private runner snapshot %s: %w. Check system temporary-directory access and retry aw wake.", snapshot.Path, err)
	}
	return snapshot, nil
}
