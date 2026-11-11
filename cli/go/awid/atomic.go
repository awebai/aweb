package awid

import (
	"os"

	"github.com/awebai/aw/internal/atomicfile"
	"github.com/awebai/aw/internal/crashtest"
)

// atomicWriteFile writes data to path using temp-file-and-rename
// with 0600 permissions (suitable for secrets).
func atomicWriteFile(path string, data []byte) error {
	return atomicWriteFileMode(path, data, 0o600)
}

// AtomicWriteFile exposes the atomic secret-file writer for higher-level CLI
// state that must survive partial failures safely.
func AtomicWriteFile(path string, data []byte) error {
	return atomicWriteFile(path, data)
}

// atomicWriteFileMode writes data to path using temp-file-and-rename,
// creating a missing directory with 0700 permissions.
// The temp file is chmod'd to mode before any data is written.
func atomicWriteFileMode(path string, data []byte, mode os.FileMode) error {
	return atomicfile.Options{Mode: mode, ParentMode: 0o700}.Write(path, data)
}

func atomicWritePrivateKeyFile(path string, data []byte) error {
	return atomicfile.Options{Mode: 0o600, ParentMode: 0o700, BeforeCommit: func() {
		// Crash-test observation only; the synced secret temp is not yet renamed.
		crashtest.Checkpoint("after-private-key-temp-sync", path)
	}}.Write(path, data)
}
