package awid

import (
	"os"
	"path/filepath"
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

// atomicWriteFileMode writes data to path using temp-file-and-rename.
// The temp file is chmod'd to mode before any data is written.
func atomicWriteFileMode(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}
