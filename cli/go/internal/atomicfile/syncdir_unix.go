//go:build !windows

package atomicfile

import (
	"errors"
	"os"
	"syscall"
)

// SyncDir flushes the directory's entries to stable storage, which is what
// makes a file created in it, or renamed into it, survive a host crash. On a
// filesystem that cannot flush a directory it does nothing.
func SyncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := handle.Sync(); err != nil && !syncUnsupported(err) {
		_ = handle.Close()
		return err
	}
	return handle.Close()
}

// syncUnsupported reports whether err is a filesystem's answer that it does
// not offer a sync of a directory (some network and userspace filesystems).
func syncUnsupported(err error) bool {
	return errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP)
}
