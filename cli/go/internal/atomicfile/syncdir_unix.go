//go:build !windows

package atomicfile

import "os"

// SyncDir flushes the directory's entries to stable storage, which is what
// makes a file created in it, or renamed into it, survive a host crash.
func SyncDir(dir string) error {
	handle, err := os.Open(dir)
	if err != nil {
		return err
	}
	if err := handle.Sync(); err != nil {
		_ = handle.Close()
		return err
	}
	return handle.Close()
}
