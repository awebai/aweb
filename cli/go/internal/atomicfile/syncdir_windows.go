//go:build windows

package atomicfile

// SyncDir does nothing: Windows cannot flush a directory handle.
func SyncDir(dir string) error {
	return nil
}
