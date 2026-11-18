//go:build !windows

package wake

import (
	"fmt"
	"os"
	"syscall"
)

// Existing read-only access is harmless here; write access by another user
// would let them replace the executable cache or wake registrations.
func checkWakeDirectory(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || stat.Uid != uint32(os.Geteuid()) || info.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("unsafe wake directory %s. Choose a private --state-dir owned by your user and retry aw wake.", path)
	}
	return nil
}
