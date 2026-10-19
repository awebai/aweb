//go:build !windows

package awconfig

import (
	"fmt"
	"os"
	"syscall"
)

func checkIdentityHomeOwner(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("identity home %s is not owned by the current user", path)
	}
	if info.Mode().Perm()&0o500 != 0o500 {
		return fmt.Errorf("identity home %s is not readable and searchable by its owner", path)
	}
	return nil
}
