//go:build !windows

package wake

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/awebai/aw/internal/custodypath"
)

func prepareControlSocket(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return checkControlSocket(path)
}

func checkControlSocket(path string) error {
	if err := checkWakeControlDirectory(filepath.Dir(path), custodypath.IsRuntime(path)); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 || !ownedByWakeUser(info) || info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("unsafe wake control socket %s; inspect it before restarting the wake broker", path)
	}
	return nil
}

func checkWakeControlDirectory(dir string, privateRuntime bool) error {
	readDir := os.Stat
	if privateRuntime {
		// The fixed per-user directory for shortened paths must be private
		// and must itself be a directory, even under a shared temp root.
		readDir = os.Lstat
	}
	info, err := readDir(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() || !ownedByWakeUser(info) || (privateRuntime && info.Mode().Perm()&0o077 != 0) {
		return fmt.Errorf("unsafe wake control directory %s; use an owner-controlled wake state directory", dir)
	}
	return nil
}

func ownedByWakeUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}
