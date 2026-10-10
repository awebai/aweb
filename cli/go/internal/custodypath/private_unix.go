//go:build !windows

package custodypath

import (
	"fmt"
	"os"
	"syscall"

	"github.com/awebai/aw/internal/pathpreflight"
)

func ownerOnly(info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) {
		return fmt.Errorf("custody path is not owned by the current user")
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("custody path must not be a symlink")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("custody path must be owner-only")
	}
	return nil
}

// Prepare creates only the fixed short runtime directory. Existing unsafe paths
// are refused, never chmodded or followed. Short legacy/explicit paths are unchanged.
func Prepare(socket string) error {
	if !IsRuntime(socket) {
		return nil
	}
	return prepareAt(RuntimeDir(), socket)
}

func prepareAt(dir, socket string) error {
	if err := pathpreflight.RejectSymlinkedExistingComponents(dir, "custody runtime", pathpreflight.Options{}); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	return checkAt(dir, socket)
}

// Check runs before both listen and dial, so a predictable locator cannot route
// a client to another user's socket, even before this user first starts custody.
func Check(socket string) error {
	if !IsRuntime(socket) {
		return nil
	}
	return checkAt(RuntimeDir(), socket)
}

func checkAt(dir, socket string) error {
	if err := pathpreflight.RejectSymlinkedExistingComponents(dir, "custody runtime", pathpreflight.Options{}); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("custody runtime path must be a directory")
	}
	if err := ownerOnly(info); err != nil {
		return err
	}
	info, err = os.Lstat(socket)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if err := ownerOnly(info); err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("custody path must be a socket")
	}
	return nil
}
