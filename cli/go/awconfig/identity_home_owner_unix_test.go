//go:build !windows

package awconfig

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

type foreignIdentityHomeInfo struct{ os.FileInfo }

func (f foreignIdentityHomeInfo) Sys() any { return &syscall.Stat_t{Uid: uint32(os.Geteuid() + 1)} }

func TestSelectedIdentityHomeRejectsForeignOwnerAndUnreadableDirectory(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := checkIdentityHomeOwner(root, foreignIdentityHomeInfo{info}); err == nil {
		t.Fatal("accepted another user's identity directory")
	}
	if err := os.Chmod(root, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(root, 0o700) })
	if _, err := ResolveIdentityHome(root, root); err == nil {
		t.Fatal("accepted an unreadable selected identity home")
	}
}
