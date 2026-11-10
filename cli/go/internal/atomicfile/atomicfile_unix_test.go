//go:build !windows

package atomicfile

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func assertMode(t *testing.T, path string, want os.FileMode) {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != want {
		t.Fatalf("%s has mode %v; want %v", path, info.Mode(), want)
	}
}

// No test in this package runs in parallel, so changing the process umask
// here cannot leak into another test.
func TestWriteAppliesTheExactModeUnderAnyUmask(t *testing.T) {
	for _, umask := range []int{0o022, 0o077, 0o000, 0o277} {
		for _, mode := range []os.FileMode{0o600, 0o644, 0o755, 0o400} {
			previous := syscall.Umask(umask)
			dir := t.TempDir()
			path := filepath.Join(dir, "file")
			exclusive := filepath.Join(dir, "exclusive")
			err := Write(path, []byte("x"), mode)
			if err == nil {
				err = WriteExclusive(exclusive, []byte("x"), mode)
			}
			syscall.Umask(previous)
			if err != nil {
				t.Fatalf("umask %03o mode %03o: %v", umask, mode, err)
			}
			assertMode(t, path, mode)
			assertMode(t, exclusive, mode)
		}
	}
}

// The data must never be readable through a mode wider than the one asked for.
func TestTempFileCarriesTheRequestedModeBeforeCommit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	var tempName string
	err := Options{Mode: 0o600, TempName: &tempName, BeforeCommit: func() {
		assertMode(t, tempName, 0o600)
	}}.Write(path, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
}

func TestWriteReplacesTheModeOfAnExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "file")
	mustWriteFile(t, path, []byte("old"), 0o644)
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertMode(t, path, 0o600)
}

func TestParentModeAppliesToCreatedDirectories(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "made", "file")
	if err := (Options{Mode: 0o600, ParentMode: 0o700}).Write(path, []byte("x")); err != nil {
		t.Fatal(err)
	}
	assertMode(t, filepath.Dir(path), os.ModeDir|0o700)
}

func TestWriteReplacesASymlinkAtTheDestinationWithoutFollowingIt(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	mustWriteFile(t, target, []byte("target content"), 0o600)
	path := filepath.Join(dir, "link")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if err := Write(path, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	assertContent(t, target, []byte("target content"))
	assertMode(t, path, 0o600)
	assertContent(t, path, []byte("new"))
}

func TestWriteExclusiveRefusesADanglingSymlink(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	missing := filepath.Join(dir, "missing")
	if err := os.Symlink(missing, path); err != nil {
		t.Fatal(err)
	}
	err := WriteExclusive(path, []byte("key"), 0o600)
	if !errors.Is(err, os.ErrExist) {
		t.Fatalf("want an already-exists error, got %v", err)
	}
	if _, err := os.Lstat(missing); !os.IsNotExist(err) {
		t.Fatalf("the symlink was followed: %v", err)
	}
	assertOnlyEntries(t, dir, "signing.key")
}

func skipWhenPermissionsAreNotEnforced(t *testing.T) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("root bypasses directory permissions")
	}
}

func TestWriteIntoAReadOnlyDirectoryLeavesTheDestination(t *testing.T) {
	skipWhenPermissionsAreNotEnforced(t)
	dir := filepath.Join(t.TempDir(), "locked")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "file")
	mustWriteFile(t, path, []byte("old"), 0o600)
	if err := os.Chmod(dir, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	err := Write(path, []byte("new"), 0o600)
	if !errors.Is(err, os.ErrPermission) {
		t.Fatalf("want a permission error, got %v", err)
	}
	assertContent(t, path, []byte("old"))
	assertOnlyEntries(t, dir, "file")
}

// A directory that can be written and searched but not read accepts the temp
// file and the rename, and then cannot be opened for the directory sync. The
// write must report that instead of claiming a durable rename.
func TestWriteReportsADirectorySyncFailure(t *testing.T) {
	skipWhenPermissionsAreNotEnforced(t)
	for _, exclusive := range []bool{false, true} {
		dir := filepath.Join(t.TempDir(), "unreadable")
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "file")
		if err := os.Chmod(dir, 0o300); err != nil {
			t.Fatal(err)
		}
		err := Options{Mode: 0o600, Exclusive: exclusive}.Write(path, []byte("new"))
		if chmodErr := os.Chmod(dir, 0o700); chmodErr != nil {
			t.Fatal(chmodErr)
		}
		if !errors.Is(err, os.ErrPermission) {
			t.Fatalf("exclusive=%v: want the directory open failure, got %v", exclusive, err)
		}
		if !strings.Contains(err.Error(), "sync directory") || !strings.Contains(err.Error(), path) {
			t.Fatalf("exclusive=%v: error does not name the directory sync and %s: %v", exclusive, path, err)
		}
		// The rename already happened: the failure is about durability, and
		// the destination holds the complete new content.
		assertContent(t, path, []byte("new"))
		assertOnlyEntries(t, dir, "file")
	}
}

func TestSyncDirReportsAnUnopenableDirectory(t *testing.T) {
	err := SyncDir(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("want a not-exist error, got %v", err)
	}
}
