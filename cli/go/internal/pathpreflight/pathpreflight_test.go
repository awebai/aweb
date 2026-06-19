package pathpreflight

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPreflightDirRejectsSymlinkedParentForExistingHome(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.MkdirAll(filepath.Join(outside, "agent"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	err := PreflightDir(filepath.Join(base, "link", "agent"), "agent home", AllowTempAmbientSymlinkPrefix())
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
}

func TestPreflightDirRejectsSymlinkedParentForMissingHome(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	err := PreflightDir(filepath.Join(base, "link", "agent"), "agent home", AllowTempAmbientSymlinkPrefix())
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(outside, "agent")); !os.IsNotExist(statErr) {
		t.Fatalf("preflight created through symlinked parent, stat err=%v", statErr)
	}
}

func TestPreflightFileRejectsFinalSymlinkAndNonRegular(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(root, "outside")
	if err := os.Symlink(outside, filepath.Join(root, "agent.log")); err != nil {
		t.Fatal(err)
	}
	err := PreflightFile(filepath.Join(root, "agent.log"), "runtime file", AllowTempAmbientSymlinkPrefix())
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("symlink error=%v", err)
	}
	if _, statErr := os.Lstat(outside); !os.IsNotExist(statErr) {
		t.Fatalf("outside target unexpectedly exists, stat err=%v", statErr)
	}

	dirDest := filepath.Join(root, "agent.json")
	if err := os.Mkdir(dirDest, 0o755); err != nil {
		t.Fatal(err)
	}
	err = PreflightFile(dirDest, "runtime file", AllowTempAmbientSymlinkPrefix())
	if err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("directory error=%v", err)
	}
}

func TestPreflightFileAllowsMissingAndRegular(t *testing.T) {
	root := t.TempDir()
	missing := filepath.Join(root, "missing")
	if err := PreflightFile(missing, "runtime file", AllowTempAmbientSymlinkPrefix()); err != nil {
		t.Fatalf("missing file should be allowed: %v", err)
	}
	regular := filepath.Join(root, "regular")
	if err := os.WriteFile(regular, []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := PreflightFile(regular, "runtime file", AllowTempAmbientSymlinkPrefix()); err != nil {
		t.Fatalf("regular file should be allowed: %v", err)
	}
}
