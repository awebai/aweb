package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestFindWorktreeContextPathWalksUp(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	root := filepath.Join(tmp, "repo")
	nested := filepath.Join(root, "a", "b", "c")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	ctxPath := filepath.Join(root, ".aw", "context")
	if err := os.WriteFile(ctxPath, []byte("default_account: alice\n"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}

	got, err := FindWorktreeContextPath(nested)
	if err != nil {
		t.Fatalf("FindWorktreeContextPath: %v", err)
	}
	if got != ctxPath {
		t.Fatalf("path=%q want %q", got, ctxPath)
	}
}

func TestFindWorktreeContextPathMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	_, err := FindWorktreeContextPath(tmp)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v, want os.ErrNotExist", err)
	}
}
