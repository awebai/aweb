package run

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDetectWorktreeGitDirReturnsEmptyForRegularRepo(t *testing.T) {
	worktree := t.TempDir()
	if err := os.Mkdir(filepath.Join(worktree, ".git"), 0o755); err != nil {
		t.Fatalf("mkdir .git: %v", err)
	}

	got, err := detectWorktreeGitDir(worktree)
	if err != nil {
		t.Fatalf("detectWorktreeGitDir returned error: %v", err)
	}
	if got != "" {
		t.Fatalf("expected no gitdir for regular repo, got %q", got)
	}
}

func TestDetectWorktreeGitDirResolvesRelativePath(t *testing.T) {
	worktree := t.TempDir()
	relative := filepath.Join("..", "repo", ".git", "worktrees", "grace")
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+relative+"\n"), 0o644); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	got, err := detectWorktreeGitDir(worktree)
	if err != nil {
		t.Fatalf("detectWorktreeGitDir returned error: %v", err)
	}

	want := filepath.Clean(filepath.Join(worktree, relative))
	if got != want {
		t.Fatalf("gitdir=%q want %q", got, want)
	}
}

func TestDetectWorktreeGitDirRejectsMalformedFile(t *testing.T) {
	worktree := t.TempDir()
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("not-a-gitdir\n"), 0o644); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	if _, err := detectWorktreeGitDir(worktree); err == nil {
		t.Fatal("expected malformed .git file to return an error")
	}
}
