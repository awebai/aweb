package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestInitNextStepLinesHostedGitRepoPromoteRunAndDashboard(t *testing.T) {
	repo := t.TempDir()
	if out, err := exec.Command("git", "-C", repo, "init").CombinedOutput(); err != nil {
		t.Fatalf("git init: %v\n%s", err, string(out))
	}

	lines := initNextStepLines(&initResult{
		ServerName:    "app.aweb.ai",
		ExportBaseURL: "https://app.aweb.ai/api",
	}, repo, false, false, false)
	text := strings.Join(lines, "\n")

	for _, want := range []string{
		"aw run codex",
		"aw run claude",
		"aw workspace add-worktree <role>",
		"aw claim-human --email you@example.com",
		"aw init --inject-docs",
		"aw init --setup-hooks",
		"aw init --setup-channel",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in next steps:\n%s", want, text)
		}
	}
}

func TestInitNextStepLinesLocalDirStayFocused(t *testing.T) {
	lines := initNextStepLines(&initResult{
		ServerName:    "localhost",
		ExportBaseURL: "http://127.0.0.1:8000/api",
	}, t.TempDir(), true, true, true)
	text := strings.Join(lines, "\n")

	if len(lines) != 2 {
		t.Fatalf("expected 2 next-step lines, got %d:\n%s", len(lines), text)
	}
	for _, want := range []string{"aw run codex", "aw run claude"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in next steps:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"aw workspace add-worktree <role>", "aw init", "aw claim-human", "aw init --inject-docs", "aw init --setup-hooks", "aw init --setup-channel"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("unexpected %q in next steps:\n%s", unwanted, text)
		}
	}
}

func TestFormatWorkspaceAddWorktreeExplainsNewIdentity(t *testing.T) {
	out := formatWorkspaceAddWorktree(workspaceAddWorktreeOutput{
		Alias:        "bob",
		Role:         "developer",
		Branch:       "bob",
		WorktreePath: "/tmp/repo-bob",
	})

	for _, want := range []string{
		"New agent worktree created at",
		"Workspace:  this worktree is now agent bob",
		"State:      .aw/ in that worktree stores the local identity and workspace binding",
		"aw run codex",
		"aw run claude",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in output:\n%s", want, out)
		}
	}
}
