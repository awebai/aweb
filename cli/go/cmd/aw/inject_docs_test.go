package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// skipIfNoSymlinkSupport skips on platforms where os.Symlink generally
// requires elevated privileges (Windows non-admin shells). The InjectAgentDocs
// symlink behavior is best-effort on those platforms; AGENTS.md alone still works.
func skipIfNoSymlinkSupport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires elevated privileges on Windows; skipping")
	}
}

func TestInjectAgentDocsCreatesAgentsWhenNoFilesExist(t *testing.T) {
	skipIfNoSymlinkSupport(t)
	t.Parallel()

	tmp := t.TempDir()
	result := InjectProvidedAgentDocs(tmp, "## Shared Rules\n\nUse `aw`.")
	// Creates AGENTS.md and a CLAUDE.md symlink pointing at it so Claude Code
	// picks up the same source-of-truth.
	if len(result.Created) != 2 {
		t.Fatalf("created=%v", result.Created)
	}
	if result.Created[0] != "AGENTS.md" {
		t.Fatalf("expected AGENTS.md first, got %v", result.Created)
	}
	if !strings.Contains(result.Created[1], "CLAUDE.md") || !strings.Contains(result.Created[1], "AGENTS.md") {
		t.Fatalf("expected CLAUDE.md symlink → AGENTS.md, got %q", result.Created[1])
	}
	data, err := os.ReadFile(filepath.Join(tmp, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{awDocsMarkerStart, "# Agent Instructions", "## Shared Rules", "Use `aw`."} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in AGENTS.md:\n%s", want, text)
		}
	}
	// Verify CLAUDE.md exists as a symlink and resolves to AGENTS.md.
	claudePath := filepath.Join(tmp, "CLAUDE.md")
	info, err := os.Lstat(claudePath)
	if err != nil {
		t.Fatalf("CLAUDE.md not created: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("CLAUDE.md should be a symlink, got mode %v", info.Mode())
	}
	target, err := os.Readlink(claudePath)
	if err != nil {
		t.Fatalf("readlink CLAUDE.md: %v", err)
	}
	if target != "AGENTS.md" {
		t.Fatalf("CLAUDE.md should symlink to AGENTS.md, got %q", target)
	}
	// Reading through the symlink should return AGENTS.md content.
	claudeData, err := os.ReadFile(claudePath)
	if err != nil {
		t.Fatalf("read through CLAUDE.md symlink: %v", err)
	}
	if string(claudeData) != string(data) {
		t.Fatal("CLAUDE.md content (via symlink) should match AGENTS.md")
	}
}

func TestInjectAgentDocsDoesNotClobberExistingClaude(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	// Pre-existing CLAUDE.md as a regular file — must not be replaced by a symlink.
	claudePath := filepath.Join(tmp, "CLAUDE.md")
	if err := os.WriteFile(claudePath, []byte("# Local Notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := InjectProvidedAgentDocs(tmp, "## Shared Rules\n\nUse `aw`.")
	// Existing CLAUDE.md path: inject into existing file, do not create AGENTS.md
	// or a symlink (the symlink branch only fires when neither file exists).
	if len(result.Injected) != 1 || result.Injected[0] != "CLAUDE.md" {
		t.Fatalf("injected=%v, expected CLAUDE.md", result.Injected)
	}
	if len(result.Created) != 0 {
		t.Fatalf("created=%v, expected empty", result.Created)
	}
	info, err := os.Lstat(claudePath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("CLAUDE.md must remain a regular file, not be replaced by a symlink")
	}
}

func TestInjectAgentDocsAppendsToExistingFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "CLAUDE.md")
	if err := os.WriteFile(path, []byte("# Local Notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := InjectProvidedAgentDocs(tmp, "## Shared Rules\n\nUse `aw`.")
	if len(result.Injected) != 1 || result.Injected[0] != "CLAUDE.md" {
		t.Fatalf("injected=%v", result.Injected)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "# Local Notes") || !strings.Contains(text, awDocsMarkerStart) {
		t.Fatalf("unexpected content:\n%s", text)
	}
}

func TestInjectAgentDocsReplacesExistingInjectedSection(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "AGENTS.md")
	content := "Header\n\n" + awDocsMarkerStart + "\nold docs\n" + awDocsMarkerEnd + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	InjectProvidedAgentDocs(tmp, "## Shared Rules\n\nUse `aw`.")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, awDocsMarkerStart) != 1 {
		t.Fatalf("expected one injected section:\n%s", text)
	}
	if strings.Contains(text, "old docs") {
		t.Fatalf("old docs should be replaced:\n%s", text)
	}
}

func TestInjectAgentDocsAvoidsDoubleWriteForSymlink(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	target := filepath.Join(tmp, "AGENTS.md")
	link := filepath.Join(tmp, "CLAUDE.md")
	if err := os.WriteFile(target, []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	InjectProvidedAgentDocs(tmp, "## Shared Rules\n\nUse `aw`.")
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, awDocsMarkerStart) != 1 {
		t.Fatalf("expected one injected section:\n%s", text)
	}
}
