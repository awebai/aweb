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

func TestInjectAgentDocsReplacesAndDeduplicatesExistingInjectedSections(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "AGENTS.md")
	content := "Header\n\n" + awDocsMarkerStart + "\nold docs\n" + awDocsMarkerEnd + "\n\n" + awDocsMarkerStart + "\nstale duplicate\n" + awDocsMarkerEnd + "\n"
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
	if strings.Contains(text, "old docs") || strings.Contains(text, "stale duplicate") {
		t.Fatalf("old docs should be replaced:\n%s", text)
	}
}

func TestAwebOwnedStartupGuidanceHasSingleCanonicalOrder(t *testing.T) {
	root := cmdMonorepoRootForTest(t)
	read := func(rel string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}

	canonical := read("skills/aweb-coordination/SKILL.md")
	previous := -1
	for _, command := range []string{"aw workspace status", "aw mail inbox", "aw chat pending", "aw work ready"} {
		position := strings.Index(canonical, command)
		if position <= previous {
			t.Fatalf("canonical startup command %q missing or out of order", command)
		}
		previous = position
	}
	if !strings.Contains(strings.Join(strings.Fields(canonical), " "), "Read waiting mail and chat before claiming work") {
		t.Fatal("canonical startup loop must state why message checks precede work claims")
	}

	for _, rel := range []string{
		"packages/codex-plugin/skills/aweb-coordination/SKILL.md",
		"oas/.agents/capabilities/owned/aweb-tasks/skills/aweb-coordination/SKILL.md",
	} {
		if generated := read(rel); generated != canonical {
			t.Errorf("generated skill copy %s differs from canonical skill", rel)
		}
	}

	for _, rel := range []string{
		"agents/instructions.md",
		"agents/souls/consultant/AGENTS.md",
		"agents/souls/coordinator/AGENTS.md",
		"agents/souls/developer/AGENTS.md",
		"docs/agent-guide.md",
		"docs/configuration.md",
		"docs/coordination.md",
		"docs/start-working.md",
		"docs/tasks-and-work.md",
		"resource-packs/coord-workflows/resources/instructions.md",
		"server/src/aweb/defaults/roles/backend.md",
		"server/src/aweb/defaults/roles/coordinator.md",
		"server/src/aweb/defaults/roles/developer.md",
		"server/src/aweb/defaults/roles/frontend.md",
		"server/src/aweb/defaults/roles/reviewer.md",
		"server/src/aweb/defaults/team_instructions.md",
	} {
		guidance := strings.Join(strings.Fields(read(rel)), " ")
		if !strings.Contains(guidance, "canonical start-of-session loop in the `aweb-coordination` skill") {
			t.Errorf("startup guidance %s must defer to the canonical skill", rel)
		}
	}
}

func TestDefaultTeamInstructionsReinjectCanonicalStartupDeferral(t *testing.T) {
	root := cmdMonorepoRootForTest(t)
	body, err := os.ReadFile(filepath.Join(root, "server", "src", "aweb", "defaults", "team_instructions.md"))
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	path := filepath.Join(home, "AGENTS.md")
	if err := os.WriteFile(path, []byte("# Local profile\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	result := InjectProvidedAgentDocs(home, string(body))
	if len(result.Errors) != 0 {
		t.Fatalf("reinject errors: %v", result.Errors)
	}
	injected, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(injected)
	normalized := strings.Join(strings.Fields(text), " ")
	if !strings.Contains(normalized, "canonical start-of-session loop in the `aweb-coordination` skill") {
		t.Fatalf("re-injected home does not defer to canonical skill:\n%s", text)
	}
	if strings.Contains(text, "aw workspace status\naw work ready\naw mail inbox") {
		t.Fatalf("re-injected home retains an independent startup order:\n%s", text)
	}
}

func TestRootAgentInstructionsUseCoordinatorIntegrationWorkflow(t *testing.T) {
	path := filepath.Join(cmdMonorepoRootForTest(t), "AGENTS.md")
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	staticInstructions := strings.Join(strings.Fields(strings.SplitN(string(body), awDocsMarkerStart, 2)[0]), " ")
	for _, want := range []string{
		"The handoff is the branch",
		"Agents never merge their branches to main",
		"detached worktree based on `origin/main`",
		"merge `origin/main` into their own branch",
		"A team without a coordinator may use a different integration workflow",
	} {
		if !strings.Contains(staticInstructions, want) {
			t.Errorf("%s static instructions missing %q", path, want)
		}
	}
	for _, stale := range []string{
		"You merge your branch to main",
		"You merge main back to your branch",
	} {
		if strings.Contains(staticInstructions, stale) {
			t.Errorf("%s static instructions retain self-merge guidance %q", path, stale)
		}
	}
}

func TestInjectAgentDocsRejectsSymlinkOutsideTarget(t *testing.T) {
	skipIfNoSymlinkSupport(t)
	t.Parallel()

	target := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.md")
	original := []byte("# Outside file\n")
	if err := os.WriteFile(outside, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(target, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}

	result := InjectProvidedAgentDocs(target, "## Shared Rules\n\nUse `aw`.")
	if len(result.Errors) == 0 {
		t.Fatal("expected injection to reject AGENTS.md symlink outside target")
	}
	errorText := strings.Join(result.Errors, "; ")
	for _, want := range []string{target, outside} {
		if !strings.Contains(errorText, want) {
			t.Fatalf("escape error %q does not name %q", errorText, want)
		}
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != string(original) {
		t.Fatalf("outside file was modified:\n%s", data)
	}
}

func TestInjectAgentDocsAllowsInDirectorySymlinkAndUpdatesOnce(t *testing.T) {
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

	result := InjectProvidedAgentDocs(tmp, "## Shared Rules\n\nUse `aw`.")
	if len(result.Errors) > 0 {
		t.Fatalf("in-directory CLAUDE.md symlink was rejected: %v", result.Errors)
	}
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, awDocsMarkerStart) != 1 || strings.Count(text, awDocsMarkerEnd) != 1 || !strings.Contains(text, "Use `aw`.") {
		t.Fatalf("expected exactly one updated injected section:\n%s", text)
	}
}
