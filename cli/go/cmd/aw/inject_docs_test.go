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

	assertStartupOrder := func(source, guidance string) {
		t.Helper()
		previous := -1
		for _, command := range []string{"aw workspace status", "aw mail inbox", "aw chat pending", "aw work ready"} {
			position := strings.Index(guidance, command)
			if position <= previous {
				t.Fatalf("%s startup command %q missing or out of order", source, command)
			}
			previous = position
		}
	}

	canonical := read("skills/aweb-coordination/SKILL.md")
	assertStartupOrder("canonical skill", canonical)
	if !strings.Contains(strings.Join(strings.Fields(canonical), " "), "Read waiting mail and chat before claiming work") {
		t.Fatal("canonical startup loop must state why message checks precede work claims")
	}

	standaloneGuide := read("docs/agent-guide.md")
	assertStartupOrder("standalone agent guide", standaloneGuide)
	standaloneGuidance := strings.Join(strings.Fields(standaloneGuide), " ")
	for _, want := range []string{
		"Active team instructions govern startup ordering when present.",
		"optional `aweb-coordination` skill may provide the same ordering when installed",
		"otherwise the standard commands below stand on their own",
		"Neither the skill nor a Library/profile service is required for messaging.",
		"Mail and waiting chat come before new work because another agent may already be blocked on you.",
	} {
		if !strings.Contains(standaloneGuidance, want) {
			t.Errorf("standalone agent guide missing startup contract %q", want)
		}
	}
	if strings.Contains(standaloneGuidance, "canonical start-of-session loop in the `aweb-coordination` skill") {
		t.Error("standalone agent guide must not require the optional coordination skill")
	}

	for _, rel := range []string{
		"packages/codex-plugin/skills/aweb-coordination/SKILL.md",
		"oats/.agents/capabilities/owned/aweb-tasks/skills/aweb-coordination/SKILL.md",
	} {
		if generated := read(rel); generated != canonical {
			t.Errorf("generated skill copy %s differs from canonical skill", rel)
		}
	}

	for _, rel := range []string{
		"agents/souls/consultant/AGENTS.md",
		"agents/souls/coordinator/AGENTS.md",
		"agents/souls/developer/AGENTS.md",
		"docs/configuration.md",
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

	teamCopy := strings.Join(strings.Fields(read("agents/instructions.md")), " ")
	for _, want := range []string{
		"The canonical source for this order is the `aweb-coordination` skill.",
		"This block reproduces it so it is available without loading the skill.",
		"If the two ever disagree, the skill wins and this block is stale.",
	} {
		if !strings.Contains(teamCopy, want) {
			t.Errorf("team-instructions convenience copy missing %q", want)
		}
	}
	if strings.Contains(teamCopy, "This order is canonical") {
		t.Error("team-instructions convenience copy independently claims canonicality")
	}
}

func TestRepositoryInstructionCopiesDoNotFreezeLiveRoster(t *testing.T) {
	root := cmdMonorepoRootForTest(t)
	for _, relative := range []string{"AGENTS.md", "agents/instructions.md", "cli/go/AGENTS.md"} {
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		guidance := strings.Join(strings.Fields(string(body)), " ")
		for _, want := range []string{
			"Do not copy teammate names, presence timestamps, or current availability into repository or profile instructions.",
			"Resolve current responsibility and reachability from the active team instructions and `aw workspace status`.",
		} {
			if !strings.Contains(guidance, want) {
				t.Errorf("%s missing durable roster-precedence guidance %q", relative, want)
			}
		}
		for _, stale := range []string{"dev is live", "dev is not reachable", "avi is not reachable", "last seen 2026-"} {
			if strings.Contains(strings.ToLower(guidance), stale) {
				t.Errorf("%s freezes mutable roster claim %q", relative, stale)
			}
		}
	}
}

func TestSelfHostingGuideUsesTheCurrentExistingDirectoryLocalIdentityPath(t *testing.T) {
	if idVerifyCmd.Use != "verify <did_aw>" {
		t.Fatalf("id verify command shape changed to %q", idVerifyCmd.Use)
	}

	body, err := os.ReadFile(filepath.Join(cmdMonorepoRootForTest(t), "docs", "self-hosting-guide.md"))
	if err != nil {
		t.Fatal(err)
	}
	guidance := strings.Join(strings.Fields(string(body)), " ")
	for _, want := range []string{
		"a local self-custodial identity for `default:local`",
		"Run the join command from a second existing agent directory",
		"aw team join <invite-token> --name bob",
		"workspace using the self-hosted URL carried by the invite",
		"aw check",
		"aw id verify <did:aw>",
	} {
		if !strings.Contains(guidance, want) {
			t.Errorf("self-hosting guide missing current local path %q", want)
		}
	}
	for _, stale := range []string{
		"a global identity in the local test namespace",
		"aw workspace add-worktree",
		"aw workspace connect --service http://localhost:8000",
	} {
		if strings.Contains(guidance, stale) {
			t.Errorf("self-hosting guide retains stale setup path %q", stale)
		}
	}
}

func TestPublicTeamJoinGuidanceConnectsByDefault(t *testing.T) {
	joinHelp := strings.Join(strings.Fields(teamHumanJoinCmd.Long), " ")
	if !strings.Contains(joinHelp, "connects this workspace") || !strings.Contains(joinHelp, "--no-connect") {
		t.Fatalf("team join help does not state its default connection contract:\n%s", teamHumanJoinCmd.Long)
	}
	if teamHumanJoinCmd.Flags().Lookup("no-connect") == nil {
		t.Fatal("team join no longer offers the identity-only escape hatch")
	}

	connected := true
	formatted := formatTeamAcceptInvite(teamAcceptInviteOutput{
		Status: "accepted", TeamID: "default:example.com", Alias: "bob", CertPath: ".aw/team-certs/default_example.com.json", Connected: &connected, AwebURL: "https://app.example/api",
	})
	if !strings.Contains(formatted, "Connected to https://app.example/api as bob") {
		t.Fatalf("team join output does not report the connection it completed:\n%s", formatted)
	}
	notConnected := false
	legacyFormatted := formatTeamAcceptInvite(teamAcceptInviteOutput{Connected: &notConnected})
	if !strings.Contains(legacyFormatted, "aw workspace connect --service '<url>'") {
		t.Fatalf("legacy membership-only output does not shell-quote its URL placeholder:\n%s", legacyFormatted)
	}
	if got := formatTeamInvite(teamInviteOutput{Token: "token", PorcelainJoin: true}); !strings.Contains(got, "aw team join token --name <name>") {
		t.Fatalf("human invite does not print the porcelain join path:\n%s", got)
	}
	if got := formatTeamInvite(teamInviteOutput{Token: "token"}); !strings.Contains(got, "aw id team accept-invite token --name <name>") {
		t.Fatalf("low-level invite no longer prints its membership-only primitive:\n%s", got)
	}
}

func TestTeamJoinGuidanceMirrorsStayCurrent(t *testing.T) {
	root := cmdMonorepoRootForTest(t)
	read := func(relative string) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		return string(body)
	}
	for canonical, mirrors := range map[string][]string{
		"docs/identity-guide.md":               {"awid/site/static/identity-guide.md"},
		"skills/aweb-identity/SKILL.md":        {"packages/codex-plugin/skills/aweb-identity/SKILL.md"},
		"skills/aweb-team-membership/SKILL.md": {"packages/codex-plugin/skills/aweb-team-membership/SKILL.md"},
		"skills/aweb-coordination/SKILL.md": {
			"packages/codex-plugin/skills/aweb-coordination/SKILL.md",
			"oats/.agents/capabilities/owned/aweb-tasks/skills/aweb-coordination/SKILL.md",
		},
	} {
		want := read(canonical)
		for _, mirror := range mirrors {
			if got := read(mirror); got != want {
				t.Errorf("%s differs from canonical %s", mirror, canonical)
			}
		}
	}

	for _, relative := range []string{
		"docs/identity-guide.md",
		"awid/site/static/identity-guide.md",
		"skills/aweb-coordination/SKILL.md",
		"resource-packs/coord-workflows/README.md",
	} {
		guidance := read(relative)
		for _, stale := range []string{
			"aw team join <invite-token>\naw init",
			"aw team join <invite-token>\naw workspace connect",
			"Joining installs the second agent's identity and membership but does not create",
		} {
			if strings.Contains(guidance, stale) {
				t.Errorf("%s retains stale post-join setup contract %q", relative, stale)
			}
		}
	}
}

func TestAwebTeamInstructionsExplainRosterResponsibility(t *testing.T) {
	body, err := os.ReadFile(filepath.Join(cmdMonorepoRootForTest(t), "agents", "instructions.md"))
	if err != nil {
		t.Fatal(err)
	}
	guidance := strings.Join(strings.Fields(string(body)), " ")
	for _, want := range []string{
		"Roles shown in `aw workspace status` are each workspace's current operating responsibility on this team.",
		"Setup initializes `role_name` from the materialized profile, but it remains independently mutable",
		"changing it does not change which profile the workspace runs or grant additional authority",
		"Presence shows which workspaces currently carry a responsibility and which are offline.",
	} {
		if !strings.Contains(guidance, want) {
			t.Errorf("team instructions missing roster guidance %q", want)
		}
	}
	if strings.Contains(guidance, "Roles shown in `aw workspace status` are the profile each agent runs") {
		t.Error("team instructions still equate mutable roles with materialized profiles")
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

func TestAwebProjectAndTeamInstructionsCarryCurrentIntegrationPolicy(t *testing.T) {
	root := cmdMonorepoRootForTest(t)
	readNormalized := func(rel string, beforeMarker bool) string {
		t.Helper()
		body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		text := string(body)
		if beforeMarker {
			text = strings.SplitN(text, awDocsMarkerStart, 2)[0]
		}
		return strings.Join(strings.Fields(text), " ")
	}

	projectCopy := readNormalized("AGENTS.md", true)
	teamAuthority := readNormalized("agents/instructions.md", false)
	for _, want := range []string{
		"Ordinary single-repo work: merge it yourself.",
		"merge your branch to main and merge main back into your branch",
		"Ask the coordinator to integrate when the change spans repositories, cuts a release tag, or touches production tooling.",
		"never merge work your reviewer has not ACKed",
		"always merge `origin/main` into your branch before handing off",
	} {
		if !strings.Contains(projectCopy, want) {
			t.Errorf("project instruction copy missing %q", want)
		}
		if !strings.Contains(teamAuthority, want) {
			t.Errorf("authoritative team instructions missing %q", want)
		}
	}
	for _, want := range []string{
		"Active team instructions are authoritative for this team's branch and integration workflow.",
		"If a repository or profile copy disagrees, the active team instructions win and the copy is stale.",
	} {
		if !strings.Contains(teamAuthority, want) {
			t.Errorf("authoritative team instructions missing %q", want)
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
