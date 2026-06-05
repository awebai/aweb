package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func writeTeamBootstrapFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite := func(rel, body string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("team.yaml", `name: dev-review-two-agent
instructions:
  file: docs/team.md
roles:
  developer:
    title: Developer
    file: roles/developer.md
  reviewer:
    title: Reviewer
    file: roles/reviewer.md
agents:
  implementation:
    role_name: developer
    default_name: builder
    default_alias: dev
  review:
    role_name: reviewer
    default_name: reviewer
    default_alias: review
worktrees:
  - name: impl
    role_name: developer
    alias: dev
`)
	mustWrite("docs/team.md", "# Team\n")
	mustWrite("roles/developer.md", "# Developer\n")
	mustWrite("roles/reviewer.md", "# Reviewer\n")
	mustWrite("agents/implementation/AGENTS.md", "# Implementation\n")
	mustWrite("agents/review/AGENTS.md", "# Review\n")
	return dir
}

func writeInRepoTeamBootstrapFixture(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	mustWrite := func(rel, body string) {
		t.Helper()
		path := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite("team.yaml", `name: in-repo-team
instructions:
  file: docs/team.md
roles:
  coordinator:
    title: Coordinator
    file: roles/coordinator.md
  developer:
    title: Developer
    file: roles/developer.md
agents:
  coordinator:
    role_name: coordinator
    default_name: coord
    default_alias: coord
    home_template: home/coordinator
    work: repo_root
  implementation:
    role_name: developer
    default_name: impl
    default_alias: impl
    home_template: home/implementation
    work: git_worktree
`)
	mustWrite("docs/team.md", "# Team\n")
	mustWrite("roles/coordinator.md", "# Coordinator\n")
	mustWrite("roles/developer.md", "# Developer\n")
	mustWrite("home/coordinator/AGENTS.md", "# Coordinator\n")
	mustWrite("home/coordinator/README.md", "coordinator home\n")
	mustWrite("home/implementation/AGENTS.md", "# Implementation\n")
	return dir
}

func resetTeamBootstrapGlobals(t *testing.T) {
	t.Helper()
	prevHomeRoot := teamBootstrapHomeRoot
	prevAgentsDir := teamBootstrapAgentsDir
	prevWorkDir := teamBootstrapWorkDirectory
	prevRepoURL := teamBootstrapWorkRepoURL
	prevLegacy := teamBootstrapWorkRepo
	prevCache := teamBootstrapTemplateCacheDir
	prevRefresh := teamBootstrapRefreshTemplate
	prevFork := teamBootstrapForkTemplate
	prevUsername := teamBootstrapUsername
	prevNamespace := teamBootstrapNamespace
	prevTeam := teamBootstrapTeamName
	prevDisplay := teamBootstrapTeamDisplayName
	prevInvite := teamBootstrapInviteToken
	prevRegistry := teamBootstrapRegistryURL
	prevAweb := teamBootstrapAwebURL
	prevDryRun := teamBootstrapDryRun
	prevYes := teamBootstrapYes
	prevAsk := teamBootstrapAskAgentNames
	prevSkipRoles := teamBootstrapSkipRoles
	prevSkipInstructions := teamBootstrapSkipInstructions
	t.Cleanup(func() {
		teamBootstrapHomeRoot = prevHomeRoot
		teamBootstrapAgentsDir = prevAgentsDir
		teamBootstrapWorkDirectory = prevWorkDir
		teamBootstrapWorkRepoURL = prevRepoURL
		teamBootstrapWorkRepo = prevLegacy
		teamBootstrapTemplateCacheDir = prevCache
		teamBootstrapRefreshTemplate = prevRefresh
		teamBootstrapForkTemplate = prevFork
		teamBootstrapUsername = prevUsername
		teamBootstrapNamespace = prevNamespace
		teamBootstrapTeamName = prevTeam
		teamBootstrapTeamDisplayName = prevDisplay
		teamBootstrapInviteToken = prevInvite
		teamBootstrapRegistryURL = prevRegistry
		teamBootstrapAwebURL = prevAweb
		teamBootstrapDryRun = prevDryRun
		teamBootstrapYes = prevYes
		teamBootstrapAskAgentNames = prevAsk
		teamBootstrapSkipRoles = prevSkipRoles
		teamBootstrapSkipInstructions = prevSkipInstructions
	})
	teamBootstrapHomeRoot = ""
	teamBootstrapAgentsDir = "agents"
	teamBootstrapWorkDirectory = ""
	teamBootstrapWorkRepoURL = ""
	teamBootstrapWorkRepo = ""
	teamBootstrapTemplateCacheDir = ""
	teamBootstrapRefreshTemplate = false
	teamBootstrapForkTemplate = false
	teamBootstrapUsername = ""
	teamBootstrapNamespace = ""
	teamBootstrapTeamName = ""
	teamBootstrapTeamDisplayName = ""
	teamBootstrapInviteToken = ""
	teamBootstrapRegistryURL = ""
	teamBootstrapAwebURL = ""
	teamBootstrapDryRun = false
	teamBootstrapYes = false
	teamBootstrapAskAgentNames = false
	teamBootstrapSkipRoles = false
	teamBootstrapSkipInstructions = false
}

func testTeamBootstrapCommand(t *testing.T) *cobra.Command {
	t.Helper()
	cmd := &cobra.Command{Use: "bootstrap"}
	cmd.Flags().String("agents-dir", teamBootstrapAgentsDir, "")
	return cmd
}

func initGitRepo(t *testing.T, dir string) {
	t.Helper()
	run := func(args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	run("init")
	run("config", "user.email", "test@example.com")
	run("config", "user.name", "Test")
	if err := os.WriteFile(filepath.Join(dir, "README.md"), []byte("# repo\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run("add", "README.md")
	run("commit", "-m", "init")
}

func TestTeamBootstrapSpecPlansUseResponsibilityDirsAndRoleNames(t *testing.T) {
	templateDir := writeTeamBootstrapFixture(t)
	spec, err := loadTeamBootstrapSpec(templateDir)
	if err != nil {
		t.Fatalf("loadTeamBootstrapSpec: %v", err)
	}
	if err := validateTeamBootstrapSpec(templateDir, spec); err != nil {
		t.Fatalf("validateTeamBootstrapSpec: %v", err)
	}

	plans, err := buildTeamBootstrapPlans(strings.NewReader(""), &bytes.Buffer{}, templateDir, filepath.Join(templateDir, "homes"), spec, false)
	if err != nil {
		t.Fatalf("buildTeamBootstrapPlans: %v", err)
	}
	if len(plans) != 2 {
		t.Fatalf("expected 2 plans, got %d", len(plans))
	}
	if plans[0].Responsibility != "implementation" || plans[0].RoleName != "developer" || plans[0].Name != "builder" {
		t.Fatalf("implementation plan mismatch: %+v", plans[0])
	}
	if plans[1].Responsibility != "review" || plans[1].RoleName != "reviewer" || plans[1].Name != "reviewer" {
		t.Fatalf("review plan mismatch: %+v", plans[1])
	}
}

func TestTeamBootstrapInRepoPlansUseHomeTemplateAndWorkBindings(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	spec, err := loadTeamBootstrapSpec(templateDir)
	if err != nil {
		t.Fatalf("loadTeamBootstrapSpec: %v", err)
	}
	if err := validateTeamBootstrapSpec(templateDir, spec); err != nil {
		t.Fatalf("validateTeamBootstrapSpec: %v", err)
	}
	layout := teamBootstrapLayout{
		Mode:             teamBootstrapLayoutInRepo,
		CustomerRepoRoot: filepath.Join(t.TempDir(), "repo"),
		AgentsDirName:    "agents",
		AgentsRoot:       filepath.Join(t.TempDir(), "repo", "agents"),
	}
	layout.HomeRoot = filepath.Join(layout.AgentsRoot, "home")
	layout.WorktreesRoot = filepath.Join(layout.AgentsRoot, "worktrees")

	plans, err := buildTeamBootstrapPlans(strings.NewReader(""), &bytes.Buffer{}, templateDir, layout.HomeRoot, spec, false)
	if err != nil {
		t.Fatalf("buildTeamBootstrapPlans: %v", err)
	}
	if err := applyInRepoBootstrapWorkBindings(layout, plans); err != nil {
		t.Fatalf("applyInRepoBootstrapWorkBindings: %v", err)
	}
	if plans[0].Responsibility != "coordinator" {
		t.Fatalf("first plan=%s", plans[0].Responsibility)
	}
	if plans[0].SourceHome != filepath.Join(templateDir, "home", "coordinator") {
		t.Fatalf("coordinator source home=%q", plans[0].SourceHome)
	}
	if plans[0].WorkDir != layout.CustomerRepoRoot {
		t.Fatalf("coordinator work dir=%q", plans[0].WorkDir)
	}
	if plans[1].WorkDir != filepath.Join(layout.WorktreesRoot, "impl") {
		t.Fatalf("implementation work dir=%q", plans[1].WorkDir)
	}
	if plans[1].Instructions != filepath.Join(plans[1].HomeDir, "AGENTS.md") {
		t.Fatalf("implementation instructions=%q", plans[1].Instructions)
	}
}

func TestTeamBootstrapInRepoDryRunDoesNotCreateAgentsDir(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	prevCwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(prevCwd) })
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	teamBootstrapDryRun = true
	teamBootstrapSkipRoles = true
	teamBootstrapSkipInstructions = true

	var out bytes.Buffer
	cmd := testTeamBootstrapCommand(t)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runTeamBootstrap(cmd, []string{templateDir}); err != nil {
		t.Fatalf("runTeamBootstrap: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "agents")); !os.IsNotExist(err) {
		t.Fatalf("dry-run created agents dir or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".gitignore")); !os.IsNotExist(err) {
		t.Fatalf("dry-run created .gitignore or unexpected stat error: %v", err)
	}
}

func TestTeamBootstrapInRepoMissingSourceFailsBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	prevCwd, _ := os.Getwd()
	prevStdin := os.Stdin
	nonTTY, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Chdir(prevCwd)
		os.Stdin = prevStdin
		_ = nonTTY.Close()
	})
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	os.Stdin = nonTTY
	t.Setenv("AWEB_API_KEY", "")
	teamBootstrapSkipRoles = true
	teamBootstrapSkipInstructions = true

	var out bytes.Buffer
	cmd := testTeamBootstrapCommand(t)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	err = runTeamBootstrap(cmd, []string{templateDir})
	if err == nil || !strings.Contains(err.Error(), "requires a team source") {
		t.Fatalf("expected missing source error, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, "agents")); !os.IsNotExist(err) {
		t.Fatalf("missing-source run created agents dir or unexpected stat error: %v", err)
	}
	if _, err := os.Stat(filepath.Join(repoDir, ".gitignore")); !os.IsNotExist(err) {
		t.Fatalf("missing-source run created .gitignore or unexpected stat error: %v", err)
	}
}

func TestTeamBootstrapLayoutRejectsMixedAgentsDirAndLegacyWorkFlags(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	prevCwd, _ := os.Getwd()
	t.Cleanup(func() { _ = os.Chdir(prevCwd) })
	if err := os.Chdir(repoDir); err != nil {
		t.Fatal(err)
	}
	teamBootstrapWorkDirectory = filepath.Join(repoDir, "work")
	cmd := testTeamBootstrapCommand(t)
	if err := cmd.Flags().Set("agents-dir", "agents"); err != nil {
		t.Fatal(err)
	}

	if _, err := resolveTeamBootstrapLayoutPreflight(cmd); err == nil || !strings.Contains(err.Error(), "--agents-dir cannot be combined with --work-directory") {
		t.Fatalf("expected mixed flag error, got %v", err)
	}
}

func TestTeamBootstrapAskForAgentNamesRequiresTTY(t *testing.T) {
	prevStdin := os.Stdin
	nonTTY, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = nonTTY
	t.Cleanup(func() {
		os.Stdin = prevStdin
		_ = nonTTY.Close()
	})

	templateDir := writeTeamBootstrapFixture(t)
	spec, err := loadTeamBootstrapSpec(templateDir)
	if err != nil {
		t.Fatalf("loadTeamBootstrapSpec: %v", err)
	}
	_, err = buildTeamBootstrapPlans(strings.NewReader(""), &bytes.Buffer{}, templateDir, filepath.Join(templateDir, "homes"), spec, true)
	if err == nil || !strings.Contains(err.Error(), "requires an interactive terminal") {
		t.Fatalf("expected interactive terminal error, got %v", err)
	}
}

func TestTeamBootstrapCloneURLParsing(t *testing.T) {
	cloneURL, slug, full, err := resolveTeamBootstrapCloneURL("gh:awebai/aweb-team-dev-review")
	if err != nil {
		t.Fatalf("resolveTeamBootstrapCloneURL: %v", err)
	}
	if cloneURL != "https://github.com/awebai/aweb-team-dev-review.git" {
		t.Fatalf("cloneURL=%q", cloneURL)
	}
	if slug != "aweb-team-dev-review" {
		t.Fatalf("slug=%q", slug)
	}
	if full != "awebai/aweb-team-dev-review" {
		t.Fatalf("full=%q", full)
	}
}

func TestTeamBootstrapMaterializesAgentHomes(t *testing.T) {
	templateDir := writeTeamBootstrapFixture(t)
	plan := teamBootstrapAgentPlan{
		Responsibility: "implementation",
		RoleName:       "developer",
		Name:           "builder",
		HomeDir:        filepath.Join(templateDir, "agents", "implementation"),
		Instructions:   filepath.Join(templateDir, "agents", "implementation", "AGENTS.md"),
	}
	workDir := filepath.Join(templateDir, "workdir")
	if err := os.MkdirAll(workDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := materializeTeamBootstrapAgent(templateDir, plan, workDir); err != nil {
		t.Fatalf("materializeTeamBootstrapAgent: %v", err)
	}
	for _, rel := range []string{"AGENTS.md", "CLAUDE.md", "work"} {
		if _, err := os.Lstat(filepath.Join(plan.HomeDir, rel)); err != nil {
			t.Fatalf("expected %s: %v", rel, err)
		}
	}
	commands := plannedInitCommands([]teamBootstrapAgentPlan{{HomeDir: plan.HomeDir, Name: "builder", RoleName: "developer", Alias: "dev"}})
	if len(commands) != 1 || !strings.Contains(commands[0], "aw init --name builder --role-name developer") {
		t.Fatalf("unexpected init command: %#v", commands)
	}
}

func TestTeamBootstrapResolveWorkDirectoryRequiresExactlyOneFlag(t *testing.T) {
	templateDir := writeTeamBootstrapFixture(t)
	prevWorkDir := teamBootstrapWorkDirectory
	prevRepoURL := teamBootstrapWorkRepoURL
	prevLegacy := teamBootstrapWorkRepo
	t.Cleanup(func() {
		teamBootstrapWorkDirectory = prevWorkDir
		teamBootstrapWorkRepoURL = prevRepoURL
		teamBootstrapWorkRepo = prevLegacy
	})

	teamBootstrapWorkDirectory = ""
	teamBootstrapWorkRepoURL = ""
	teamBootstrapWorkRepo = ""
	if _, _, err := resolveTeamBootstrapWorkDirectoryAndRepoURL(templateDir); err == nil {
		t.Fatal("expected error when neither --work-directory nor --work-repo-url is set")
	}

	teamBootstrapWorkDirectory = filepath.Join(templateDir, "work")
	teamBootstrapWorkRepoURL = "https://github.com/awebai/aweb.git"
	teamBootstrapWorkRepo = ""
	if _, _, err := resolveTeamBootstrapWorkDirectoryAndRepoURL(templateDir); err == nil {
		t.Fatal("expected error when both --work-directory and --work-repo-url are set")
	}
}

func TestTeamBootstrapResolveWorkDirectoryDerivesFromWorkRepoURL(t *testing.T) {
	templateDir := writeTeamBootstrapFixture(t)
	prevWorkDir := teamBootstrapWorkDirectory
	prevRepoURL := teamBootstrapWorkRepoURL
	prevLegacy := teamBootstrapWorkRepo
	t.Cleanup(func() {
		teamBootstrapWorkDirectory = prevWorkDir
		teamBootstrapWorkRepoURL = prevRepoURL
		teamBootstrapWorkRepo = prevLegacy
	})

	repoURL := "https://github.com/awebai/aweb-team-dev-review.git"
	teamBootstrapWorkDirectory = ""
	teamBootstrapWorkRepoURL = repoURL
	teamBootstrapWorkRepo = ""

	workDir, gotURL, err := resolveTeamBootstrapWorkDirectoryAndRepoURL(templateDir)
	if err != nil {
		t.Fatalf("resolveTeamBootstrapWorkDirectoryAndRepoURL: %v", err)
	}
	if gotURL != repoURL {
		t.Fatalf("workRepoURL=%q want %q", gotURL, repoURL)
	}
	want := filepath.Join(templateDir, "worktrees", "aweb-team-dev-review")
	wantAbs, err := filepath.Abs(want)
	if err != nil {
		t.Fatal(err)
	}
	if workDir != wantAbs {
		t.Fatalf("workDir=%q want %q", workDir, wantAbs)
	}
}

func TestTeamBootstrapPrimaryPlanIsFirstGeneratedAgent(t *testing.T) {
	plans := []teamBootstrapAgentPlan{
		{Responsibility: "alpha", HomeDir: "/tmp/alpha"},
		{Responsibility: "implementation", HomeDir: "/tmp/implementation"},
	}
	primary, err := primaryTeamBootstrapPlan(plans)
	if err != nil {
		t.Fatalf("primaryTeamBootstrapPlan: %v", err)
	}
	if primary.Responsibility != "alpha" {
		t.Fatalf("primary responsibility=%q, want alpha", primary.Responsibility)
	}
}

func TestTeamBootstrapResolveSourceRejectsConflicts(t *testing.T) {
	prevInvite := teamBootstrapInviteToken
	prevUsername := teamBootstrapUsername
	prevNamespace := teamBootstrapNamespace
	prevTeam := teamBootstrapTeamName
	prevCwd, _ := os.Getwd()
	t.Cleanup(func() {
		teamBootstrapInviteToken = prevInvite
		teamBootstrapUsername = prevUsername
		teamBootstrapNamespace = prevNamespace
		teamBootstrapTeamName = prevTeam
		_ = os.Chdir(prevCwd)
	})
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWEB_API_KEY", "aw_sk_test")
	teamBootstrapInviteToken = "invite-token"
	teamBootstrapUsername = ""
	teamBootstrapNamespace = ""
	teamBootstrapTeamName = ""

	if _, err := resolveTeamBootstrapSource(); err == nil || !strings.Contains(err.Error(), "set only one team source") {
		t.Fatalf("expected conflict error, got %v", err)
	}
}

func TestTeamBootstrapResolveSourceUsesAPIKeyWithDefaultURL(t *testing.T) {
	prevInvite := teamBootstrapInviteToken
	prevUsername := teamBootstrapUsername
	prevNamespace := teamBootstrapNamespace
	prevTeam := teamBootstrapTeamName
	prevAwebURL := teamBootstrapAwebURL
	t.Cleanup(func() {
		teamBootstrapInviteToken = prevInvite
		teamBootstrapUsername = prevUsername
		teamBootstrapNamespace = prevNamespace
		teamBootstrapTeamName = prevTeam
		teamBootstrapAwebURL = prevAwebURL
	})
	t.Setenv("AWEB_API_KEY", "aw_sk_test")
	t.Setenv("AWEB_URL", "")
	teamBootstrapInviteToken = ""
	teamBootstrapUsername = ""
	teamBootstrapNamespace = ""
	teamBootstrapTeamName = ""
	teamBootstrapAwebURL = ""

	source, err := resolveTeamBootstrapSource()
	if err != nil {
		t.Fatalf("resolveTeamBootstrapSource: %v", err)
	}
	if source.Kind != teamBootstrapSourceAPIKey {
		t.Fatalf("source kind=%q, want api-key", source.Kind)
	}
}

func TestTeamBootstrapResolveSourceUsesAPIKeyWithURL(t *testing.T) {
	prevInvite := teamBootstrapInviteToken
	prevUsername := teamBootstrapUsername
	prevNamespace := teamBootstrapNamespace
	prevTeam := teamBootstrapTeamName
	prevAwebURL := teamBootstrapAwebURL
	t.Cleanup(func() {
		teamBootstrapInviteToken = prevInvite
		teamBootstrapUsername = prevUsername
		teamBootstrapNamespace = prevNamespace
		teamBootstrapTeamName = prevTeam
		teamBootstrapAwebURL = prevAwebURL
	})
	t.Setenv("AWEB_API_KEY", "aw_sk_test")
	t.Setenv("AWEB_URL", "https://app.aweb.ai")
	teamBootstrapInviteToken = ""
	teamBootstrapUsername = ""
	teamBootstrapNamespace = ""
	teamBootstrapTeamName = ""
	teamBootstrapAwebURL = ""

	source, err := resolveTeamBootstrapSource()
	if err != nil {
		t.Fatalf("resolveTeamBootstrapSource: %v", err)
	}
	if source.Kind != teamBootstrapSourceAPIKey {
		t.Fatalf("source kind=%q, want api-key", source.Kind)
	}
}

func TestTeamBootstrapResolveSourceUsesInviteToken(t *testing.T) {
	prevInvite := teamBootstrapInviteToken
	prevUsername := teamBootstrapUsername
	prevNamespace := teamBootstrapNamespace
	prevTeam := teamBootstrapTeamName
	prevCwd, _ := os.Getwd()
	t.Cleanup(func() {
		teamBootstrapInviteToken = prevInvite
		teamBootstrapUsername = prevUsername
		teamBootstrapNamespace = prevNamespace
		teamBootstrapTeamName = prevTeam
		_ = os.Chdir(prevCwd)
	})
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWEB_API_KEY", "")
	teamBootstrapInviteToken = "invite-token"
	teamBootstrapUsername = ""
	teamBootstrapNamespace = ""
	teamBootstrapTeamName = ""

	source, err := resolveTeamBootstrapSource()
	if err != nil {
		t.Fatalf("resolveTeamBootstrapSource: %v", err)
	}
	if source.Kind != teamBootstrapSourceInvite || source.InviteToken != "invite-token" {
		t.Fatalf("unexpected source: %+v", source)
	}
}

func TestTeamBootstrapResolveSourceErrorsWithoutSourceNonInteractive(t *testing.T) {
	prevInvite := teamBootstrapInviteToken
	prevUsername := teamBootstrapUsername
	prevNamespace := teamBootstrapNamespace
	prevTeam := teamBootstrapTeamName
	prevCwd, _ := os.Getwd()
	prevStdin := os.Stdin
	nonTTY, err := os.CreateTemp(t.TempDir(), "stdin")
	if err != nil {
		t.Fatal(err)
	}
	os.Stdin = nonTTY
	t.Cleanup(func() {
		teamBootstrapInviteToken = prevInvite
		teamBootstrapUsername = prevUsername
		teamBootstrapNamespace = prevNamespace
		teamBootstrapTeamName = prevTeam
		os.Stdin = prevStdin
		_ = os.Chdir(prevCwd)
		_ = nonTTY.Close()
	})
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWEB_API_KEY", "")
	teamBootstrapInviteToken = ""
	teamBootstrapUsername = ""
	teamBootstrapNamespace = ""
	teamBootstrapTeamName = ""

	if _, err := resolveTeamBootstrapSource(); err == nil || !strings.Contains(err.Error(), "requires a team source") {
		t.Fatalf("expected missing source error, got %v", err)
	}
}

func TestTeamBootstrapWorktreesRequireKnownRoleName(t *testing.T) {
	templateDir := writeTeamBootstrapFixture(t)
	path := filepath.Join(templateDir, "team.yaml")
	if err := os.WriteFile(path, []byte(`name: dev-review-two-agent
instructions:
  file: docs/team.md
roles:
  developer:
    title: Developer
    file: roles/developer.md
agents:
  implementation:
    role_name: developer
    default_name: builder
    default_alias: dev
worktrees:
  - name: impl
    role_name: missing
    alias: dev
`), 0o644); err != nil {
		t.Fatal(err)
	}
	spec, err := loadTeamBootstrapSpec(templateDir)
	if err != nil {
		t.Fatalf("loadTeamBootstrapSpec: %v", err)
	}
	if err := validateTeamBootstrapSpec(templateDir, spec); err == nil {
		t.Fatal("expected validateTeamBootstrapSpec to fail")
	}
}
