package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
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
	prevLayoutOnly := teamBootstrapLayoutOnly
	prevYes := teamBootstrapYes
	prevAsk := teamBootstrapAskAgentNames
	prevSkipRoles := teamBootstrapSkipRoles
	prevSkipInstructions := teamBootstrapSkipInstructions
	prevIdentityPrefix := agentsIdentityPrefix
	prevAddLocal := agentsAddLocal
	prevAddGlobal := agentsAddGlobal
	prevAddRole := agentsAddRole
	prevAddWorktreeAlias := agentsAddWorktreeAlias
	prevAddLayoutOnly := agentsAddLayoutOnly
	prevRemoveDeprovision := agentsRemoveDeprovisionLocal
	prevRemoveLayout := agentsRemoveRemoveLayout
	prevRemoveDeleteAddress := agentsRemoveDeleteAddress
	prevAddMaterialize := agentsAddMaterializeAgent
	prevAddInitPrimary := agentsAddInitPrimaryAgent
	prevAddInitAdditional := agentsAddInitAdditionalAgent
	prevAddClaim := agentsAddClaimIdentityAddress
	prevAddCert := agentsAddEnsureGlobalCertificate
	prevAddConnect := agentsAddConnectGlobalAgent
	prevLockExclusive := agentsLockExclusive
	prevWriteLayoutYAML := writeAgentsAddLayoutYAML
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
		teamBootstrapLayoutOnly = prevLayoutOnly
		teamBootstrapYes = prevYes
		teamBootstrapAskAgentNames = prevAsk
		teamBootstrapSkipRoles = prevSkipRoles
		teamBootstrapSkipInstructions = prevSkipInstructions
		agentsIdentityPrefix = prevIdentityPrefix
		agentsAddLocal = prevAddLocal
		agentsAddGlobal = prevAddGlobal
		agentsAddRole = prevAddRole
		agentsAddWorktreeAlias = prevAddWorktreeAlias
		agentsAddLayoutOnly = prevAddLayoutOnly
		agentsRemoveDeprovisionLocal = prevRemoveDeprovision
		agentsRemoveRemoveLayout = prevRemoveLayout
		agentsRemoveDeleteAddress = prevRemoveDeleteAddress
		agentsAddMaterializeAgent = prevAddMaterialize
		agentsAddInitPrimaryAgent = prevAddInitPrimary
		agentsAddInitAdditionalAgent = prevAddInitAdditional
		agentsAddClaimIdentityAddress = prevAddClaim
		agentsAddEnsureGlobalCertificate = prevAddCert
		agentsAddConnectGlobalAgent = prevAddConnect
		agentsLockExclusive = prevLockExclusive
		writeAgentsAddLayoutYAML = prevWriteLayoutYAML
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
	teamBootstrapLayoutOnly = false
	teamBootstrapYes = false
	teamBootstrapAskAgentNames = false
	teamBootstrapSkipRoles = false
	teamBootstrapSkipInstructions = false
	agentsIdentityPrefix = ""
	agentsAddLocal = false
	agentsAddGlobal = false
	agentsAddRole = ""
	agentsAddWorktreeAlias = ""
	agentsAddLayoutOnly = false
	agentsRemoveDeprovisionLocal = false
	agentsRemoveRemoveLayout = false
	agentsRemoveDeleteAddress = false
	agentsAddMaterializeAgent = materializeTeamBootstrapAgent
	agentsAddInitPrimaryAgent = initTeamBootstrapPrimaryAgent
	agentsAddInitAdditionalAgent = initTeamBootstrapAdditionalAgent
	agentsAddClaimIdentityAddress = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, params awid.AtomicAddressClaimParams) (*awid.AtomicAddressClaimResult, error) {
		return registry.ClaimIdentityAddressAt(ctx, registryURL, params)
	}
	agentsAddEnsureGlobalCertificate = ensureAgentsAddGlobalCertificate
	agentsAddConnectGlobalAgent = initCertificateConnectWithOptions
	agentsLockExclusive = func(lockPath string) (agentsLayoutLock, error) {
		return awconfig.LockExclusive(lockPath)
	}
	writeAgentsAddLayoutYAML = writeAgentsAddLayoutYAMLImpl
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

func gitBranchExistsForTest(t *testing.T, repoDir, branch string) bool {
	t.Helper()
	cmd := exec.Command("git", "-C", repoDir, "branch", "--list", branch)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git branch --list %s: %v\n%s", branch, err, out)
	}
	return strings.TrimSpace(string(out)) != ""
}

func TestAgentsCommandSurfaceKeepsLegacyAgentsAlongsideHumanTeamVerbs(t *testing.T) {
	agents := findRootSubcommand("agents")
	if agents == nil {
		t.Fatal("root command missing aw agents")
	}
	if agents.GroupID != groupObsolete {
		t.Fatalf("aw agents GroupID=%q, want %q", agents.GroupID, groupObsolete)
	}
	team := findRootSubcommand("team")
	if team == nil {
		t.Fatal("root command missing aw team")
	}
	for _, name := range []string{"create", "invite", "join", "list", "switch", "leave", "remove-agent"} {
		if findSubcommand(team, name) == nil {
			t.Fatalf("aw team missing %s subcommand", name)
		}
	}
	for _, tt := range []struct {
		name string
		use  string
	}{
		{"bootstrap", "bootstrap <template>"},
		{"plan", "plan"},
		{"provision", "provision"},
		{"add", "add <responsibility>"},
		{"add-worktree", "add-worktree [role]"},
		{"remove", "remove <responsibility>"},
	} {
		cmd := findSubcommand(agents, tt.name)
		if cmd == nil {
			t.Fatalf("aw agents missing %s subcommand", tt.name)
		}
		if cmd.Use != tt.use {
			t.Fatalf("aw agents %s Use=%q, want %q", tt.name, cmd.Use, tt.use)
		}
	}
	if !strings.Contains(agents.Long, "repo root itself is not an aw identity") {
		t.Fatalf("aw agents help should explain repo root identity boundary:\n%s", agents.Long)
	}
}

func findRootSubcommand(name string) *cobra.Command {
	return findSubcommand(rootCmd, name)
}

func findSubcommand(parent *cobra.Command, name string) *cobra.Command {
	for _, cmd := range parent.Commands() {
		if cmd.Name() == name {
			return cmd
		}
	}
	return nil
}

func agentsProvisionHasCheck(out agentsProvisionOutput, responsibility, field, value, status string) bool {
	for _, check := range out.Availability {
		if check.Responsibility == responsibility && check.Field == field && check.Value == value && check.Status == status {
			return true
		}
	}
	return false
}

func assertPathExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected path to exist %s: %v", path, err)
	}
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

func TestTeamBootstrapInRepoSanitizesWorktreeAliasPath(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	spec, err := loadTeamBootstrapSpec(templateDir)
	if err != nil {
		t.Fatalf("loadTeamBootstrapSpec: %v", err)
	}
	agent := spec.Agents["implementation"]
	agent.DefaultAlias = "../escape"
	spec.Agents["implementation"] = agent
	if err := validateTeamBootstrapSpec(templateDir, spec); err != nil {
		t.Fatalf("validateTeamBootstrapSpec: %v", err)
	}
	repoRoot := filepath.Join(t.TempDir(), "repo")
	layout := teamBootstrapLayout{
		Mode:             teamBootstrapLayoutInRepo,
		CustomerRepoRoot: repoRoot,
		AgentsDirName:    "agents",
		AgentsRoot:       filepath.Join(repoRoot, "agents"),
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
	got := plans[1].WorkDir
	want := filepath.Join(layout.WorktreesRoot, "escape")
	if got != want {
		t.Fatalf("worktree path=%q want %q", got, want)
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

func TestTeamBootstrapInRepoLayoutOnlyCreatesSharedLayoutWithoutIdentity(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	t.Chdir(repoDir)
	teamBootstrapLayoutOnly = true
	teamBootstrapSkipRoles = true
	teamBootstrapSkipInstructions = true

	var out bytes.Buffer
	cmd := testTeamBootstrapCommand(t)
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runTeamBootstrap(cmd, []string{templateDir}); err != nil {
		t.Fatalf("runTeamBootstrap: %v", err)
	}
	assertPathExists(t, filepath.Join(repoDir, "agents", "team.yaml"))
	assertPathExists(t, filepath.Join(repoDir, "agents", "home", "coordinator", "AGENTS.md"))
	assertPathExists(t, filepath.Join(repoDir, "agents", "worktrees", "implementation"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "coordinator", ".aw"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "implementation", ".aw"))
	gitignore, err := os.ReadFile(filepath.Join(repoDir, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"/agents/home/*/.aw/", "/agents/home/*/work", "/agents/worktrees/"} {
		if !strings.Contains(string(gitignore), want) {
			t.Fatalf(".gitignore missing %q:\n%s", want, string(gitignore))
		}
	}
}

func TestTeamBootstrapDryRunUsesTemplateNamingPolicy(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	teamYAML := filepath.Join(templateDir, "team.yaml")
	data, err := os.ReadFile(teamYAML)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), "agents:\n", "naming:\n  local_alias:\n    sequence: star-name\n    pattern: \"{star-name}\"\nagents:\n", 1)
	if err := os.WriteFile(teamYAML, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	t.Chdir(repoDir)
	teamBootstrapDryRun = true
	teamBootstrapSkipRoles = true
	teamBootstrapSkipInstructions = true

	oldStdout := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	t.Cleanup(func() {
		os.Stdout = oldStdout
		_ = r.Close()
		_ = w.Close()
	})

	err = runTeamBootstrap(testTeamBootstrapCommand(t), []string{templateDir})
	_ = w.Close()
	os.Stdout = oldStdout
	if err != nil {
		t.Fatalf("runTeamBootstrap: %v", err)
	}
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	text := string(out)
	if !strings.Contains(text, "coordinator: scope=local name=sirius role=coordinator alias=sirius") {
		t.Fatalf("bootstrap output did not use star-name naming policy:\n%s", text)
	}
	expectedRepoDir, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "work="+filepath.Join(expectedRepoDir, "agents", "worktrees", "implementation")+" (git_worktree)") {
		t.Fatalf("bootstrap output did not use responsibility worktree naming policy:\n%s", text)
	}
	if !strings.Contains(text, "team_alias: available") {
		t.Fatalf("bootstrap output missing availability checks:\n%s", text)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents"))
}

func TestAgentsProvisionPlanReadsExistingLayoutAndUsesIdentityPrefix(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsIdentityPrefix = "maria"

	out, layout, _, plans, err := buildAgentsProvisionOutput(&cobra.Command{Use: "plan"})
	if err != nil {
		t.Fatalf("buildAgentsProvisionOutput: %v", err)
	}
	expectedRepoDir, err := filepath.EvalSymlinks(repoDir)
	if err != nil {
		t.Fatal(err)
	}
	if layout.CustomerRepoRoot != expectedRepoDir {
		t.Fatalf("repo root=%q, want %q", layout.CustomerRepoRoot, expectedRepoDir)
	}
	if out.IdentityPrefix != "maria" {
		t.Fatalf("identity_prefix=%q, want maria", out.IdentityPrefix)
	}
	if len(plans) != 2 {
		t.Fatalf("plans=%d, want 2", len(plans))
	}
	byResponsibility := map[string]teamBootstrapAgentPlan{}
	for _, plan := range plans {
		byResponsibility[plan.Responsibility] = plan
	}
	if got := byResponsibility["coordinator"].Alias; got != "alice" {
		t.Fatalf("coordinator alias=%q, want alice", got)
	}
	if got := byResponsibility["implementation"].Alias; got != "bob" {
		t.Fatalf("implementation alias=%q, want bob", got)
	}
	if got := byResponsibility["coordinator"].HomeDir; got != filepath.Join(expectedRepoDir, "agents", "home", "coordinator") {
		t.Fatalf("coordinator home=%q", got)
	}
	if got := byResponsibility["implementation"].WorkDir; got != filepath.Join(expectedRepoDir, "agents", "worktrees", "implementation") {
		t.Fatalf("implementation workdir=%q, want responsibility-based worktree path", got)
	}
	if !agentsProvisionHasCheck(out, "implementation", "worktree", "implementation", "available") {
		t.Fatalf("implementation worktree availability missing: %#v", out.Availability)
	}
	formatted := formatAgentsProvisionOutput(out)
	if !strings.Contains(formatted, "Agents provision plan (dry run)") ||
		!strings.Contains(formatted, "Identity prefix: maria") ||
		!strings.Contains(formatted, "worktree: available") {
		t.Fatalf("formatted provision plan missing expected content:\n%s", formatted)
	}
	assertPathMissing(t, filepath.Join(repoDir, ".aw"))
}

func TestTeamBootstrapHostedPrimaryGlobalRequestsPersistentIdentity(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	home := filepath.Join(t.TempDir(), "coordinator")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	oldWizard := guidedOnboardingWizard
	t.Cleanup(func() { guidedOnboardingWizard = oldWizard })
	var got guidedOnboardingRequest
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		got = req
		return &guidedOnboardingResult{}, nil
	}

	err := initTeamBootstrapPrimaryAgent(&cobra.Command{}, teamBootstrapSource{Kind: teamBootstrapSourceHostedNew}, teamBootstrapAgentPlan{
		HomeDir:        home,
		Alias:          "juan-alice",
		RoleName:       "coordinator",
		IdentityScope:  agentsIdentityScopeGlobal,
		GlobalAddress:  "juan.aweb.ai/juan-coordinator",
		Responsibility: "coordinator",
	})
	if err != nil {
		t.Fatalf("initTeamBootstrapPrimaryAgent: %v", err)
	}
	if !got.Persistent {
		t.Fatalf("hosted global primary did not request persistent identity: %+v", got)
	}
	if got.Alias != "juan-alice" || got.Role != "coordinator" {
		t.Fatalf("unexpected onboarding request: %+v", got)
	}
}

func TestAgentsProvisionLocalOnlyLayoutAllowsMissingIdentityPrefix(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("AWEB_IDENTITY_PREFIX", "")
	t.Setenv("AWEB_HUMAN", "")
	t.Setenv("USER", "")
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)

	out, _, _, _, err := buildAgentsProvisionOutput(&cobra.Command{Use: "plan"})
	if err != nil {
		t.Fatalf("buildAgentsProvisionOutput: %v", err)
	}
	if out.IdentityPrefix != "" {
		t.Fatalf("identity_prefix=%q, want empty for local-only layout", out.IdentityPrefix)
	}
}

func TestAgentsProvisionGlobalLayoutRequiresIdentityPrefix(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("AWEB_IDENTITY_PREFIX", "")
	t.Setenv("AWEB_HUMAN", "")
	t.Setenv("USER", "")
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	agentsDir := filepath.Join(repoDir, "agents")
	if err := copyDir(templateDir, agentsDir); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	teamYAML := `name: in-repo-team
instructions:
  file: docs/team.md
roles:
  coordinator:
    title: Coordinator
    file: roles/coordinator.md
agents:
  coordinator:
    role_name: coordinator
    identity_scope: global
    home_template: home/coordinator
    work: repo_root
`
	if err := os.WriteFile(filepath.Join(agentsDir, "team.yaml"), []byte(teamYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoDir)

	_, _, _, _, err := buildAgentsProvisionOutput(&cobra.Command{Use: "plan"})
	if err == nil {
		t.Fatal("expected missing identity prefix to fail")
	}
	if !strings.Contains(err.Error(), "identity prefix is required") ||
		!strings.Contains(err.Error(), "--identity-prefix") ||
		!strings.Contains(err.Error(), "AWEB_IDENTITY_PREFIX") {
		t.Fatalf("error=%q, want identity-prefix guidance", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, ".aw"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "coordinator", "CLAUDE.md"))
}

func TestAgentsProvisionRejectsUsernameSource(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	teamBootstrapUsername = "maria"

	_, err := resolveAgentsProvisionSource()
	if err == nil {
		t.Fatal("expected --username to be rejected for provision")
	}
	if !strings.Contains(err.Error(), "does not create a hosted team from --username") ||
		!strings.Contains(err.Error(), "--invite-token") {
		t.Fatalf("error=%q, want provision username guidance", err)
	}
}

func TestAgentsProvisionMissingSourceFailsBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)

	cmd := &cobra.Command{Use: "provision"}
	cmd.SetIn(strings.NewReader(""))
	cmd.SetErr(&bytes.Buffer{})
	err := runAgentsProvision(cmd, nil)
	if err == nil {
		t.Fatal("expected missing team source to fail")
	}
	if !strings.Contains(err.Error(), "requires a team source") {
		t.Fatalf("error=%q, want team-source guidance", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, ".aw"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "worktrees"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "coordinator", "CLAUDE.md"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "coordinator", "work"))
}

func TestAgentsProvisionAcceptsMatchingExistingAWState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	root := t.TempDir()
	coordinator := filepath.Join(root, "agents", "home", "coordinator")
	developer := filepath.Join(root, "agents", "home", "developer")
	writeWorkspaceBindingForTest(t, coordinator, workspaceBinding("https://app.example", "circle:example.com", "alice", "workspace-alice"))
	writeWorkspaceBindingForTest(t, developer, workspaceBinding("https://app.example", "circle:example.com", "bob", "workspace-bob"))

	state, err := assessAgentsProvisionState([]teamBootstrapAgentPlan{
		{Responsibility: "coordinator", HomeDir: coordinator, Alias: "alice"},
		{Responsibility: "developer", HomeDir: developer, Alias: "bob"},
	}, "circle:example.com")
	if err != nil {
		t.Fatalf("assessAgentsProvisionState: %v", err)
	}
	if state != agentsProvisionStateAlreadyProvisioned {
		t.Fatalf("state=%v, want already provisioned", state)
	}
}

func TestAgentsProvisionRefusesPartialAWState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	root := t.TempDir()
	coordinator := filepath.Join(root, "agents", "home", "coordinator")
	developer := filepath.Join(root, "agents", "home", "developer")
	writeWorkspaceBindingForTest(t, coordinator, workspaceBinding("https://app.example", "circle:example.com", "alice", "workspace-alice"))
	if err := os.MkdirAll(developer, 0o755); err != nil {
		t.Fatal(err)
	}

	_, err := assessAgentsProvisionState([]teamBootstrapAgentPlan{
		{Responsibility: "coordinator", HomeDir: coordinator, Alias: "alice"},
		{Responsibility: "developer", HomeDir: developer, Alias: "bob"},
	}, "circle:example.com")
	if err == nil {
		t.Fatal("expected partial .aw state to fail")
	}
	if !strings.Contains(err.Error(), "partially provisioned") ||
		!strings.Contains(err.Error(), "does not auto-recover partial state") {
		t.Fatalf("error=%q, want partial-state guidance", err)
	}
}

func TestAgentsProvisionRefusesMismatchedExistingAWState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	home := filepath.Join(t.TempDir(), "agents", "home", "developer")
	writeWorkspaceBindingForTest(t, home, workspaceBinding("https://app.example", "circle:example.com", "charlie", "workspace-charlie"))

	_, err := assessAgentsProvisionState([]teamBootstrapAgentPlan{{
		Responsibility: "developer",
		HomeDir:        home,
		Alias:          "bob",
	}}, "circle:example.com")
	if err == nil {
		t.Fatal("expected mismatched .aw state to fail")
	}
	if !strings.Contains(err.Error(), "already belongs to alias") ||
		!strings.Contains(err.Error(), "does not merge mismatched identity state") {
		t.Fatalf("error=%q, want mismatch guidance", err)
	}
}

func TestAgentsAddLayoutOnlyAddsLocalAgentBlueprint(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsAddLayoutOnly = true
	agentsAddRole = "analyst"

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "add"}
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	if err := runAgentsAdd(cmd, []string{"analyst"}); err != nil {
		t.Fatalf("runAgentsAdd: %v\n%s", err, out.String())
	}
	spec, err := loadTeamBootstrapSpec(filepath.Join(repoDir, "agents"))
	if err != nil {
		t.Fatalf("load spec: %v", err)
	}
	agent, ok := spec.Agents["analyst"]
	if !ok {
		t.Fatalf("analyst agent missing from spec: %#v", spec.Agents)
	}
	if agent.RoleName != "analyst" || agent.IdentityScope != agentsIdentityScopeLocal || agent.HomeTemplate != "home/analyst" || agent.Work != agentsWorkRepoRoot {
		t.Fatalf("agent spec mismatch: %#v", agent)
	}
	role, ok := spec.Roles["analyst"]
	if !ok || role.File != "roles/analyst.md" {
		t.Fatalf("analyst role mismatch: %#v", spec.Roles["analyst"])
	}
	assertPathExists(t, filepath.Join(repoDir, "agents", "roles", "analyst.md"))
	assertPathExists(t, filepath.Join(repoDir, "agents", "home", "analyst", "AGENTS.md"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "analyst", ".aw"))
	data, err := os.ReadFile(filepath.Join(repoDir, "agents", "team.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "default_alias") || strings.Contains(string(data), "default_name") {
		t.Fatalf("team.yaml contains legacy default identity fields:\n%s", string(data))
	}
}

func TestAgentsAddLocalProvisionsAfterLayoutMaterialization(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	teamBootstrapInviteToken = "aw-invite-test-token"

	var sawPlan teamBootstrapAgentPlan
	var sawSource teamBootstrapSource
	agentsAddInitPrimaryAgent = func(cmd *cobra.Command, source teamBootstrapSource, plan teamBootstrapAgentPlan) error {
		sawSource = source
		sawPlan = plan
		assertPathExists(t, filepath.Join(plan.HomeDir, "AGENTS.md"))
		assertPathExists(t, filepath.Join(plan.HomeDir, "CLAUDE.md"))
		assertPathExists(t, filepath.Join(plan.HomeDir, "work"))
		if err := os.MkdirAll(filepath.Join(plan.HomeDir, ".aw"), 0o700); err != nil {
			return err
		}
		return nil
	}
	agentsAddInitAdditionalAgent = func(primaryDir string, plan teamBootstrapAgentPlan) error {
		t.Fatalf("additional-agent path should not run: primary=%s plan=%+v", primaryDir, plan)
		return nil
	}

	if err := runAgentsAdd(&cobra.Command{Use: "add"}, []string{"support"}); err != nil {
		t.Fatalf("runAgentsAdd: %v", err)
	}
	if sawSource.Kind != teamBootstrapSourceInvite {
		t.Fatalf("source kind=%q want invite", sawSource.Kind)
	}
	if sawPlan.Responsibility != "support" || sawPlan.IdentityScope != agentsIdentityScopeLocal || sawPlan.GlobalAddress != "" {
		t.Fatalf("plan mismatch: %+v", sawPlan)
	}
	assertPathExists(t, filepath.Join(repoDir, "agents", "home", "support", ".aw"))
	spec, err := loadTeamBootstrapSpec(filepath.Join(repoDir, "agents"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Agents["support"]; !ok {
		t.Fatalf("support missing from team.yaml: %#v", spec.Agents)
	}
}

func TestAgentsAddUsesTemplateNamingPolicy(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	teamYAML := filepath.Join(repoDir, "agents", "team.yaml")
	data, err := os.ReadFile(teamYAML)
	if err != nil {
		t.Fatal(err)
	}
	updated := strings.Replace(string(data), "agents:\n", "naming:\n  local_alias:\n    sequence: star-name\n    pattern: \"{star-name}\"\nagents:\n", 1)
	if err := os.WriteFile(teamYAML, []byte(updated), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoDir)

	out, _, _, plan, err := buildAgentsAddOutput(&cobra.Command{Use: "add"}, "support", agentsWorkRepoRoot)
	if err != nil {
		t.Fatalf("buildAgentsAddOutput: %v", err)
	}
	if plan.Alias != "sirius" {
		t.Fatalf("alias=%q want template star-name policy first candidate sirius", plan.Alias)
	}
	if !agentsProvisionHasCheck(agentsProvisionOutput{Availability: out.Availability}, "support", "team_alias", "sirius", "available") {
		t.Fatalf("availability missing sirius team_alias check: %+v", out.Availability)
	}
}

func TestAgentsAddWorktreeRequiresRoleNonTTYBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	server := newAgentsAddWorktreeTestServer(t, nil)
	seedAgentsAddWorktreeAnchor(t, repoDir, server.URL, "default:example.aweb.ai", "aw_sk_parent")

	cmd := &cobra.Command{Use: "add-worktree"}
	cmd.SetIn(strings.NewReader(""))
	err := runAgentsAddWorktree(cmd, nil)
	if err == nil {
		t.Fatal("expected role error")
	}
	if !strings.Contains(err.Error(), "no role specified") || !strings.Contains(err.Error(), "developer") {
		t.Fatalf("error=%q, want role guidance", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "worktrees", "qa"))
}

func TestAgentsAddWorktreeRejectsUnknownRoleBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	server := newAgentsAddWorktreeTestServer(t, nil)
	seedAgentsAddWorktreeAnchor(t, repoDir, server.URL, "default:example.aweb.ai", "aw_sk_parent")

	err := runAgentsAddWorktree(&cobra.Command{Use: "add-worktree"}, []string{"qa"})
	if err == nil {
		t.Fatal("expected unknown role error")
	}
	if !strings.Contains(err.Error(), "invalid role") || !strings.Contains(err.Error(), "developer") {
		t.Fatalf("error=%q, want role validation", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "worktrees", "qa"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "roles", "qa.md"))
}

func TestAgentsAddWorktreeCreatesWorkspaceInsideWorktreeWithoutLayoutMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	teamYAMLPath := filepath.Join(repoDir, "agents", "team.yaml")
	beforeTeamYAML, err := os.ReadFile(teamYAMLPath)
	if err != nil {
		t.Fatal(err)
	}
	var initBody map[string]any
	server := newAgentsAddWorktreeTestServer(t, &initBody)
	seedAgentsAddWorktreeAnchor(t, repoDir, server.URL, "default:example.aweb.ai", "aw_sk_parent")

	if err := runAgentsAddWorktree(&cobra.Command{Use: "add-worktree"}, []string{"developer"}); err != nil {
		t.Fatalf("runAgentsAddWorktree: %v", err)
	}
	worktree := filepath.Join(repoDir, "agents", "worktrees", "qa")
	assertPathExists(t, filepath.Join(worktree, ".aw", "workspace.yaml"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "qa"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "roles", "qa.md"))
	afterTeamYAML, err := os.ReadFile(teamYAMLPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterTeamYAML) != string(beforeTeamYAML) {
		t.Fatalf("add-worktree mutated team.yaml:\n--- before ---\n%s\n--- after ---\n%s", beforeTeamYAML, afterTeamYAML)
	}
	if got := strings.TrimSpace(fmt.Sprint(initBody["alias"])); got != "qa" {
		t.Fatalf("workspace init alias=%q want qa (body=%v)", got, initBody)
	}
	if got := strings.TrimSpace(fmt.Sprint(initBody["role_name"])); got != "developer" {
		t.Fatalf("workspace init role_name=%q want developer (body=%v)", got, initBody)
	}
}

func newAgentsAddWorktreeTestServer(t *testing.T, initBody *map[string]any) *httptest.Server {
	t.Helper()
	const teamID = "default:example.aweb.ai"
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = awid.ComputeDIDKey(teamPub)
	return newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "roles-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
					"reviewer":  map[string]any{"title": "Reviewer"},
				},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/suggest-alias-prefix":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":     teamID,
				"name_prefix": "qa",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			if got := strings.TrimSpace(r.Header.Get("Authorization")); got != "Bearer aw_sk_parent" {
				t.Fatalf("Authorization=%q, want parent API key", got)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if initBody != nil {
				*initBody = body
			}
			didKey := strings.TrimSpace(fmt.Sprint(body["did"]))
			alias := strings.TrimSpace(fmt.Sprint(body["alias"]))
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         teamID,
				MemberDIDKey: didKey,
				Alias:        alias,
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_url":     "http://" + r.Host + "/api",
				"team_cert":      encoded,
				"alias":          alias,
				"team_id":        teamID,
				"workspace_id":   "workspace-qa",
				"did":            didKey,
				"stable_id":      "",
				"identity_scope": awid.IdentityModeLocal,
				"custody":        awid.CustodySelf,
				"api_key":        "aw_sk_child",
			})
		case r.Method == http.MethodPost && (r.URL.Path == "/v1/connect" || r.URL.Path == "/api/v1/connect"):
			cert := requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      teamID,
				"alias":        cert.Alias,
				"agent_id":     "agent-" + cert.Alias,
				"workspace_id": "workspace-" + cert.Alias,
				"repo_id":      "repo-" + cert.Alias,
				"team_did_key": cert.TeamDIDKey,
				"role":         "developer",
				"status":       "ok",
			})
		default:
			http.NotFound(w, r)
		}
	}))
}

func seedAgentsAddWorktreeAnchor(t *testing.T, repoDir, serverURL, teamID, apiKey string) {
	t.Helper()
	anchor := filepath.Join(repoDir, "agents", "home", "coordinator")
	if err := os.MkdirAll(anchor, 0o755); err != nil {
		t.Fatal(err)
	}
	state := workspaceBinding(serverURL, teamID, "coordinator", "workspace-parent")
	state.APIKey = apiKey
	writeWorkspaceBindingForTest(t, anchor, state)
}

func TestAgentsAddWorktreeRejectsGlobalBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsAddGlobal = true
	agentsIdentityPrefix = "juan"
	teamBootstrapNamespace = "example.com"
	teamBootstrapTeamName = "circle"
	teamBootstrapRegistryURL = agentsAddEmptyPreflightRegistry(t)

	err := runAgentsAddWorktree(&cobra.Command{Use: "add-worktree"}, []string{"support"})
	if err == nil {
		t.Fatal("expected global add-worktree rejection")
	}
	if !strings.Contains(err.Error(), "add-worktree --global is not supported") {
		t.Fatalf("error=%q, want global add-worktree guidance", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "worktrees", "support"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "support"))
	data, err := os.ReadFile(filepath.Join(repoDir, "agents", "team.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "support") {
		t.Fatalf("team.yaml mutated before global+worktree rejection:\n%s", string(data))
	}
}

func TestAgentsRemoveDryRunDoesNotMutate(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsRemoveRemoveLayout = true
	teamBootstrapDryRun = true

	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	assertPathExists(t, filepath.Join(repoDir, "agents", "home", "coordinator", "AGENTS.md"))
	spec, err := loadTeamBootstrapSpec(filepath.Join(repoDir, "agents"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Agents["coordinator"]; !ok {
		t.Fatalf("coordinator removed during dry-run: %#v", spec.Agents)
	}
}

func TestAgentsRemoveWorktreeDeprovisionMovesLocalStateAndRemovesWorktree(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	worktreePath := filepath.Join(repoDir, "agents", "worktrees", "implementation")
	if err := os.MkdirAll(filepath.Dir(worktreePath), 0o755); err != nil {
		t.Fatal(err)
	}
	branchCreated, err := createWorkspaceGitWorktree(repoDir, worktreePath, "implementation", true)
	if err != nil {
		t.Fatalf("create fixture worktree: %v", err)
	}
	if !branchCreated {
		t.Fatal("expected fixture worktree branch to be created")
	}
	awDir := filepath.Join(repoDir, "agents", "worktrees", "implementation", ".aw")
	if err := os.MkdirAll(awDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "marker"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	agentsRemoveDeprovisionLocal = true
	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"implementation"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "worktrees", "implementation", ".aw"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "worktrees", "implementation"))
	spec, err := loadTeamBootstrapSpec(filepath.Join(repoDir, "agents"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Agents["implementation"]; !ok {
		t.Fatalf("deprovision-local should preserve layout entry: %#v", spec.Agents)
	}
	backupRoot, err := awconfig.PathInAWIDState("agents-remove-backups")
	if err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(backupRoot, "*-implementation-*", ".aw", "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one moved .aw marker under %s, got %v", backupRoot, matches)
	}
}

func TestAgentsRemoveWorktreeDeprovisionHandlesLegacyHomeState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	worktreePath := filepath.Join(repoDir, "agents", "worktrees", "implementation")
	if err := os.MkdirAll(filepath.Dir(worktreePath), 0o755); err != nil {
		t.Fatal(err)
	}
	branchCreated, err := createWorkspaceGitWorktree(repoDir, worktreePath, "implementation", true)
	if err != nil {
		t.Fatalf("create fixture worktree: %v", err)
	}
	if !branchCreated {
		t.Fatal("expected fixture worktree branch to be created")
	}
	legacyAWDir := filepath.Join(repoDir, "agents", "home", "implementation", ".aw")
	if err := os.MkdirAll(legacyAWDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(legacyAWDir, "marker"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}

	plan, err := buildAgentsRemovePlan("implementation")
	if err != nil {
		t.Fatal(err)
	}
	expectedLegacyHome, err := filepath.EvalSymlinks(filepath.Join(repoDir, "agents", "home", "implementation"))
	if err != nil {
		t.Fatal(err)
	}
	if plan.Output.WorkspaceDir != expectedLegacyHome {
		t.Fatalf("workspace_dir=%q want legacy home %q", plan.Output.WorkspaceDir, expectedLegacyHome)
	}
	if len(plan.Output.Warnings) == 0 || !strings.Contains(strings.Join(plan.Output.Warnings, "\n"), "legacy worktree .aw state") {
		t.Fatalf("warnings=%v, want legacy migration warning", plan.Output.Warnings)
	}

	agentsRemoveDeprovisionLocal = true
	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"implementation"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "implementation", ".aw"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "worktrees", "implementation"))
	backupRoot, err := awconfig.PathInAWIDState("agents-remove-backups")
	if err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(backupRoot, "*-implementation-*", ".aw", "marker"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected one moved legacy .aw marker under %s, got %v", backupRoot, matches)
	}
}

func TestAgentsRemoveLayoutMovesHomeAndRemovesSpec(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsRemoveRemoveLayout = true

	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"implementation"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "implementation"))
	spec, err := loadTeamBootstrapSpec(filepath.Join(repoDir, "agents"))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := spec.Agents["implementation"]; ok {
		t.Fatalf("implementation remained in team.yaml after remove-layout: %#v", spec.Agents["implementation"])
	}
	backupRoot, err := awconfig.PathInAWIDState("agents-remove-backups")
	if err != nil {
		t.Fatal(err)
	}
	matches, err := filepath.Glob(filepath.Join(backupRoot, "*-implementation-*", "implementation", "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 1 {
		t.Fatalf("expected moved home under %s, got %v", backupRoot, matches)
	}
}

type testAgentsLayoutLock struct {
	closed *bool
}

func (l testAgentsLayoutLock) Close() error {
	if l.closed != nil {
		*l.closed = true
	}
	return nil
}

func TestAgentsRemoveUsesLayoutLockForMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsRemoveRemoveLayout = true
	layout, err := resolveAgentsExistingLayoutPreflight()
	if err != nil {
		t.Fatalf("resolve layout: %v", err)
	}

	var gotLockPath string
	closed := false
	agentsLockExclusive = func(lockPath string) (agentsLayoutLock, error) {
		gotLockPath = lockPath
		return testAgentsLayoutLock{closed: &closed}, nil
	}
	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	wantLockPath := agentsAddLayoutLockPath(layout.AgentsRoot)
	if gotLockPath != wantLockPath {
		t.Fatalf("lock path=%q want %q", gotLockPath, wantLockPath)
	}
	if !closed {
		t.Fatal("layout lock was not closed")
	}
}

func TestAgentsRemoveLayoutWarnsWhenMovingActiveAWWithoutDeprovision(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	if err := os.MkdirAll(filepath.Join(home, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoDir)
	agentsRemoveRemoveLayout = true

	plan, err := buildAgentsRemovePlan("coordinator")
	if err != nil {
		t.Fatalf("buildAgentsRemovePlan: %v", err)
	}
	if len(plan.Output.Warnings) == 0 {
		t.Fatal("expected warning for active .aw layout removal")
	}
	if !strings.Contains(strings.Join(plan.Output.Warnings, "\n"), "without revoking membership") {
		t.Fatalf("warnings=%v, want active .aw remove-layout warning", plan.Output.Warnings)
	}
}

func TestAgentsRemoveLayoutWriteFailureGuidesRetry(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsRemoveRemoveLayout = true
	writeAgentsAddLayoutYAML = func(layout teamBootstrapLayout, spec *teamBootstrapSpec) error {
		return os.ErrPermission
	}

	err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"implementation"})
	if err == nil {
		t.Fatal("expected layout write failure")
	}
	text := err.Error()
	for _, want := range []string{"retry `aw agents remove --remove-layout implementation`", "backup", "restore the backup"} {
		if !strings.Contains(text, want) {
			t.Fatalf("error=%q missing %q", text, want)
		}
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "implementation"))
	data, readErr := os.ReadFile(filepath.Join(repoDir, "agents", "team.yaml"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if !strings.Contains(string(data), "implementation:") {
		t.Fatalf("team.yaml unexpectedly changed after write failure:\n%s", string(data))
	}
}

func TestAgentsRemoveMissingTeamKeyFailsBeforeMovingLocalState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	_, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(signingKey, awid.TeamCertificateFields{
		Team:          "circle:example.com",
		MemberDIDKey:  "did:key:ztest",
		MemberAddress: "example.com/juan-coordinator",
		Alias:         "juan-coordinator",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(home, cert.Team, cert); err != nil {
		t.Fatalf("save cert: %v", err)
	}
	if err := awconfig.SaveTeamState(home, &awconfig.TeamState{
		ActiveTeam: cert.Team,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   cert.Team,
			Alias:    cert.Alias,
			CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
		}},
	}); err != nil {
		t.Fatalf("save team state: %v", err)
	}
	t.Chdir(repoDir)
	agentsRemoveDeprovisionLocal = true

	err = runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"})
	if err == nil {
		t.Fatal("expected missing team key to fail")
	}
	if !strings.Contains(err.Error(), "team controller key is unavailable") {
		t.Fatalf("error=%q, want team-controller guidance", err)
	}
	assertPathExists(t, filepath.Join(home, ".aw", "teams.yaml"))
	assertPathExists(t, awconfig.TeamCertificatePath(home, "circle:example.com"))
}

func TestAgentsRemoveDeleteAddressRequiresCertificateBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:       "did:key:ztest",
		StableID:  "did:aw:test-global",
		Address:   "example.com/juan-coordinator",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.IdentityModeGlobal,
		CreatedAt: "2026-06-07T00:00:00Z",
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	if err := awconfig.SaveTeamState(home, &awconfig.TeamState{
		ActiveTeam: "circle:example.com",
		Memberships: []awconfig.TeamMembership{{
			TeamID:   "circle:example.com",
			Alias:    "juan-coordinator",
			CertPath: awconfig.TeamCertificateRelativePath("circle:example.com"),
		}},
	}); err != nil {
		t.Fatalf("save team state: %v", err)
	}

	t.Chdir(repoDir)
	agentsRemoveDeprovisionLocal = true
	agentsRemoveDeleteAddress = true
	err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"})
	if err == nil {
		t.Fatal("expected missing certificate to fail before deleting address")
	}
	if !strings.Contains(err.Error(), "no active team certificate") {
		t.Fatalf("error=%q, want missing certificate guidance", err)
	}
	assertPathExists(t, filepath.Join(home, ".aw", "identity.yaml"))
	assertPathExists(t, filepath.Join(home, ".aw", "teams.yaml"))
}

func TestAgentsRemoveHostedCertOnlyDeprovisionUsesServiceEndpoint(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(home), memberKey); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "circle:example.com",
		MemberDIDKey:  awid.ComputeDIDKey(memberPub),
		MemberDIDAW:   "did:aw:test-hosted-global",
		MemberAddress: "example.com/juan-coordinator",
		Alias:         "juan-coordinator",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(home, cert.Team, cert); err != nil {
		t.Fatalf("save cert: %v", err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:       cert.MemberDIDKey,
		StableID:  cert.MemberDIDAW,
		Address:   cert.MemberAddress,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.IdentityModeGlobal,
		CreatedAt: "2026-06-07T00:00:00Z",
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/me/deprovision" {
			t.Fatalf("unexpected hosted request: %s %s", r.Method, r.URL.Path)
		}
		if strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) == "" {
			t.Fatal("missing hosted team certificate header")
		}
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); !strings.HasPrefix(auth, "DIDKey "+cert.MemberDIDKey+" ") {
			t.Fatalf("Authorization=%q, want DIDKey for %s", auth, cert.MemberDIDKey)
		}
		assertPathExists(t, filepath.Join(home, ".aw", "teams.yaml"))
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"agent_id": "agent-hosted-global",
			"status":   "archived",
		})
	}))
	t.Cleanup(server.Close)
	if err := awconfig.SaveTeamState(home, &awconfig.TeamState{
		ActiveTeam: cert.Team,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   cert.Team,
			Alias:    cert.Alias,
			CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
			AwebURL:  server.URL,
		}},
	}); err != nil {
		t.Fatalf("save team state: %v", err)
	}

	t.Chdir(repoDir)
	agentsRemoveDeprovisionLocal = true
	agentsRemoveDeleteAddress = true
	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	if gotBody["delete_global_address"] != true {
		t.Fatalf("delete_global_address=%v, want true", gotBody["delete_global_address"])
	}
	assertPathMissing(t, filepath.Join(home, ".aw"))
}

func TestAgentsRemoveHostedAlreadyDeprovisionedMovesLocalState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(home), memberKey); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "circle:example.com",
		MemberDIDKey:  awid.ComputeDIDKey(memberPub),
		MemberDIDAW:   "did:aw:test-hosted-global",
		MemberAddress: "example.com/juan-coordinator",
		Alias:         "juan-coordinator",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(home, cert.Team, cert); err != nil {
		t.Fatalf("save cert: %v", err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:       cert.MemberDIDKey,
		StableID:  cert.MemberDIDAW,
		Address:   cert.MemberAddress,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.IdentityModeGlobal,
		CreatedAt: "2026-06-07T00:00:00Z",
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/me/deprovision" {
			t.Fatalf("unexpected hosted request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": map[string]string{
				"code":    "agent_not_found",
				"message": "Agent not found",
			},
		})
	}))
	t.Cleanup(server.Close)
	if err := awconfig.SaveTeamState(home, &awconfig.TeamState{
		ActiveTeam: cert.Team,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   cert.Team,
			Alias:    cert.Alias,
			CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
			AwebURL:  server.URL,
		}},
	}); err != nil {
		t.Fatalf("save team state: %v", err)
	}

	t.Chdir(repoDir)
	agentsRemoveDeprovisionLocal = true
	agentsRemoveDeleteAddress = true
	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	assertPathMissing(t, filepath.Join(home, ".aw"))
}

func TestAgentsRemoveHostedProseNotTreatedAsAlreadyDeprovisioned(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(home), memberKey); err != nil {
		t.Fatalf("save signing key: %v", err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "circle:example.com",
		MemberDIDKey:  awid.ComputeDIDKey(memberPub),
		MemberDIDAW:   "did:aw:test-hosted-global",
		MemberAddress: "example.com/juan-coordinator",
		Alias:         "juan-coordinator",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(home, cert.Team, cert); err != nil {
		t.Fatalf("save cert: %v", err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(home, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:       cert.MemberDIDKey,
		StableID:  cert.MemberDIDAW,
		Address:   cert.MemberAddress,
		Custody:   awid.CustodySelf,
		Lifetime:  awid.IdentityModeGlobal,
		CreatedAt: "2026-06-07T00:00:00Z",
	}); err != nil {
		t.Fatalf("save identity: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/api/v1/agents/me/deprovision" {
			t.Fatalf("unexpected hosted request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"detail": "Agent not found"})
	}))
	t.Cleanup(server.Close)
	if err := awconfig.SaveTeamState(home, &awconfig.TeamState{
		ActiveTeam: cert.Team,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   cert.Team,
			Alias:    cert.Alias,
			CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
			AwebURL:  server.URL,
		}},
	}); err != nil {
		t.Fatalf("save team state: %v", err)
	}

	t.Chdir(repoDir)
	agentsRemoveDeprovisionLocal = true
	agentsRemoveDeleteAddress = true
	err = runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"})
	if err == nil {
		t.Fatal("expected unstructured hosted error to fail")
	}
	assertPathExists(t, filepath.Join(home, ".aw"))
}

func TestAgentsRemoveDeprovisionRevokesBeforeMovingLocalState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	homeRoot := t.TempDir()
	t.Setenv("HOME", homeRoot)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, homeRoot, "example.com", "circle", teamKey)
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "circle:example.com",
		MemberDIDKey:  "did:key:ztest",
		MemberAddress: "example.com/juan-coordinator",
		Alias:         "juan-coordinator",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(home, cert.Team, cert); err != nil {
		t.Fatalf("save cert: %v", err)
	}
	if err := awconfig.SaveTeamState(home, &awconfig.TeamState{
		ActiveTeam: cert.Team,
		Memberships: []awconfig.TeamMembership{{
			TeamID:      cert.Team,
			Alias:       cert.Alias,
			CertPath:    awconfig.TeamCertificateRelativePath(cert.Team),
			RegistryURL: "override-by-test",
		}},
	}); err != nil {
		t.Fatalf("save team state: %v", err)
	}
	var gotRevoke map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/example.com/teams/circle/certificates/revoke" {
			t.Fatalf("unexpected registry request: %s %s", r.Method, r.URL.Path)
		}
		assertPathExists(t, filepath.Join(home, ".aw", "teams.yaml"))
		if err := json.NewDecoder(r.Body).Decode(&gotRevoke); err != nil {
			t.Fatal(err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	teamState, err := awconfig.LoadTeamState(home)
	if err != nil {
		t.Fatal(err)
	}
	teamState.Memberships[0].RegistryURL = server.URL
	if err := awconfig.SaveTeamState(home, teamState); err != nil {
		t.Fatal(err)
	}

	t.Chdir(repoDir)
	agentsRemoveDeprovisionLocal = true
	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	if gotRevoke["certificate_id"] != cert.CertificateID {
		t.Fatalf("revoke certificate_id=%v want %s", gotRevoke["certificate_id"], cert.CertificateID)
	}
	assertPathMissing(t, filepath.Join(home, ".aw"))
}

func TestAgentsRemoveDeleteAddressSuccessRevokesDeletesBeforeMovingLocalState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	homeRoot := t.TempDir()
	t.Setenv("HOME", homeRoot)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "coordinator")
	controllerPub, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("example.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	writeTeamKeyForTest(t, homeRoot, "example.com", "circle", teamKey)
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "circle:example.com",
		MemberDIDKey:  "did:key:ztest",
		MemberDIDAW:   "did:aw:test-global",
		MemberAddress: "example.com/juan-coordinator",
		Alias:         "juan-coordinator",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(home, cert.Team, cert); err != nil {
		t.Fatalf("save cert: %v", err)
	}
	if err := awconfig.SaveTeamState(home, &awconfig.TeamState{
		ActiveTeam: cert.Team,
		Memberships: []awconfig.TeamMembership{{
			TeamID:      cert.Team,
			Alias:       cert.Alias,
			CertPath:    awconfig.TeamCertificateRelativePath(cert.Team),
			RegistryURL: "will-be-replaced",
		}},
	}); err != nil {
		t.Fatalf("save team state: %v", err)
	}
	events := []string{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/example.com/teams/circle/certificates/revoke":
			events = append(events, "revoke")
			assertPathExists(t, filepath.Join(home, ".aw", "teams.yaml"))
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/example.com":
			events = append(events, "namespace")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-example",
				"domain":              "example.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-06-07T00:00:00Z",
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/example.com/addresses/juan-coordinator":
			events = append(events, "delete")
			assertPathExists(t, filepath.Join(home, ".aw", "teams.yaml"))
			verifyRegistrySignatureForTest(t, r, controllerPub, map[string]string{
				"domain":    "example.com",
				"name":      "juan-coordinator",
				"operation": "delete_address",
			})
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected registry request: %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	teamState, err := awconfig.LoadTeamState(home)
	if err != nil {
		t.Fatal(err)
	}
	teamState.Memberships[0].RegistryURL = server.URL
	if err := awconfig.SaveTeamState(home, teamState); err != nil {
		t.Fatal(err)
	}

	t.Chdir(repoDir)
	agentsRemoveDeprovisionLocal = true
	agentsRemoveDeleteAddress = true
	if err := runAgentsRemove(&cobra.Command{Use: "remove"}, []string{"coordinator"}); err != nil {
		t.Fatalf("runAgentsRemove: %v", err)
	}
	if strings.Join(events, ",") != "revoke,namespace,delete" {
		t.Fatalf("events=%v, want revoke, namespace, delete", events)
	}
	assertPathMissing(t, filepath.Join(home, ".aw"))
}

func TestAgentsAddGlobalRequiresIdentityPrefixBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("AWEB_IDENTITY_PREFIX", "")
	t.Setenv("AWEB_HUMAN", "")
	t.Setenv("USER", "")
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsAddGlobal = true
	agentsAddLayoutOnly = true
	teamBootstrapNamespace = "example.com"

	err := runAgentsAdd(&cobra.Command{Use: "add"}, []string{"support"})
	if err == nil {
		t.Fatal("expected missing identity prefix to fail")
	}
	if !strings.Contains(err.Error(), "identity prefix is required") {
		t.Fatalf("error=%q, want identity-prefix guidance", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "support"))
	data, err := os.ReadFile(filepath.Join(repoDir, "agents", "team.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "support") {
		t.Fatalf("team.yaml mutated before prefix preflight failed:\n%s", string(data))
	}
}

func TestAgentsAddGlobalProvisionRequiresTeamBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	t.Chdir(repoDir)
	agentsAddGlobal = true
	agentsIdentityPrefix = "juan"
	teamBootstrapNamespace = "example.com"

	err := runAgentsAdd(&cobra.Command{Use: "add"}, []string{"support"})
	if err == nil {
		t.Fatal("expected global add to require team")
	}
	if !strings.Contains(err.Error(), "--team is required") {
		t.Fatalf("error=%q, want --team guidance", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "support"))
	data, err := os.ReadFile(filepath.Join(repoDir, "agents", "team.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "support") {
		t.Fatalf("team.yaml mutated before atomic-claim guard failed:\n%s", string(data))
	}
}

func TestAgentsAddGlobalAtomicConflictCleansPendingStateBeforeLayoutMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("example.com", controllerKey); err != nil {
		t.Fatalf("save controller key: %v", err)
	}
	t.Chdir(repoDir)
	agentsAddGlobal = true
	agentsIdentityPrefix = "juan"
	teamBootstrapNamespace = "example.com"
	teamBootstrapTeamName = "circle"
	teamBootstrapRegistryURL = agentsAddEmptyPreflightRegistry(t)
	agentsAddClaimIdentityAddress = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, params awid.AtomicAddressClaimParams) (*awid.AtomicAddressClaimResult, error) {
		return nil, &awid.AtomicAddressClaimConflictError{
			StatusCode: 409,
			Code:       awid.AtomicAddressClaimCodeAddressTakenDifferentOwner,
			Message:    "taken",
		}
	}
	agentsAddEnsureGlobalCertificate = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, controllerKey, signingKey ed25519.PrivateKey, pending *agentsAddGlobalPendingState, homeDir string) (*localTeamBootstrapResult, error) {
		t.Fatal("certificate path should not run after atomic conflict")
		return nil, nil
	}

	err = runAgentsAdd(&cobra.Command{Use: "add"}, []string{"support"})
	if err == nil {
		t.Fatal("expected atomic conflict")
	}
	if !strings.Contains(err.Error(), "already claimed") {
		t.Fatalf("error=%q, want conflict recovery", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "support", ".aw"))
	assertPathMissing(t, filepath.Join(repoDir, "agents", "home", "support"))
	data, err := os.ReadFile(filepath.Join(repoDir, "agents", "team.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "support") {
		t.Fatalf("team.yaml mutated before atomic conflict was reported:\n%s", string(data))
	}
}

func TestAgentsAddGlobalProvisionsSelfCustodialAgent(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("example.com", controllerKey); err != nil {
		t.Fatalf("save controller key: %v", err)
	}
	t.Chdir(repoDir)
	agentsAddGlobal = true
	agentsIdentityPrefix = "juan"
	teamBootstrapNamespace = "example.com"
	teamBootstrapTeamName = "circle"
	teamBootstrapRegistryURL = agentsAddEmptyPreflightRegistry(t)

	claimCalled := false
	agentsAddClaimIdentityAddress = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, params awid.AtomicAddressClaimParams) (*awid.AtomicAddressClaimResult, error) {
		claimCalled = true
		if params.Domain != "example.com" || params.AddressName != "juan-support" {
			t.Fatalf("claim params=%+v", params)
		}
		if params.DIDAW == "" || params.CurrentDIDKey == "" || params.IdentitySigningKey == nil || params.NamespaceControllerSigningKey == nil {
			t.Fatalf("incomplete claim params=%+v", params)
		}
		return &awid.AtomicAddressClaimResult{Status: "claimed", Domain: params.Domain, Name: params.AddressName, DIDAW: params.DIDAW, CurrentDIDKey: params.CurrentDIDKey}, nil
	}
	agentsAddEnsureGlobalCertificate = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, controllerKey, signingKey ed25519.PrivateKey, pending *agentsAddGlobalPendingState, homeDir string) (*localTeamBootstrapResult, error) {
		_, teamKey, err := awid.GenerateKeypair()
		if err != nil {
			return nil, err
		}
		cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
			Team:          pending.TeamID,
			MemberDIDKey:  pending.CurrentDIDKey,
			MemberDIDAW:   pending.DIDAW,
			MemberAddress: pending.GlobalAddress,
			Alias:         pending.Alias,
			IdentityScope: awid.IdentityModeGlobal,
		})
		if err != nil {
			return nil, err
		}
		pending.Certificate = cert
		pending.CertificateRegistered = true
		if err := saveAgentsAddGlobalPending(homeDir, pending); err != nil {
			return nil, err
		}
		return &localTeamBootstrapResult{TeamID: pending.TeamID, Certificate: cert}, nil
	}
	agentsAddConnectGlobalAgent = func(workingDir, awebURL string, opts certificateConnectOptions) (connectOutput, error) {
		expected := filepath.Join(repoDir, "agents", "home", "support")
		gotResolved, _ := filepath.EvalSymlinks(workingDir)
		wantResolved, _ := filepath.EvalSymlinks(expected)
		if filepath.Clean(firstNonEmpty(gotResolved, workingDir)) != filepath.Clean(firstNonEmpty(wantResolved, expected)) {
			t.Fatalf("connect workingDir=%s", workingDir)
		}
		if opts.Role != "support" {
			t.Fatalf("connect role=%q", opts.Role)
		}
		return connectOutput{}, nil
	}

	if err := runAgentsAdd(&cobra.Command{Use: "add"}, []string{"support"}); err != nil {
		t.Fatalf("runAgentsAdd: %v", err)
	}
	if !claimCalled {
		t.Fatal("atomic claim was not called")
	}
	home := filepath.Join(repoDir, "agents", "home", "support")
	assertPathExists(t, filepath.Join(home, ".aw", "identity.yaml"))
	assertPathExists(t, filepath.Join(home, ".aw", "signing.key"))
	assertPathExists(t, filepath.Join(home, ".aw", "teams.yaml"))
	assertPathMissing(t, agentsAddGlobalPendingPath(home))
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(home, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	if identity.Address != "example.com/juan-support" || identity.Custody != awid.CustodySelf {
		t.Fatalf("identity=%+v", identity)
	}
	spec, err := loadTeamBootstrapSpec(filepath.Join(repoDir, "agents"))
	if err != nil {
		t.Fatal(err)
	}
	if got := spec.Agents["support"].IdentityScope; got != agentsIdentityScopeGlobal {
		t.Fatalf("support scope=%q", got)
	}
}

func TestAgentsAddGlobalRetriesAfterPostClaimLocalFailure(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	t.Setenv("HOME", t.TempDir())
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("example.com", controllerKey); err != nil {
		t.Fatalf("save controller key: %v", err)
	}
	t.Chdir(repoDir)
	agentsAddGlobal = true
	agentsIdentityPrefix = "juan"
	teamBootstrapNamespace = "example.com"
	teamBootstrapTeamName = "circle"
	teamBootstrapRegistryURL = agentsAddEmptyPreflightRegistry(t)

	claimCalls := 0
	agentsAddClaimIdentityAddress = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, params awid.AtomicAddressClaimParams) (*awid.AtomicAddressClaimResult, error) {
		claimCalls++
		return &awid.AtomicAddressClaimResult{Status: "claimed", Domain: params.Domain, Name: params.AddressName, DIDAW: params.DIDAW, CurrentDIDKey: params.CurrentDIDKey}, nil
	}
	agentsAddEnsureGlobalCertificate = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, controllerKey, signingKey ed25519.PrivateKey, pending *agentsAddGlobalPendingState, homeDir string) (*localTeamBootstrapResult, error) {
		if pending.Certificate == nil {
			_, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				return nil, err
			}
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          pending.TeamID,
				MemberDIDKey:  pending.CurrentDIDKey,
				MemberDIDAW:   pending.DIDAW,
				MemberAddress: pending.GlobalAddress,
				Alias:         pending.Alias,
				IdentityScope: awid.IdentityModeGlobal,
			})
			if err != nil {
				return nil, err
			}
			pending.Certificate = cert
		}
		pending.CertificateRegistered = true
		if err := saveAgentsAddGlobalPending(homeDir, pending); err != nil {
			return nil, err
		}
		return &localTeamBootstrapResult{TeamID: pending.TeamID, Certificate: pending.Certificate}, nil
	}
	connectCalls := 0
	agentsAddConnectGlobalAgent = func(workingDir, awebURL string, opts certificateConnectOptions) (connectOutput, error) {
		connectCalls++
		if connectCalls == 1 {
			return connectOutput{}, os.ErrPermission
		}
		return connectOutput{}, nil
	}

	err = runAgentsAdd(&cobra.Command{Use: "add"}, []string{"support"})
	if err == nil {
		t.Fatal("expected first run to fail after claim")
	}
	if !strings.Contains(err.Error(), "Retry with:") {
		t.Fatalf("error=%q, want retry guidance", err)
	}
	home := filepath.Join(repoDir, "agents", "home", "support")
	assertPathExists(t, agentsAddGlobalPendingPath(home))

	agentsIdentityPrefix = "maria"
	retryCmd := &cobra.Command{Use: "add"}
	retryCmd.Flags().String("identity-prefix", "", "")
	if err := retryCmd.Flags().Set("identity-prefix", "maria"); err != nil {
		t.Fatal(err)
	}
	out, _, _, _, err := buildAgentsAddOutput(retryCmd, "support", agentsWorkRepoRoot)
	if err != nil {
		t.Fatalf("build retry add output: %v", err)
	}
	if len(out.Warnings) != 1 || !strings.Contains(out.Warnings[0], "using pending identity prefix juan") || !strings.Contains(out.Warnings[0], "--identity-prefix maria is ignored") {
		t.Fatalf("retry warnings=%v, want pending-prefix warning", out.Warnings)
	}
	if out.IdentityPrefix != "juan" {
		t.Fatalf("retry identity prefix=%q, want pending juan", out.IdentityPrefix)
	}

	if err := runAgentsAdd(retryCmd, []string{"support"}); err != nil {
		t.Fatalf("retry runAgentsAdd: %v", err)
	}
	if claimCalls != 1 {
		t.Fatalf("claimCalls=%d, want 1", claimCalls)
	}
	if connectCalls != 2 {
		t.Fatalf("connectCalls=%d, want 2", connectCalls)
	}
	assertPathMissing(t, agentsAddGlobalPendingPath(home))
	assertPathExists(t, filepath.Join(home, ".aw", "identity.yaml"))
}

func TestAgentsAddGlobalConflictCodeCoverage(t *testing.T) {
	for _, code := range awid.AtomicAddressClaimConflictCodes {
		if agentsAddGlobalSpecificConflictCodes[code] && agentsAddGlobalDefaultConflictCodes[code] {
			t.Fatalf("conflict code %s is both specifically handled and default-handled", code)
		}
		if !agentsAddGlobalSpecificConflictCodes[code] && !agentsAddGlobalDefaultConflictCodes[code] {
			t.Fatalf("conflict code %s is not covered by agents add --global consumer maps", code)
		}
	}
	known := map[string]bool{}
	for _, code := range awid.AtomicAddressClaimConflictCodes {
		known[code] = true
	}
	for code := range agentsAddGlobalSpecificConflictCodes {
		if !known[code] {
			t.Fatalf("specific conflict map contains unknown code %s", code)
		}
	}
	for code := range agentsAddGlobalDefaultConflictCodes {
		if !known[code] {
			t.Fatalf("default conflict map contains unknown code %s", code)
		}
	}
}

func TestAgentsAddLayoutLockPathStableAndRepoScoped(t *testing.T) {
	a := agentsAddLayoutLockPath(filepath.Join("tmp", "repo", "agents"))
	b := agentsAddLayoutLockPath(filepath.Join("tmp", "repo", "agents"))
	c := agentsAddLayoutLockPath(filepath.Join("tmp", "other", "agents"))
	if a == "" || b == "" || c == "" {
		t.Fatal("lock path must not be empty")
	}
	if a != b {
		t.Fatalf("same agents root lock path changed: %q vs %q", a, b)
	}
	if a == c {
		t.Fatalf("different agents roots share lock path %q", a)
	}
	if !strings.HasPrefix(filepath.Base(a), "aw-agents-layout-") {
		t.Fatalf("lock path=%q, want aw-agents-layout prefix", a)
	}
}

func agentsAddEmptyPreflightRegistry(t *testing.T) string {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/example.com/teams/circle/certificates" {
			_, _ = w.Write([]byte(`{"certificates":[]}`))
			return
		}
		t.Fatalf("unexpected preflight registry request: %s %s", r.Method, r.URL.String())
	}))
	t.Cleanup(server.Close)
	return server.URL
}

func TestExistingBYOTNamesAllowsFreshMissingTeam(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/bootstrap.local/teams/circle/certificates" {
			t.Fatalf("unexpected registry request: %s %s", r.Method, r.URL.String())
		}
		if got := r.URL.Query().Get("active_only"); got != "true" {
			t.Fatalf("active_only=%q want true", got)
		}
		http.Error(w, "Team not found", http.StatusNotFound)
	}))
	t.Cleanup(server.Close)
	teamBootstrapRegistryURL = server.URL

	aliases, globalNames, err := existingBYOTNamesForAgentsProvision("Bootstrap.Local", "circle")
	if err != nil {
		t.Fatalf("existingBYOTNamesForAgentsProvision: %v", err)
	}
	if len(aliases) != 0 || len(globalNames) != 0 {
		t.Fatalf("fresh missing team should produce empty availability, aliases=%v globalNames=%v", aliases, globalNames)
	}
}

func TestAgentsAddRejectsExistingHomeBeforeMutation(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	if err := copyDir(templateDir, filepath.Join(repoDir, "agents")); err != nil {
		t.Fatalf("copy layout: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(repoDir, "agents", "home", "support"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoDir)
	agentsAddLayoutOnly = true

	err := runAgentsAdd(&cobra.Command{Use: "add"}, []string{"support"})
	if err == nil {
		t.Fatal("expected existing home to fail")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("error=%q, want existing-home guidance", err)
	}
	data, err := os.ReadFile(filepath.Join(repoDir, "agents", "team.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "support") {
		t.Fatalf("team.yaml mutated despite existing home conflict:\n%s", string(data))
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

func TestTeamBootstrapHostedNonInteractiveFailureRollsBackAgentsLayout(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	originalGitignore := "# existing project ignore\nnode_modules/\n"
	if err := os.WriteFile(filepath.Join(repoDir, ".gitignore"), []byte(originalGitignore), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Chdir(repoDir)
	teamBootstrapUsername = "maria"

	oldWizard := guidedOnboardingWizard
	t.Cleanup(func() { guidedOnboardingWizard = oldWizard })
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		return nil, fmt.Errorf("hosted setup unavailable")
	}

	cmd := testTeamBootstrapCommand(t)
	cmd.SetIn(strings.NewReader(""))
	err := runTeamBootstrap(cmd, []string{templateDir})
	if err == nil {
		t.Fatal("expected hosted setup failure")
	}
	if !strings.Contains(err.Error(), "rolled back newly-created agents layout") || !strings.Contains(err.Error(), "retry is safe") {
		t.Fatalf("error=%q, want rollback guidance", err)
	}
	assertPathMissing(t, filepath.Join(repoDir, "agents"))
	gitignoreAfter, readErr := os.ReadFile(filepath.Join(repoDir, ".gitignore"))
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(gitignoreAfter) != originalGitignore {
		t.Fatalf(".gitignore was not restored after rollback:\n%s", string(gitignoreAfter))
	}
	if gitBranchExistsForTest(t, repoDir, "implementation") {
		t.Fatal("generated implementation branch remained after rollback")
	}
}

func TestTeamBootstrapRollbackPreservesAgentsLayoutWithIdentityState(t *testing.T) {
	resetTeamBootstrapGlobals(t)
	repoDir := t.TempDir()
	initGitRepo(t, repoDir)
	templateDir := writeInRepoTeamBootstrapFixture(t)
	t.Chdir(repoDir)
	teamBootstrapUsername = "maria"

	oldWizard := guidedOnboardingWizard
	t.Cleanup(func() { guidedOnboardingWizard = oldWizard })
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		awDir := filepath.Join(req.WorkingDir, ".aw")
		if err := os.MkdirAll(awDir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(filepath.Join(awDir, "signing.key"), []byte("do-not-delete"), 0o600); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("connect failed after identity write")
	}

	cmd := testTeamBootstrapCommand(t)
	cmd.SetIn(strings.NewReader(""))
	err := runTeamBootstrap(cmd, []string{templateDir})
	if err == nil {
		t.Fatal("expected hosted setup failure")
	}
	if !strings.Contains(err.Error(), "contains .aw identity state") || !strings.Contains(err.Error(), "do not delete private keys") {
		t.Fatalf("error=%q, want preserve guidance", err)
	}
	assertPathExists(t, filepath.Join(repoDir, "agents", "home", "coordinator", ".aw", "signing.key"))
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
