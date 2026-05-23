package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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

func TestTeamBootstrapSpecPlansUseResponsibilityDirsAndRoleNames(t *testing.T) {
	templateDir := writeTeamBootstrapFixture(t)
	spec, err := loadTeamBootstrapSpec(templateDir)
	if err != nil {
		t.Fatalf("loadTeamBootstrapSpec: %v", err)
	}
	if err := validateTeamBootstrapSpec(templateDir, spec); err != nil {
		t.Fatalf("validateTeamBootstrapSpec: %v", err)
	}

	plans, err := buildTeamBootstrapPlans(strings.NewReader(""), &bytes.Buffer{}, templateDir, filepath.Join(templateDir, "homes"), spec, true)
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
