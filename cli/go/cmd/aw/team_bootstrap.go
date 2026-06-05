package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var teamTopCmd = &cobra.Command{
	Use:   "team",
	Short: "Bootstrap agent teams from templates",
}

var teamBootstrapCmd = &cobra.Command{
	Use:   "bootstrap <template-dir>",
	Short: "Bootstrap an agent team from a template repository",
	Long: `Bootstrap an agent team from a template repository.

The template repository is convention-first:

  docs/                  shared team/project instructions
  roles/                 role playbooks installed with aw roles set
  home/<responsibility>/AGENTS.md
  team.yaml              maps agent responsibility dirs to aw role names

team.yaml supplies the parts that cannot be inferred safely: role bundle
metadata, each agent responsibility's role_name, and default identity names.
Agent directory names are responsibilities (for example coordinator,
implementation, or review), not fixed human/agent names.

By default bootstrap runs in the current project git repo and creates an
agents/ convention directory:

  agents/home/<responsibility>/      agent homes; run Codex/Claude from here
  agents/worktrees/<alias>/          generated git worktrees for worktree agents

Use --agents-dir to choose a different project-local convention directory.
Passing --work-directory or --work-repo-url selects the legacy out-of-repo mode.

By default bootstrap uses the template's default identity names; pass
--ask-for-agent-names when you want an interactive prompt to rename generated
agents before provisioning.`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamBootstrap,
}

var (
	teamBootstrapHomeRoot         string
	teamBootstrapAgentsDir        string
	teamBootstrapWorkDirectory    string
	teamBootstrapWorkRepoURL      string
	teamBootstrapWorkRepo         string // deprecated alias for --work-directory
	teamBootstrapTemplateCacheDir string
	teamBootstrapRefreshTemplate  bool
	teamBootstrapForkTemplate     bool
	teamBootstrapUsername         string
	teamBootstrapNamespace        string
	teamBootstrapTeamName         string
	teamBootstrapTeamDisplayName  string
	teamBootstrapInviteToken      string
	teamBootstrapRegistryURL      string
	teamBootstrapAwebURL          string
	teamBootstrapDryRun           bool
	teamBootstrapYes              bool // deprecated no-op; defaults are used unless --ask-for-agent-names is set
	teamBootstrapAskAgentNames    bool
	teamBootstrapSkipRoles        bool
	teamBootstrapSkipInstructions bool
)

type teamBootstrapSpec struct {
	Name         string                            `yaml:"name"`
	Instructions teamBootstrapInstructionsSpec     `yaml:"instructions"`
	Roles        map[string]teamBootstrapRoleSpec  `yaml:"roles"`
	Agents       map[string]teamBootstrapAgentSpec `yaml:"agents"`
	Worktrees    []teamBootstrapWorktreeAgentSpec  `yaml:"worktrees"`
}

type teamBootstrapInstructionsSpec struct {
	File string `yaml:"file"`
}

type teamBootstrapRoleSpec struct {
	Title string `yaml:"title"`
	File  string `yaml:"file"`
}

type teamBootstrapAgentSpec struct {
	RoleName     string `yaml:"role_name"`
	DefaultName  string `yaml:"default_name"`
	DefaultAlias string `yaml:"default_alias"`
	Work         string `yaml:"work"`
	HomeTemplate string `yaml:"home_template"`
}

type teamBootstrapWorktreeAgentSpec struct {
	Name     string `yaml:"name"`
	RoleName string `yaml:"role_name"`
	Alias    string `yaml:"alias"`
}

type teamBootstrapAgentPlan struct {
	Responsibility string `json:"responsibility"`
	RoleName       string `json:"role_name"`
	Name           string `json:"name"`
	Alias          string `json:"alias,omitempty"`
	HomeDir        string `json:"home_dir"`
	SourceHome     string `json:"-"`
	Instructions   string `json:"instructions"`
	WorkBinding    string `json:"work_binding,omitempty"`
	WorkDir        string `json:"work_dir,omitempty"`
}

type teamBootstrapOutput struct {
	TemplateRef       string `json:"template_ref,omitempty"`
	TemplateDir       string `json:"template_dir"`
	TemplateCloned    bool   `json:"template_cloned"`
	TemplateRefreshed bool   `json:"template_refreshed"`

	TeamName              string                   `json:"team_name,omitempty"`
	DryRun                bool                     `json:"dry_run"`
	RolesInstalled        bool                     `json:"roles_installed"`
	InstructionsInstalled bool                     `json:"instructions_installed"`
	HomeRoot              string                   `json:"home_root"`
	AgentsDir             string                   `json:"agents_dir,omitempty"`
	LayoutMode            string                   `json:"layout_mode,omitempty"`
	WorkDirectory         string                   `json:"work_directory"`
	WorkRepoURL           string                   `json:"work_repo_url,omitempty"`
	Agents                []teamBootstrapAgentPlan `json:"agents"`
	NextCommands          []string                 `json:"next_commands,omitempty"`
}

type teamBootstrapLayoutMode string

const (
	teamBootstrapLayoutLegacy teamBootstrapLayoutMode = "legacy"
	teamBootstrapLayoutInRepo teamBootstrapLayoutMode = "in-repo"
)

const (
	teamBootstrapWorkRepoRoot    = "repo_root"
	teamBootstrapWorkGitWorktree = "git_worktree"
)

type teamBootstrapLayout struct {
	Mode             teamBootstrapLayoutMode
	CustomerRepoRoot string
	AgentsDirName    string
	AgentsRoot       string
	HomeRoot         string
	WorktreesRoot    string
	WorkDirectory    string
	WorkRepoURL      string
}

func init() {
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapHomeRoot, "home-root", "", "Legacy mode: directory where agent workspaces are created (default: <template-dir>/agents)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapAgentsDir, "agents-dir", "agents", "Project-local directory to create for in-repo bootstrap output")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkDirectory, "work-directory", "", "Legacy mode: directory symlinked into each agent workspace as ./work (mutually exclusive with --work-repo-url)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkRepoURL, "work-repo-url", "", "Legacy mode: git URL or local repo path to clone into <template-dir>/worktrees/<derived-name> (mutually exclusive with --work-directory)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkRepo, "work-repo", "", "Deprecated alias for --work-directory (kept for one release cycle)")
	_ = teamBootstrapCmd.Flags().MarkHidden("work-repo")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTemplateCacheDir, "template-cache-dir", "", "Directory where remote templates are cloned (advanced; defaults to cloning into the current directory)")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapRefreshTemplate, "refresh-template", false, "Re-clone the template into the destination directory before using it")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapForkTemplate, "fork", false, "Fork the template repository with gh and clone the fork into the destination directory")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapUsername, "username", "", "Hosted onboarding username to create/use (prompts when omitted and onboarding is used)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapNamespace, "namespace", "", "BYOT team namespace domain to create/use (required for one-step BYOT team bootstrap)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTeamName, "team", "", "BYOT team name/slug to create/use (required for one-step BYOT team bootstrap)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTeamDisplayName, "team-display-name", "", "Optional team display name when creating a new BYOT team")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapInviteToken, "invite-token", "", "Team invite token to accept into the first generated agent workspace")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapRegistryURL, "registry", "", "AWID registry URL override")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapAwebURL, "aweb-url", "", "Aweb server base URL to connect each generated agent workspace")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapDryRun, "dry-run", false, "Validate and print the bootstrap plan without changing files or team roles")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapYes, "yes", false, "Deprecated no-op; default agent names are used unless --ask-for-agent-names is set")
	_ = teamBootstrapCmd.Flags().MarkHidden("yes")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapAskAgentNames, "ask-for-agent-names", false, "Prompt for generated agent names instead of using template defaults")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapSkipRoles, "skip-roles", false, "Do not install the roles bundle")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapSkipInstructions, "skip-instructions", false, "Do not install shared team instructions")

	teamTopCmd.AddCommand(teamBootstrapCmd)
	rootCmd.AddCommand(teamTopCmd)
	teamTopCmd.GroupID = groupWorkspace
	bindTeamSelector(teamTopCmd)
}

func runTeamBootstrap(cmd *cobra.Command, args []string) error {
	layout, err := resolveTeamBootstrapLayoutPreflight(cmd)
	if err != nil {
		return err
	}

	resolved, err := resolveTeamBootstrapTemplate(cmd, args[0], layout.Mode)
	if err != nil {
		return err
	}
	if strings.TrimSpace(resolved.CleanupDir) != "" {
		defer os.RemoveAll(resolved.CleanupDir)
	}
	spec, err := loadTeamBootstrapSpec(resolved.TemplateDir)
	if err != nil {
		return err
	}
	if err := validateTeamBootstrapSpec(resolved.TemplateDir, spec); err != nil {
		return err
	}

	var workDirectory, workRepoURL string
	homeRoot := layout.HomeRoot
	if layout.Mode == teamBootstrapLayoutLegacy {
		homeRoot = strings.TrimSpace(teamBootstrapHomeRoot)
		if homeRoot == "" {
			homeRoot = filepath.Join(resolved.TemplateDir, "agents")
		}
		homeRoot, err = filepath.Abs(homeRoot)
		if err != nil {
			return err
		}

		workDirectory, workRepoURL, err = resolveTeamBootstrapWorkDirectoryAndRepoURL(resolved.TemplateDir)
		if err != nil {
			return err
		}
		layout.HomeRoot = homeRoot
		layout.WorkDirectory = workDirectory
		layout.WorkRepoURL = workRepoURL
	} else {
		workDirectory = layout.CustomerRepoRoot
	}

	plans, err := buildTeamBootstrapPlans(cmd.InOrStdin(), cmd.ErrOrStderr(), resolved.TemplateDir, homeRoot, spec, teamBootstrapAskAgentNames)
	if err != nil {
		return err
	}
	if layout.Mode == teamBootstrapLayoutInRepo {
		if err := applyInRepoBootstrapWorkBindings(layout, plans); err != nil {
			return err
		}
	}

	out := teamBootstrapOutput{
		TemplateRef:       templateRefForOutput(args[0]),
		TemplateDir:       resolved.TemplateDir,
		TemplateCloned:    resolved.Cloned,
		TemplateRefreshed: resolved.Refreshed,
		TeamName:          spec.Name,
		DryRun:            teamBootstrapDryRun,
		HomeRoot:          homeRoot,
		AgentsDir:         layout.AgentsRoot,
		LayoutMode:        string(layout.Mode),
		WorkDirectory:     workDirectory,
		WorkRepoURL:       workRepoURL,
		Agents:            plans,
	}

	if teamBootstrapDryRun {
		out.NextCommands = plannedInitCommands(plans)
		printOutput(out, formatTeamBootstrapOutput)
		return nil
	}

	source, err := resolveTeamBootstrapSource()
	if err != nil {
		return err
	}

	if layout.Mode == teamBootstrapLayoutLegacy && workRepoURL != "" {
		if err := ensureTeamBootstrapWorktreesGitIgnored(resolved.TemplateDir); err != nil {
			return err
		}
	}
	if layout.Mode == teamBootstrapLayoutLegacy {
		if err := ensureTeamBootstrapWorkRepoReady(workDirectory, workRepoURL, spec); err != nil {
			return err
		}
	} else {
		if err := prepareInRepoBootstrapAgentsDir(layout, resolved.TemplateDir, plans); err != nil {
			return err
		}
		if err := ensureInRepoBootstrapGitignore(layout); err != nil {
			return err
		}
		if err := createInRepoBootstrapWorktrees(layout, plans); err != nil {
			return err
		}
	}

	for _, plan := range plans {
		planWorkDirectory := workDirectory
		if strings.TrimSpace(plan.WorkDir) != "" {
			planWorkDirectory = plan.WorkDir
		}
		if err := materializeTeamBootstrapAgent(resolved.TemplateDir, plan, planWorkDirectory); err != nil {
			return err
		}
	}

	rolesInstalled, instructionsInstalled, err := bootstrapTeamAndInitAgentDirs(cmd, source, spec, resolved.TemplateDir, plans)
	if err != nil {
		return err
	}
	out.RolesInstalled = rolesInstalled
	out.InstructionsInstalled = instructionsInstalled
	out.NextCommands = nil
	if layout.Mode == teamBootstrapLayoutLegacy {
		if err := bootstrapTeamBootstrapWorktreeAgents(cmd, resolved.TemplateDir, workDirectory, spec, plans); err != nil {
			return err
		}
	}

	printOutput(out, formatTeamBootstrapOutput)
	return nil
}

func resolveTeamBootstrapLayoutPreflight(cmd *cobra.Command) (teamBootstrapLayout, error) {
	hasWorkDirectory := strings.TrimSpace(teamBootstrapWorkDirectory) != "" || strings.TrimSpace(teamBootstrapWorkRepo) != ""
	hasWorkRepoURL := strings.TrimSpace(teamBootstrapWorkRepoURL) != ""
	agentsDirExplicit := cmd.Flags().Changed("agents-dir")

	if agentsDirExplicit && hasWorkDirectory {
		return teamBootstrapLayout{}, usageError("--agents-dir cannot be combined with --work-directory")
	}
	if agentsDirExplicit && hasWorkRepoURL {
		return teamBootstrapLayout{}, usageError("--agents-dir cannot be combined with --work-repo-url")
	}
	if hasWorkDirectory || hasWorkRepoURL {
		return teamBootstrapLayout{Mode: teamBootstrapLayoutLegacy}, nil
	}
	if strings.TrimSpace(teamBootstrapHomeRoot) != "" {
		return teamBootstrapLayout{}, usageError("--home-root cannot be combined with in-repo bootstrap; use --agents-dir to choose the project-local agents directory")
	}

	wd, err := os.Getwd()
	if err != nil {
		return teamBootstrapLayout{}, err
	}
	repoRoot, err := currentGitWorktreeRootFromDir(wd)
	if err != nil {
		return teamBootstrapLayout{}, usageError("in-repo team bootstrap must be run from inside a git repository; run from your project repo or pass --work-directory/--work-repo-url for legacy bootstrap")
	}
	agentsDir, err := validateTeamBootstrapAgentsDir(teamBootstrapAgentsDir)
	if err != nil {
		return teamBootstrapLayout{}, err
	}
	agentsRoot := filepath.Join(repoRoot, agentsDir)
	if _, err := os.Stat(agentsRoot); err == nil {
		return teamBootstrapLayout{}, teamBootstrapAgentsDirExistsError(agentsRoot, agentsDir)
	} else if !os.IsNotExist(err) {
		return teamBootstrapLayout{}, fmt.Errorf("stat agents directory %s: %w", agentsRoot, err)
	}

	return teamBootstrapLayout{
		Mode:             teamBootstrapLayoutInRepo,
		CustomerRepoRoot: repoRoot,
		AgentsDirName:    agentsDir,
		AgentsRoot:       agentsRoot,
		HomeRoot:         filepath.Join(agentsRoot, "home"),
		WorktreesRoot:    filepath.Join(agentsRoot, "worktrees"),
	}, nil
}

func validateTeamBootstrapAgentsDir(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	if value == "" {
		return "", usageError("--agents-dir must not be empty")
	}
	if filepath.IsAbs(value) {
		return "", usageError("--agents-dir must be a relative path inside the current git repository")
	}
	clean := filepath.Clean(value)
	if clean == "." {
		return "", usageError("--agents-dir must name a directory, not .")
	}
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", usageError("--agents-dir must not contain .. path traversal")
		}
	}
	return clean, nil
}

func teamBootstrapAgentsDirExistsError(path, agentsDir string) error {
	return usageError(
		"agents directory already exists at %s.\n\n"+
			"To create a new bootstrap here:\n"+
			"  1. Pick a different name with --agents-dir <name>, or\n"+
			"  2. Remove or rename the existing directory if you no longer need it.\n\n"+
			"aw team bootstrap does not adopt, merge, or overwrite existing agents directories in v1. "+
			"This prevents accidental data loss to existing agent identity state.",
		path,
	)
}

func prepareInRepoBootstrapAgentsDir(layout teamBootstrapLayout, templateDir string, plans []teamBootstrapAgentPlan) error {
	if layout.Mode != teamBootstrapLayoutInRepo {
		return nil
	}
	if _, err := os.Stat(layout.AgentsRoot); err == nil {
		return teamBootstrapAgentsDirExistsError(layout.AgentsRoot, layout.AgentsDirName)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat agents directory %s: %w", layout.AgentsRoot, err)
	}
	if err := os.MkdirAll(layout.AgentsRoot, 0o755); err != nil {
		return err
	}
	if err := copyFile(filepath.Join(templateDir, "team.yaml"), filepath.Join(layout.AgentsRoot, "team.yaml")); err != nil {
		return err
	}
	for _, dir := range []string{"docs", "roles"} {
		src := filepath.Join(templateDir, dir)
		if info, err := os.Stat(src); err == nil && info.IsDir() {
			if err := copyDir(src, filepath.Join(layout.AgentsRoot, dir)); err != nil {
				return err
			}
		} else if err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	for _, plan := range plans {
		if strings.TrimSpace(plan.SourceHome) == "" {
			return fmt.Errorf("agent %s missing source home", plan.Responsibility)
		}
		if err := copyDir(plan.SourceHome, plan.HomeDir); err != nil {
			return fmt.Errorf("copy home template for %s: %w", plan.Responsibility, err)
		}
	}
	return nil
}

func applyInRepoBootstrapWorkBindings(layout teamBootstrapLayout, plans []teamBootstrapAgentPlan) error {
	for i := range plans {
		plans[i].Instructions = filepath.Join(plans[i].HomeDir, "AGENTS.md")
		binding := strings.TrimSpace(plans[i].WorkBinding)
		if binding == "" {
			binding = teamBootstrapWorkRepoRoot
			plans[i].WorkBinding = binding
		}
		switch binding {
		case teamBootstrapWorkRepoRoot:
			plans[i].WorkDir = layout.CustomerRepoRoot
		case teamBootstrapWorkGitWorktree:
			name := strings.TrimSpace(plans[i].Alias)
			if name == "" {
				name = sanitizeSlug(plans[i].Name)
			}
			if name == "" {
				name = sanitizeSlug(plans[i].Responsibility)
			}
			if name == "" {
				return fmt.Errorf("cannot derive worktree name for %s", plans[i].Responsibility)
			}
			plans[i].WorkDir = filepath.Join(layout.WorktreesRoot, name)
		default:
			return usageError("unsupported work binding %q for agent %s (expected repo_root or git_worktree)", binding, plans[i].Responsibility)
		}
	}
	return nil
}

func createInRepoBootstrapWorktrees(layout teamBootstrapLayout, plans []teamBootstrapAgentPlan) error {
	if layout.Mode != teamBootstrapLayoutInRepo {
		return nil
	}
	needsWorktree := false
	for _, plan := range plans {
		if plan.WorkBinding == teamBootstrapWorkGitWorktree {
			needsWorktree = true
			break
		}
	}
	if !needsWorktree {
		return nil
	}
	if err := ensureAwebRuntimeUntrackedForAddWorktree(layout.CustomerRepoRoot); err != nil {
		return err
	}
	if err := os.MkdirAll(layout.WorktreesRoot, 0o755); err != nil {
		return err
	}
	for _, plan := range plans {
		if plan.WorkBinding != teamBootstrapWorkGitWorktree {
			continue
		}
		if _, err := os.Stat(plan.WorkDir); err == nil {
			return usageError("worktree path %s already exists", plan.WorkDir)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat worktree path %s: %w", plan.WorkDir, err)
		}
		branchName := strings.TrimSpace(plan.Alias)
		if branchName == "" {
			branchName = sanitizeSlug(plan.Name)
		}
		if branchName == "" {
			branchName = sanitizeSlug(plan.Responsibility)
		}
		branchCreated, err := createWorkspaceGitWorktree(layout.CustomerRepoRoot, plan.WorkDir, branchName, jsonFlag)
		if err != nil {
			return fmt.Errorf("failed to create git worktree for %s: %w", plan.Responsibility, err)
		}
		if err := ensureAwebRuntimeGitIgnored(plan.WorkDir); err != nil {
			cleanupWorkspaceWorktree(layout.CustomerRepoRoot, plan.WorkDir, branchName, branchCreated)
			return err
		}
	}
	return nil
}

func ensureInRepoBootstrapGitignore(layout teamBootstrapLayout) error {
	if layout.Mode != teamBootstrapLayoutInRepo {
		return nil
	}
	gitignorePath := filepath.Join(layout.CustomerRepoRoot, ".gitignore")
	data, err := os.ReadFile(gitignorePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read .gitignore: %w", err)
	}
	lines := strings.Split(string(data), "\n")
	homePattern := "/" + filepath.ToSlash(filepath.Join(layout.AgentsDirName, "home", "*", ".aw")) + "/"
	worktreesPattern := "/" + filepath.ToSlash(filepath.Join(layout.AgentsDirName, "worktrees")) + "/"
	hasHome := false
	hasWorktrees := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == homePattern {
			hasHome = true
		}
		if trimmed == worktreesPattern {
			hasWorktrees = true
		}
	}
	if hasHome && hasWorktrees {
		return nil
	}
	var addition string
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		addition += "\n"
	}
	if len(data) > 0 {
		addition += "\n"
	}
	addition += "# Auto-written by aw team bootstrap (do not remove)\n"
	if !hasHome {
		addition += homePattern + "\n"
	}
	if !hasWorktrees {
		addition += worktreesPattern + "\n"
	}
	return appendFile(gitignorePath, []byte(addition), 0o644)
}

func loadTeamBootstrapSpec(templateDir string) (*teamBootstrapSpec, error) {
	data, err := os.ReadFile(filepath.Join(templateDir, "team.yaml"))
	if err != nil {
		return nil, fmt.Errorf("read team.yaml: %w", err)
	}
	var spec teamBootstrapSpec
	if err := yaml.Unmarshal(data, &spec); err != nil {
		return nil, fmt.Errorf("parse team.yaml: %w", err)
	}
	return &spec, nil
}

type resolvedTeamBootstrapTemplate struct {
	TemplateDir string
	Cloned      bool
	Refreshed   bool
	CleanupDir  string
}

func resolveTeamBootstrapTemplate(cmd *cobra.Command, templateRef string, mode teamBootstrapLayoutMode) (*resolvedTeamBootstrapTemplate, error) {
	templateRef = strings.TrimSpace(templateRef)
	if templateRef == "" {
		return nil, usageError("missing template directory")
	}

	if info, err := os.Stat(templateRef); err == nil && info.IsDir() {
		abs, aerr := filepath.Abs(templateRef)
		if aerr != nil {
			return nil, aerr
		}
		return &resolvedTeamBootstrapTemplate{TemplateDir: abs}, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}

	cloneURL, slug, repoFullName, err := resolveTeamBootstrapCloneURL(templateRef)
	if err != nil {
		return nil, err
	}
	destDir, cleanupDir, err := resolveTeamBootstrapTemplateDestDir(cmd, slug, mode)
	if err != nil {
		return nil, err
	}
	if teamBootstrapRefreshTemplate {
		if _, err := os.Stat(destDir); err == nil {
			if err := os.RemoveAll(destDir); err != nil {
				return nil, err
			}
		}
	}
	if _, err := os.Stat(destDir); errors.Is(err, os.ErrNotExist) {
		if teamBootstrapForkTemplate {
			if repoFullName == "" {
				return nil, fmt.Errorf("--fork requires a gh:OWNER/REPO template ref")
			}
			if err := runGHRepoForkClone(cmd, repoFullName, destDir); err != nil {
				return nil, err
			}
			return &resolvedTeamBootstrapTemplate{TemplateDir: destDir, Cloned: true, Refreshed: teamBootstrapRefreshTemplate, CleanupDir: cleanupDir}, nil
		}
		if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
			return nil, err
		}
		if err := runGitClone(cmd, cloneURL, destDir); err != nil {
			return nil, err
		}
		return &resolvedTeamBootstrapTemplate{TemplateDir: destDir, Cloned: true, Refreshed: teamBootstrapRefreshTemplate, CleanupDir: cleanupDir}, nil
	} else if err != nil {
		return nil, err
	}
	return &resolvedTeamBootstrapTemplate{TemplateDir: destDir, Cloned: false, Refreshed: false, CleanupDir: cleanupDir}, nil
}

func resolveTeamBootstrapTemplateDestDir(cmd *cobra.Command, slug string, mode teamBootstrapLayoutMode) (string, string, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return "", "", fmt.Errorf("internal error: empty template slug")
	}
	// Advanced override: clone into a dedicated cache directory.
	if strings.TrimSpace(teamBootstrapTemplateCacheDir) != "" {
		base, err := filepath.Abs(strings.TrimSpace(teamBootstrapTemplateCacheDir))
		if err != nil {
			return "", "", err
		}
		return filepath.Join(base, slug), "", nil
	}
	if mode == teamBootstrapLayoutInRepo {
		base, err := os.MkdirTemp("", "aw-team-bootstrap-template-*")
		if err != nil {
			return "", "", err
		}
		return filepath.Join(base, slug), base, nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", "", err
	}
	inside, err := isInsideGitWorktree(wd)
	if err != nil {
		return "", "", err
	}
	if inside {
		return "", "", fmt.Errorf(
			"refusing to clone a template into an existing git worktree (%s). "+
				"Run from an empty directory, or pass --template-cache-dir to clone elsewhere.",
			wd,
		)
	}
	return filepath.Join(wd, slug), "", nil
}

func isInsideGitWorktree(dir string) (bool, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", "-C", dir, "rev-parse", "--is-inside-work-tree")
	out, err := cmd.Output()
	if err != nil {
		// If git isn't installed or dir isn't a repo, treat as not inside.
		return false, nil
	}
	return strings.TrimSpace(string(out)) == "true", nil
}

func resolveTeamBootstrapCloneURL(ref string) (string, string, string, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "gh:") {
		repo := strings.TrimPrefix(ref, "gh:")
		repo = strings.Trim(repo, "/")
		parts := strings.Split(repo, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", "", fmt.Errorf("invalid gh: template ref %q (expected gh:OWNER/REPO)", ref)
		}
		slug := sanitizeSlug(parts[1])
		full := parts[0] + "/" + parts[1]
		return "https://github.com/" + full + ".git", slug, full, nil
	}

	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		u, err := url.Parse(ref)
		if err != nil {
			return "", "", "", err
		}
		path := strings.Trim(u.Path, "/")
		path = strings.TrimSuffix(path, ".git")
		parts := strings.Split(path, "/")
		slug := sanitizeSlug(parts[len(parts)-1])
		return ref, slug, "", nil
	}

	if strings.HasPrefix(ref, "git@") {
		// git@github.com:OWNER/REPO(.git)
		after := ref
		if idx := strings.Index(after, ":"); idx >= 0 {
			after = after[idx+1:]
		}
		after = strings.Trim(after, "/")
		after = strings.TrimSuffix(after, ".git")
		parts := strings.Split(after, "/")
		if len(parts) == 0 {
			return "", "", "", fmt.Errorf("invalid git template ref %q", ref)
		}
		slug := sanitizeSlug(parts[len(parts)-1])
		return ref, slug, "", nil
	}

	return "", "", "", fmt.Errorf("template ref %q is not a directory and is not a supported git URL (use a local dir, gh:OWNER/REPO, https://..., or git@...)", ref)
}

func runGitClone(cmd *cobra.Command, cloneURL string, destDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	git := exec.CommandContext(ctx, "git", "clone", "--depth", "1", cloneURL, destDir)
	git.Stdout = cmd.OutOrStdout()
	git.Stderr = cmd.ErrOrStderr()
	return git.Run()
}

func runGHRepoForkClone(cmd *cobra.Command, repoFullName string, destDir string) error {
	if strings.TrimSpace(repoFullName) == "" {
		return fmt.Errorf("internal error: missing fork repo name")
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return fmt.Errorf(
			"--fork requires the GitHub CLI (gh). Install it from https://cli.github.com/ and run `gh auth login`. (%v)",
			err,
		)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	args := []string{"repo", "fork", repoFullName, "--clone", "--default-branch-only", "--", "--depth", "1", destDir}
	fork := exec.CommandContext(ctx, "gh", args...)
	fork.Stdout = cmd.OutOrStdout()
	fork.Stderr = cmd.ErrOrStderr()
	return fork.Run()
}

func templateRefForOutput(raw string) string {
	return strings.TrimSpace(raw)
}

func resolveTeamBootstrapWorkDirectoryAndRepoURL(templateDir string) (string, string, error) {
	templateDir = strings.TrimSpace(templateDir)
	workDirectory := strings.TrimSpace(teamBootstrapWorkDirectory)
	workRepoURL := strings.TrimSpace(teamBootstrapWorkRepoURL)
	legacy := strings.TrimSpace(teamBootstrapWorkRepo)
	if workRepoURL != "" && legacy != "" {
		return "", "", usageError("--work-repo-url and --work-repo cannot both be set (work-repo is deprecated; use --work-directory)")
	}
	if workDirectory != "" && legacy != "" {
		return "", "", usageError("--work-directory and --work-repo cannot both be set (work-repo is deprecated; use --work-directory)")
	}
	if workDirectory == "" {
		workDirectory = legacy
	}
	if workDirectory != "" && workRepoURL != "" {
		return "", "", usageError("--work-directory and --work-repo-url are mutually exclusive; set exactly one")
	}
	if workDirectory == "" && workRepoURL == "" {
		return "", "", usageError("missing required flag: set exactly one of --work-directory or --work-repo-url")
	}
	if workRepoURL != "" {
		derived, err := deriveGitCloneDirName(workRepoURL)
		if err != nil {
			return "", "", err
		}
		if derived == "" {
			return "", "", usageError("failed to derive work directory name from --work-repo-url")
		}
		workDirectory = filepath.Join(templateDir, "worktrees", derived)
	}
	absDir, err := filepath.Abs(workDirectory)
	if err != nil {
		return "", "", err
	}
	return absDir, workRepoURL, nil
}

func deriveGitCloneDirName(workRepoURL string) (string, error) {
	workRepoURL = strings.TrimSpace(workRepoURL)
	if workRepoURL == "" {
		return "", nil
	}

	// Match git clone default dir naming: basename of URL/path with optional .git stripped.
	if strings.HasPrefix(workRepoURL, "http://") || strings.HasPrefix(workRepoURL, "https://") {
		u, err := url.Parse(workRepoURL)
		if err != nil {
			return "", err
		}
		base := pathBase(u.Path)
		base = strings.TrimSuffix(base, ".git")
		if base == "" {
			return "", usageError("invalid --work-repo-url %q (missing repo name)", workRepoURL)
		}
		return base, nil
	}

	if strings.HasPrefix(workRepoURL, "git@") {
		after := workRepoURL
		if idx := strings.Index(after, ":"); idx >= 0 {
			after = after[idx+1:]
		}
		after = strings.Trim(after, "/")
		after = strings.TrimSuffix(after, ".git")
		base := pathBase(after)
		if base == "" {
			return "", usageError("invalid --work-repo-url %q (missing repo name)", workRepoURL)
		}
		return base, nil
	}

	// Local path or other git transports: use filepath.Base.
	base := filepath.Base(filepath.Clean(workRepoURL))
	base = strings.TrimSuffix(base, ".git")
	if base == "." || base == string(filepath.Separator) || base == "" {
		return "", usageError("invalid --work-repo-url %q (missing repo name)", workRepoURL)
	}
	return base, nil
}

func pathBase(p string) string {
	p = strings.Trim(p, "/")
	if p == "" {
		return ""
	}
	parts := strings.Split(p, "/")
	return parts[len(parts)-1]
}

func ensureTeamBootstrapWorkRepoReady(workDirectory, workRepoURL string, spec *teamBootstrapSpec) error {
	workDirectory = strings.TrimSpace(workDirectory)
	if workDirectory == "" {
		return usageError("missing required flag: --work-directory")
	}
	workRepoURL = strings.TrimSpace(workRepoURL)
	if workRepoURL == "" {
		if spec != nil && len(spec.Worktrees) > 0 {
			if _, err := currentGitWorktreeRootFromDir(workDirectory); err != nil {
				return usageError("team.yaml declares worktrees but --work-directory is not a git repo")
			}
		}
		return nil
	}

	// If workDirectory is already a git repo, do nothing.
	if _, err := currentGitWorktreeRootFromDir(workDirectory); err == nil {
		return nil
	}

	// Clone into workDirectory itself.
	if err := os.MkdirAll(workDirectory, 0o755); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	git := exec.CommandContext(ctx, "git", "clone", "--depth", "1", workRepoURL, workDirectory)
	git.Stdout = os.Stderr
	git.Stderr = os.Stderr
	if err := git.Run(); err != nil {
		return fmt.Errorf("failed to clone --work-repo-url: %w", err)
	}
	if _, err := currentGitWorktreeRootFromDir(workDirectory); err != nil {
		return usageError("--work-directory %s is not a git repo after cloning --work-repo-url", workDirectory)
	}
	return nil
}

func ensureTeamBootstrapWorktreesGitIgnored(templateDir string) error {
	root, err := currentGitWorktreeRootFromDir(templateDir)
	if err != nil {
		// Template may be a plain directory; best effort.
		return nil
	}
	excludePath, err := gitPath(root, "info/exclude")
	if err != nil {
		return err
	}
	data, err := os.ReadFile(excludePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("read git exclude %s: %w", excludePath, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "worktrees/" || trimmed == "/worktrees/" {
			return nil
		}
	}
	if err := os.MkdirAll(filepath.Dir(excludePath), 0o755); err != nil {
		return fmt.Errorf("create git exclude dir: %w", err)
	}
	addition := "\n# aweb generated worktrees\nworktrees/\n"
	if err := appendFile(excludePath, []byte(addition), 0o644); err != nil {
		return fmt.Errorf("update git exclude %s: %w", excludePath, err)
	}
	return nil
}

type plannedWorktreeAgent struct {
	Name     string
	RoleName string
	Alias    string
}

func bootstrapTeamBootstrapWorktreeAgents(cmd *cobra.Command, templateDir, workDirectory string, spec *teamBootstrapSpec, plans []teamBootstrapAgentPlan) error {
	if spec == nil || len(spec.Worktrees) == 0 {
		return nil
	}
	workDirectory = strings.TrimSpace(workDirectory)
	if workDirectory == "" {
		return usageError("missing required flag: --work-directory")
	}

	workRepoRoot, err := currentGitWorktreeRootFromDir(workDirectory)
	if err != nil {
		return usageError("team.yaml declares worktrees but --work-directory is not a git repo")
	}
	if err := ensureAwebRuntimeUntrackedForAddWorktree(workRepoRoot); err != nil {
		return err
	}
	if err := ensureAwebRuntimeGitIgnored(workRepoRoot); err != nil {
		return err
	}

	primary, err := primaryTeamBootstrapPlan(plans)
	if err != nil {
		return err
	}
	workspaceState, _, err := awconfig.LoadWorktreeWorkspaceFromDir(primary.HomeDir)
	if err != nil {
		return err
	}
	sel, err := resolveSelectionForDir(primary.HomeDir)
	if err != nil {
		return err
	}
	teamID := strings.TrimSpace(sel.TeamID)
	if teamID == "" {
		return fmt.Errorf("bootstrap worktrees: primary workspace missing team_id")
	}
	teamDomain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return err
	}
	hasTeamKey, err := awconfig.TeamKeyExists(teamDomain, teamName)
	if err != nil {
		return err
	}
	sourceServerURL := strings.TrimSpace(workspaceState.AwebURL)
	if sourceServerURL == "" {
		return fmt.Errorf("bootstrap worktrees: primary workspace missing aweb_url")
	}

	worktreesRoot := filepath.Join(templateDir, "worktrees")
	if err := os.MkdirAll(worktreesRoot, 0o755); err != nil {
		return err
	}
	if err := ensureTeamBootstrapWorktreesGitIgnored(templateDir); err != nil {
		return err
	}

	repoName := filepath.Base(workRepoRoot)
	if entries, err := os.ReadDir(worktreesRoot); err == nil {
		for _, entry := range entries {
			if entry.IsDir() && strings.HasPrefix(entry.Name(), repoName+"-") {
				return usageError("refusing to create worktree agents: %s already contains worktrees for repo %s", worktreesRoot, repoName)
			}
		}
	}

	client, _, err := resolveClientSelectionForDir(primary.HomeDir)
	if err != nil {
		return err
	}
	teamAliases, err := fetchWorkspaceTeamAliases(client, strings.TrimSpace(sel.WorkspaceID))
	if err != nil {
		return err
	}

	planned := make([]plannedWorktreeAgent, 0, len(spec.Worktrees))
	for _, wt := range spec.Worktrees {
		name := strings.TrimSpace(wt.Name)
		alias := strings.TrimSpace(wt.Alias)
		if alias == "" {
			alias = sanitizeSlug(name)
		}
		if alias == "" {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			suggestion, err := client.SuggestAliasPrefix(ctx)
			cancel()
			if err != nil {
				return err
			}
			alias = strings.TrimSpace(suggestion.NamePrefix)
		}
		if !isValidWorkspaceAlias(alias) {
			return usageError("invalid worktree agent alias %q", alias)
		}
		aliasLower := strings.ToLower(alias)
		if teamAliases[aliasLower] {
			return usageError("worktree agent alias %q is already in use by this team", alias)
		}
		teamAliases[aliasLower] = true
		planned = append(planned, plannedWorktreeAgent{Name: name, RoleName: strings.TrimSpace(wt.RoleName), Alias: alias})
	}
	if len(planned) == 0 {
		return nil
	}

	first := planned[0]
	branchName := first.Alias
	worktreePath := filepath.Join(worktreesRoot, repoName+"-"+branchName)
	if _, err := os.Stat(worktreePath); err == nil {
		return usageError("worktree path %s already exists", worktreePath)
	}

	branchCreated, err := createWorkspaceGitWorktree(workRepoRoot, worktreePath, branchName, jsonFlag)
	if err != nil {
		return fmt.Errorf("failed to create initial git worktree: %w", err)
	}
	if err := ensureAwebRuntimeGitIgnored(worktreePath); err != nil {
		cleanupWorkspaceWorktree(workRepoRoot, worktreePath, branchName, branchCreated)
		return err
	}

	if hasTeamKey {
		_, err = addWorktreeViaLocalTeamKey(
			worktreePath, workRepoRoot, branchName, branchCreated,
			teamID, teamDomain, teamName, sourceServerURL, primary.HomeDir,
			first.Alias, first.RoleName, workspaceState,
		)
	} else {
		_, err = addWorktreeViaPrimaryInvite(
			primary.HomeDir, worktreePath, workRepoRoot, branchName, branchCreated,
			sourceServerURL, first.Alias, first.RoleName, workspaceState,
		)
	}
	if err != nil {
		return err
	}

	for _, wt := range planned[1:] {
		branchName = wt.Alias
		worktreePath = filepath.Join(worktreesRoot, repoName+"-"+branchName)
		if _, err := os.Stat(worktreePath); err == nil {
			return usageError("worktree path %s already exists", worktreePath)
		}
		branchCreated, err = createWorkspaceGitWorktree(workRepoRoot, worktreePath, branchName, jsonFlag)
		if err != nil {
			return fmt.Errorf("failed to create git worktree %s: %w", branchName, err)
		}
		if err := ensureAwebRuntimeGitIgnored(worktreePath); err != nil {
			cleanupWorkspaceWorktree(workRepoRoot, worktreePath, branchName, branchCreated)
			return err
		}
		if hasTeamKey {
			_, err = addWorktreeViaLocalTeamKey(
				worktreePath, workRepoRoot, branchName, branchCreated,
				teamID, teamDomain, teamName, sourceServerURL, primary.HomeDir,
				wt.Alias, wt.RoleName, workspaceState,
			)
		} else {
			_, err = addWorktreeViaPrimaryInvite(
				primary.HomeDir, worktreePath, workRepoRoot, branchName, branchCreated,
				sourceServerURL, wt.Alias, wt.RoleName, workspaceState,
			)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

type teamBootstrapSourceKind string

const (
	teamBootstrapSourceHostedNew teamBootstrapSourceKind = "hosted-new"
	teamBootstrapSourceAPIKey    teamBootstrapSourceKind = "api-key"
	teamBootstrapSourceInvite    teamBootstrapSourceKind = "invite"
	teamBootstrapSourceCurrent   teamBootstrapSourceKind = "current-workspace"
	teamBootstrapSourceBYOT      teamBootstrapSourceKind = "byot"
)

type teamBootstrapSource struct {
	Kind        teamBootstrapSourceKind
	InviteToken string
}

type teamBootstrapInvite struct {
	Token   string
	AwebURL string
}

func bootstrapTeamAndInitAgentDirs(cmd *cobra.Command, source teamBootstrapSource, spec *teamBootstrapSpec, templateDir string, plans []teamBootstrapAgentPlan) (bool, bool, error) {
	primary, err := primaryTeamBootstrapPlan(plans)
	if err != nil {
		return false, false, err
	}

	// 1) Connect the first generated agent. This workspace becomes the team anchor.
	if err := initTeamBootstrapPrimaryAgent(cmd, source, primary); err != nil {
		return false, false, err
	}

	// 2) Install template roles/instructions before creating the remaining agents.
	rolesInstalled, instructionsInstalled, err := installTeamBootstrapOverridesAfterConnect(spec, templateDir, plans)
	if err != nil {
		return false, false, err
	}

	// 3) Create/connect the remaining generated agents in the established team.
	for _, agent := range plans {
		if agent.HomeDir == primary.HomeDir {
			continue
		}
		if err := initTeamBootstrapAdditionalAgent(primary.HomeDir, agent); err != nil {
			return false, false, err
		}
	}

	return rolesInstalled, instructionsInstalled, nil
}

func resolveTeamBootstrapSource() (teamBootstrapSource, error) {
	hasAPIKey := resolveInitAPIKey() != ""
	hasInvite := strings.TrimSpace(teamBootstrapInviteToken) != ""
	hasBYOT := strings.TrimSpace(teamBootstrapNamespace) != "" || strings.TrimSpace(teamBootstrapTeamName) != ""
	hasUsername := strings.TrimSpace(teamBootstrapUsername) != ""

	explicit := 0
	for _, set := range []bool{hasAPIKey, hasInvite, hasBYOT, hasUsername} {
		if set {
			explicit++
		}
	}
	if explicit > 1 {
		return teamBootstrapSource{}, usageError("set only one team source: AWEB_API_KEY, --invite-token, --username, or --namespace/--team")
	}

	if hasAPIKey {
		return teamBootstrapSource{Kind: teamBootstrapSourceAPIKey}, nil
	}
	if hasInvite {
		return teamBootstrapSource{Kind: teamBootstrapSourceInvite, InviteToken: strings.TrimSpace(teamBootstrapInviteToken)}, nil
	}
	if hasBYOT {
		if strings.TrimSpace(teamBootstrapNamespace) == "" {
			return teamBootstrapSource{}, usageError("--namespace is required with --team")
		}
		if strings.TrimSpace(teamBootstrapTeamName) == "" {
			return teamBootstrapSource{}, usageError("--team is required with --namespace")
		}
		return teamBootstrapSource{Kind: teamBootstrapSourceBYOT}, nil
	}
	if hasUsername {
		return teamBootstrapSource{Kind: teamBootstrapSourceHostedNew}, nil
	}

	if currentHasTeamWorkspace() {
		return teamBootstrapSource{Kind: teamBootstrapSourceCurrent}, nil
	}
	if isTTY() {
		return teamBootstrapSource{Kind: teamBootstrapSourceHostedNew}, nil
	}
	return teamBootstrapSource{}, usageError("non-interactive team bootstrap requires a team source: AWEB_API_KEY, --invite-token, --username, --namespace/--team, or run from an initialized aw workspace to forward its current team")
}

func currentHasTeamWorkspace() bool {
	wd, err := os.Getwd()
	if err != nil {
		return false
	}
	sel, err := resolveSelectionForDir(wd)
	return err == nil && strings.TrimSpace(sel.TeamID) != ""
}

func initTeamBootstrapPrimaryAgent(cmd *cobra.Command, source teamBootstrapSource, primary teamBootstrapAgentPlan) error {
	alias := strings.TrimSpace(primary.Alias)
	if alias == "" {
		alias = sanitizeSlug(primary.Name)
	}
	if err := ensureConnectTargetClean(primary.HomeDir); err != nil {
		return err
	}

	switch source.Kind {
	case teamBootstrapSourceAPIKey:
		return initTeamBootstrapAgentViaAPIKey(primary.HomeDir, alias, primary.RoleName)
	case teamBootstrapSourceInvite:
		_, err := acceptInviteAndConnectTeamBootstrapAgent(primary.HomeDir, teamBootstrapInvite{Token: source.InviteToken}, alias, primary.RoleName)
		return err
	case teamBootstrapSourceCurrent:
		invite, err := createTeamBootstrapInviteFromCurrentWorkspace()
		if err != nil {
			return err
		}
		_, err = acceptInviteAndConnectTeamBootstrapAgent(primary.HomeDir, invite, alias, primary.RoleName)
		return err
	case teamBootstrapSourceBYOT:
		invite, err := createTeamBootstrapBYOTInvite()
		if err != nil {
			return err
		}
		_, err = acceptInviteAndConnectTeamBootstrapAgent(primary.HomeDir, invite, alias, primary.RoleName)
		return err
	case teamBootstrapSourceHostedNew:
		_, err := guidedOnboardingWizard(guidedOnboardingRequest{
			WorkingDir:         primary.HomeDir,
			PromptIn:           cmd.InOrStdin(),
			PromptOut:          cmd.ErrOrStderr(),
			BaseURL:            strings.TrimSpace(teamBootstrapAwebURL),
			RegistryURL:        strings.TrimSpace(teamBootstrapRegistryURL),
			Username:           strings.TrimSpace(teamBootstrapUsername),
			Alias:              alias,
			Role:               primary.RoleName,
			Persistent:         false,
			InjectAgentDocs:    false,
			DoNotTouchAgentsMD: true,
			AskPostCreateSetup: false,
			NonInteractive:     !isTTY(),
		})
		return err
	default:
		return fmt.Errorf("unsupported team bootstrap source %q", source.Kind)
	}
}

func initTeamBootstrapAdditionalAgent(primaryDir string, agent teamBootstrapAgentPlan) error {
	alias := strings.TrimSpace(agent.Alias)
	if alias == "" {
		alias = sanitizeSlug(agent.Name)
	}
	if err := ensureConnectTargetClean(agent.HomeDir); err != nil {
		return err
	}

	invite, err := createTeamBootstrapInviteFromWorkspace(primaryDir)
	if err != nil {
		return err
	}
	_, err = acceptInviteAndConnectTeamBootstrapAgent(agent.HomeDir, invite, alias, agent.RoleName)
	return err
}

func initTeamBootstrapAgentViaAPIKey(homeDir, alias, roleName string) error {
	awebURL := strings.TrimSpace(teamBootstrapAwebURL)
	if awebURL == "" {
		awebURL = strings.TrimSpace(os.Getenv("AWEB_URL"))
	}
	if awebURL == "" {
		awebURL = DefaultAwebURL
	}
	awebURL, err := normalizeAPIKeyBootstrapBaseURL(awebURL)
	if err != nil {
		return fmt.Errorf("invalid --aweb-url: %w", err)
	}
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir:  homeDir,
		AwebURL:     awebURL,
		RegistryURL: strings.TrimSpace(teamBootstrapRegistryURL),
		APIKey:      resolveInitAPIKey(),
		Alias:       alias,
		Role:        strings.TrimSpace(roleName),
	})
	return err
}

func acceptInviteAndConnectTeamBootstrapAgent(homeDir string, invite teamBootstrapInvite, alias, roleName string) (connectOutput, error) {
	accepted, err := acceptTeamInviteWithBootstrapAwebURL(homeDir, invite, alias)
	if err != nil {
		return connectOutput{}, err
	}
	awebURL := strings.TrimSpace(accepted.AwebURL)
	if awebURL == "" {
		awebURL = strings.TrimSpace(invite.AwebURL)
	}
	if awebURL == "" {
		awebURL = strings.TrimSpace(teamBootstrapAwebURL)
	}
	if awebURL == "" {
		awebURL = DefaultAwebURL
	}
	if err := upsertAcceptedTeamMembershipState(homeDir, accepted.Output, accepted.Certificate, accepted.RegistryURL, awebURL, true); err != nil {
		return connectOutput{}, err
	}
	return initCertificateConnectWithOptions(homeDir, awebURL, certificateConnectOptions{Role: strings.TrimSpace(roleName)})
}

func acceptTeamInviteWithBootstrapAwebURL(homeDir string, invite teamBootstrapInvite, alias string) (*acceptedTeamInvite, error) {
	preferredAwebURL := strings.TrimSpace(invite.AwebURL)
	if preferredAwebURL == "" {
		preferredAwebURL = strings.TrimSpace(teamBootstrapAwebURL)
	}
	if preferredAwebURL == "" {
		return acceptTeamInviteWithDetails(homeDir, invite.Token, alias, "")
	}

	previous, hadPrevious := os.LookupEnv("AWEB_URL")
	if err := os.Setenv("AWEB_URL", preferredAwebURL); err != nil {
		return nil, err
	}
	defer func() {
		if hadPrevious {
			_ = os.Setenv("AWEB_URL", previous)
		} else {
			_ = os.Unsetenv("AWEB_URL")
		}
	}()
	return acceptTeamInviteWithDetails(homeDir, invite.Token, alias, "")
}

func createTeamBootstrapInviteFromCurrentWorkspace() (teamBootstrapInvite, error) {
	wd, err := os.Getwd()
	if err != nil {
		return teamBootstrapInvite{}, err
	}
	return createTeamBootstrapInviteFromWorkspace(wd)
}

func createTeamBootstrapInviteFromWorkspace(workingDir string) (teamBootstrapInvite, error) {
	sel, err := resolveSelectionForDir(workingDir)
	if err != nil {
		return teamBootstrapInvite{}, err
	}
	teamID := strings.TrimSpace(sel.TeamID)
	if teamID == "" {
		return teamBootstrapInvite{}, fmt.Errorf("workspace %s has no active team", workingDir)
	}
	teamDomain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return teamBootstrapInvite{}, err
	}
	awebURL := awebURLForTeamInvite(workingDir, teamID)
	if awebURL == "" {
		awebURL = strings.TrimSpace(sel.BaseURL)
	}
	if exists, err := awconfig.TeamKeyExists(teamDomain, teamName); err != nil {
		return teamBootstrapInvite{}, err
	} else if exists {
		registryURL := registryURLForTeamInvite(workingDir, teamDomain, awebURL)
		_, token, err := createTeamInviteToken(teamDomain, teamName, registryURL, awebURL, true)
		return teamBootstrapInvite{Token: token, AwebURL: awebURL}, err
	}
	_, token, err := createHostedTeamInviteToken(workingDir, teamID, true)
	return teamBootstrapInvite{Token: token, AwebURL: awebURL}, err
}

func createTeamBootstrapBYOTInvite() (teamBootstrapInvite, error) {
	namespace := awconfig.NormalizeDomain(strings.TrimSpace(teamBootstrapNamespace))
	teamName := strings.ToLower(strings.TrimSpace(teamBootstrapTeamName))
	if namespace == "" {
		return teamBootstrapInvite{}, usageError("--namespace is required for one-step team bootstrap")
	}
	if teamName == "" {
		return teamBootstrapInvite{}, usageError("--team is required for one-step team bootstrap")
	}

	awebURL := strings.TrimSpace(teamBootstrapAwebURL)
	if awebURL == "" {
		awebURL = DefaultAwebURL
	}
	awebURL, err := normalizeAwebBaseURL(awebURL)
	if err != nil {
		return teamBootstrapInvite{}, fmt.Errorf("invalid --aweb-url: %w", err)
	}

	controllerKey, err := awconfig.LoadControllerKey(namespace)
	if err != nil {
		return teamBootstrapInvite{}, fmt.Errorf(
			"no local namespace controller key for %s: %w\n\nRun `aw id namespace prepare-controller --domain %s` first.",
			namespace,
			err,
			namespace,
		)
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return teamBootstrapInvite{}, err
	}
	registryURL := strings.TrimSpace(teamBootstrapRegistryURL)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return teamBootstrapInvite{}, fmt.Errorf("invalid --registry: %w", err)
		}
	}
	resolvedRegistryURL := strings.TrimSpace(registry.DefaultRegistryURL)

	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plan := &idCreatePlan{Domain: namespace, RegistryURL: resolvedRegistryURL, ControllerDID: controllerDID}
	if err := ensureStandaloneNamespace(ctx, registry, plan, controllerKey); err != nil {
		return teamBootstrapInvite{}, fmt.Errorf("ensure namespace %s: %w", namespace, err)
	}

	// Ensure the team exists (creates ~/.awid/team-keys/<namespace>/<team>.key if needed).
	if _, err := ensureLocalTeamRegistered(
		ctx,
		registry,
		resolvedRegistryURL,
		namespace,
		teamName,
		strings.TrimSpace(teamBootstrapTeamDisplayName),
		controllerKey,
	); err != nil {
		return teamBootstrapInvite{}, err
	}

	_, token, err := createTeamInviteToken(namespace, teamName, resolvedRegistryURL, awebURL, true)
	return teamBootstrapInvite{Token: token, AwebURL: awebURL}, err
}

func addWorktreeViaPrimaryInvite(
	primaryDir, worktreePath, root, branchName string, branchCreated bool,
	sourceServerURL, alias, role string, state *awconfig.WorktreeWorkspace,
) (connectOutput, error) {
	invite, err := createTeamBootstrapInviteFromWorkspace(primaryDir)
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("create team invite from primary workspace: %w", err)
	}
	if strings.TrimSpace(invite.AwebURL) == "" {
		invite.AwebURL = sourceServerURL
	}

	accepted, err := acceptTeamInviteWithBootstrapAwebURL(worktreePath, invite, alias)
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("accept team invite in new worktree: %w", err)
	}

	awebURL := strings.TrimSpace(accepted.AwebURL)
	if awebURL == "" {
		awebURL = strings.TrimSpace(invite.AwebURL)
	}
	if awebURL == "" {
		awebURL = strings.TrimSpace(sourceServerURL)
	}
	if awebURL == "" {
		awebURL = DefaultAwebURL
	}
	if err := upsertAcceptedTeamMembershipState(worktreePath, accepted.Output, accepted.Certificate, accepted.RegistryURL, awebURL, true); err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, err
	}

	fmt.Fprintln(os.Stderr, "Connecting new workspace...")
	connectResult, err := initCertificateConnectWithOptions(worktreePath, awebURL, certificateConnectOptions{
		Role:      role,
		HumanName: strings.TrimSpace(state.HumanName),
		AgentType: strings.TrimSpace(state.AgentType),
	})
	if err != nil {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("connect new worktree: %w", err)
	}
	if strings.TrimSpace(connectResult.Alias) != "" && !strings.EqualFold(strings.TrimSpace(connectResult.Alias), alias) {
		cleanupWorkspaceWorktree(root, worktreePath, branchName, branchCreated)
		return connectOutput{}, fmt.Errorf("new workspace connected as alias %q, expected %q", strings.TrimSpace(connectResult.Alias), alias)
	}
	return connectResult, nil
}

func validateTeamBootstrapSpec(templateDir string, spec *teamBootstrapSpec) error {
	if len(spec.Roles) == 0 {
		return fmt.Errorf("team.yaml must define at least one role")
	}
	if len(spec.Agents) == 0 {
		return fmt.Errorf("team.yaml must define at least one agent responsibility")
	}
	for name, role := range spec.Roles {
		name = strings.TrimSpace(name)
		if name == "" {
			return fmt.Errorf("role name must not be empty")
		}
		if strings.TrimSpace(role.File) == "" {
			return fmt.Errorf("role %q missing file", name)
		}
		if _, err := os.Stat(filepath.Join(templateDir, role.File)); err != nil {
			return fmt.Errorf("role %q file %q: %w", name, role.File, err)
		}
	}
	for responsibility, agent := range spec.Agents {
		responsibility = strings.TrimSpace(responsibility)
		if responsibility == "" {
			return fmt.Errorf("agent responsibility must not be empty")
		}
		if strings.TrimSpace(agent.RoleName) == "" {
			return fmt.Errorf("agent %q missing role_name", responsibility)
		}
		if _, ok := spec.Roles[agent.RoleName]; !ok {
			return fmt.Errorf("agent %q references unknown role_name %q", responsibility, agent.RoleName)
		}
		if work := strings.TrimSpace(agent.Work); work != "" && work != teamBootstrapWorkRepoRoot && work != teamBootstrapWorkGitWorktree {
			return fmt.Errorf("agent %q has unsupported work %q (expected repo_root or git_worktree)", responsibility, work)
		}
		sourceHome, err := teamBootstrapAgentSourceHome(templateDir, responsibility, agent)
		if err != nil {
			return err
		}
		agentsMD := filepath.Join(sourceHome, "AGENTS.md")
		if _, err := os.Stat(agentsMD); err != nil {
			return fmt.Errorf("agent %q instructions %q: %w", responsibility, agentsMD, err)
		}
	}
	for i, wt := range spec.Worktrees {
		name := strings.TrimSpace(wt.Name)
		if name == "" {
			return fmt.Errorf("worktrees[%d] missing name", i)
		}
		roleName := strings.TrimSpace(wt.RoleName)
		if roleName == "" {
			return fmt.Errorf("worktrees[%d] %q missing role_name", i, name)
		}
		if _, ok := spec.Roles[roleName]; !ok {
			return fmt.Errorf("worktrees[%d] %q references unknown role_name %q", i, name, roleName)
		}
	}
	return nil
}

func teamBootstrapAgentSourceHome(templateDir, responsibility string, agent teamBootstrapAgentSpec) (string, error) {
	if rel := strings.TrimSpace(agent.HomeTemplate); rel != "" {
		clean, err := cleanTeamBootstrapTemplateRelPath("home_template", rel)
		if err != nil {
			return "", fmt.Errorf("agent %q %w", responsibility, err)
		}
		return filepath.Join(templateDir, clean), nil
	}
	candidate := filepath.Join(templateDir, "home", responsibility)
	if info, err := os.Stat(candidate); err == nil && info.IsDir() {
		return candidate, nil
	} else if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	// Legacy template shape, kept for compatibility.
	return filepath.Join(templateDir, "agents", responsibility), nil
}

func cleanTeamBootstrapTemplateRelPath(field, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", usageError("%s must not be empty", field)
	}
	if filepath.IsAbs(value) {
		return "", usageError("%s must be a relative template path", field)
	}
	clean := filepath.Clean(value)
	if clean == "." {
		return "", usageError("%s must name a template directory", field)
	}
	for _, part := range strings.Split(clean, string(filepath.Separator)) {
		if part == ".." {
			return "", usageError("%s must not contain .. path traversal", field)
		}
	}
	return clean, nil
}

func buildTeamBootstrapPlans(in io.Reader, out io.Writer, templateDir, homeRoot string, spec *teamBootstrapSpec, askForAgentNames bool) ([]teamBootstrapAgentPlan, error) {
	if askForAgentNames && !isTTY() {
		return nil, usageError("--ask-for-agent-names requires an interactive terminal")
	}
	responsibilities := make([]string, 0, len(spec.Agents))
	for responsibility := range spec.Agents {
		responsibilities = append(responsibilities, responsibility)
	}
	sort.Strings(responsibilities)

	plans := make([]teamBootstrapAgentPlan, 0, len(responsibilities))
	for _, responsibility := range responsibilities {
		agent := spec.Agents[responsibility]
		sourceHome, err := teamBootstrapAgentSourceHome(templateDir, responsibility, agent)
		if err != nil {
			return nil, err
		}
		name := strings.TrimSpace(agent.DefaultName)
		if name == "" {
			name = responsibility
		}
		if askForAgentNames && isTTY() {
			prompted, err := promptRequiredStringWithIO("Agent name for "+responsibility, name, in, out)
			if err != nil {
				return nil, err
			}
			name = prompted
		}
		plans = append(plans, teamBootstrapAgentPlan{
			Responsibility: responsibility,
			RoleName:       agent.RoleName,
			Name:           name,
			Alias:          strings.TrimSpace(agent.DefaultAlias),
			HomeDir:        filepath.Join(homeRoot, responsibility),
			SourceHome:     sourceHome,
			Instructions:   filepath.Join(sourceHome, "AGENTS.md"),
			WorkBinding:    strings.TrimSpace(agent.Work),
		})
	}
	return plans, nil
}

func primaryTeamBootstrapPlan(plans []teamBootstrapAgentPlan) (teamBootstrapAgentPlan, error) {
	if len(plans) == 0 {
		return teamBootstrapAgentPlan{}, fmt.Errorf("no agents defined")
	}
	return plans[0], nil
}

func installTeamBootstrapOverridesAfterConnect(spec *teamBootstrapSpec, templateDir string, plans []teamBootstrapAgentPlan) (bool, bool, error) {
	if teamBootstrapSkipRoles && teamBootstrapSkipInstructions {
		return false, false, nil
	}
	primary, err := primaryTeamBootstrapPlan(plans)
	if err != nil {
		return false, false, err
	}
	client, _, err := resolveClientSelectionForDir(primary.HomeDir)
	if err != nil {
		return false, false, err
	}

	rolesInstalled := false
	instructionsInstalled := false
	if !teamBootstrapSkipRoles {
		if err := installTeamBootstrapRolesWithClient(client, spec, templateDir); err != nil {
			return false, false, err
		}
		rolesInstalled = true
	}
	if !teamBootstrapSkipInstructions {
		installed, err := installTeamBootstrapInstructionsWithClient(client, spec, templateDir)
		if err != nil {
			return false, false, err
		}
		instructionsInstalled = installed
	}
	return rolesInstalled, instructionsInstalled, nil
}

func installTeamBootstrapRolesWithClient(client *aweb.Client, spec *teamBootstrapSpec, templateDir string) error {
	if client == nil {
		return fmt.Errorf("nil aweb client")
	}
	bundle := aweb.TeamRolesBundle{Roles: map[string]aweb.RoleDefinition{}}
	for name, role := range spec.Roles {
		body, err := os.ReadFile(filepath.Join(templateDir, role.File))
		if err != nil {
			return err
		}
		title := strings.TrimSpace(role.Title)
		if title == "" {
			title = humanizeRoleName(name)
		}
		bundle.Roles[name] = aweb.RoleDefinition{Title: title, PlaybookMD: string(body)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	active, err := client.ActiveTeamRoles(ctx, aweb.ActiveTeamRolesParams{OnlySelected: false})
	if err != nil {
		return err
	}
	created, err := client.CreateTeamRoles(ctx, &aweb.CreateTeamRolesRequest{
		Bundle:          bundle,
		BaseTeamRolesID: active.TeamRolesID,
	})
	if err != nil {
		return err
	}
	_, err = client.ActivateTeamRoles(ctx, created.TeamRolesID)
	return err
}

func installTeamBootstrapInstructionsWithClient(client *aweb.Client, spec *teamBootstrapSpec, templateDir string) (bool, error) {
	if client == nil {
		return false, fmt.Errorf("nil aweb client")
	}
	file := strings.TrimSpace(spec.Instructions.File)
	if file == "" {
		candidate := filepath.Join(templateDir, "docs", "team.md")
		if _, err := os.Stat(candidate); err == nil {
			file = filepath.Join("docs", "team.md")
		} else {
			return false, nil
		}
	}
	body, err := os.ReadFile(filepath.Join(templateDir, file))
	if err != nil {
		return false, err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	active, err := client.ActiveTeamInstructions(ctx)
	if err != nil {
		return false, err
	}
	created, err := client.CreateTeamInstructions(ctx, &aweb.CreateTeamInstructionsRequest{
		Document:               aweb.TeamInstructionsDocument{BodyMD: string(body), Format: "markdown"},
		BaseTeamInstructionsID: active.TeamInstructionsID,
	})
	if err != nil {
		return false, err
	}
	if _, err := client.ActivateTeamInstructions(ctx, created.TeamInstructionsID); err != nil {
		return false, err
	}
	return true, nil
}

func materializeTeamBootstrapAgent(templateDir string, plan teamBootstrapAgentPlan, workDirectory string) error {
	if err := os.MkdirAll(plan.HomeDir, 0o755); err != nil {
		return err
	}

	agentsMDPath := filepath.Join(plan.HomeDir, "AGENTS.md")
	absDst, derr := filepath.Abs(agentsMDPath)
	absSrc, serr := filepath.Abs(plan.Instructions)
	if derr != nil {
		return derr
	}
	if serr != nil {
		return serr
	}
	if absSrc != absDst {
		if err := linkOrCopyFile(plan.Instructions, agentsMDPath); err != nil {
			return err
		}
	} else if _, err := os.Stat(agentsMDPath); err != nil {
		return err
	}

	claudePath := filepath.Join(plan.HomeDir, "CLAUDE.md")
	_ = os.Remove(claudePath)
	if err := os.Symlink("AGENTS.md", claudePath); err != nil {
		data, rerr := os.ReadFile(agentsMDPath)
		if rerr != nil {
			return rerr
		}
		if werr := os.WriteFile(claudePath, data, 0o644); werr != nil {
			return werr
		}
	}

	workDirectory = strings.TrimSpace(workDirectory)
	if workDirectory == "" {
		return fmt.Errorf("--work-directory is required")
	}
	workLink := filepath.Join(plan.HomeDir, "work")
	_ = os.Remove(workLink)
	if err := os.Symlink(workDirectory, workLink); err != nil {
		return err
	}
	return nil
}

func linkOrCopyFile(src, dst string) error {
	_ = os.Remove(dst)
	absSrc, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	if err := os.Symlink(absSrc, dst); err == nil {
		return nil
	}
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dst, data, 0o644)
}

func copyFile(src, dst string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, data, info.Mode().Perm())
}

func copyDir(src, dst string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("%s is not a directory", src)
	}
	if err := os.MkdirAll(dst, info.Mode().Perm()); err != nil {
		return err
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())
		entryInfo, err := entry.Info()
		if err != nil {
			return err
		}
		if entryInfo.IsDir() {
			if err := copyDir(srcPath, dstPath); err != nil {
				return err
			}
			continue
		}
		if entryInfo.Mode()&os.ModeType != 0 {
			return fmt.Errorf("unsupported special file in template: %s", srcPath)
		}
		if err := copyFile(srcPath, dstPath); err != nil {
			return err
		}
	}
	return nil
}

func plannedInitCommands(plans []teamBootstrapAgentPlan) []string {
	commands := make([]string, 0, len(plans))
	for _, plan := range plans {
		initParts := []string{
			"aw", "init",
			"--name", plan.Name,
			"--role-name", plan.RoleName,
			"--do-not-touch-agents-md",
		}
		if plan.Alias != "" {
			initParts = append(initParts, "--alias", plan.Alias)
		}
		commands = append(commands, "cd "+shellQuote(plan.HomeDir)+" && "+formatShellCommand(initParts))
	}
	return commands
}

func humanizeRoleName(name string) string {
	name = strings.ReplaceAll(name, "-", " ")
	name = strings.ReplaceAll(name, "_", " ")
	parts := strings.Fields(name)
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func formatTeamBootstrapOutput(v any) string {
	out := v.(teamBootstrapOutput)
	var b strings.Builder
	if out.DryRun {
		b.WriteString("Team bootstrap plan (dry run)\n")
	} else {
		b.WriteString("Team bootstrap complete\n")
	}
	if strings.TrimSpace(out.TemplateRef) != "" {
		b.WriteString(fmt.Sprintf("Template ref: %s\n", out.TemplateRef))
	}
	b.WriteString(fmt.Sprintf("Template: %s\n", out.TemplateDir))
	if out.TemplateCloned {
		if out.TemplateRefreshed {
			b.WriteString("Template: cloned (refreshed)\n")
		} else {
			b.WriteString("Template: cloned\n")
		}
	} else if out.TemplateRefreshed {
		b.WriteString("Template: refreshed\n")
	}
	if out.TeamName != "" {
		b.WriteString(fmt.Sprintf("Team template: %s\n", out.TeamName))
	}
	b.WriteString(fmt.Sprintf("Agent home root: %s\n", out.HomeRoot))
	if out.RolesInstalled {
		b.WriteString("Roles: installed and activated\n")
	} else if !teamBootstrapSkipRoles {
		b.WriteString("Roles: not installed\n")
	}
	if out.InstructionsInstalled {
		b.WriteString("Instructions: installed and activated\n")
	}
	if strings.TrimSpace(out.WorkDirectory) != "" {
		if out.LayoutMode == string(teamBootstrapLayoutInRepo) {
			b.WriteString(fmt.Sprintf("Project repo: %s\n", out.WorkDirectory))
		} else {
			b.WriteString(fmt.Sprintf("Work directory: %s\n", out.WorkDirectory))
		}
	}
	if strings.TrimSpace(out.WorkRepoURL) != "" {
		b.WriteString(fmt.Sprintf("Work repo url: %s\n", out.WorkRepoURL))
	}
	b.WriteString("\nAgents:\n")
	for _, agent := range out.Agents {
		alias := ""
		if agent.Alias != "" {
			alias = " alias=" + agent.Alias
		}
		work := ""
		if strings.TrimSpace(agent.WorkDir) != "" {
			work = " work=" + agent.WorkDir
			if strings.TrimSpace(agent.WorkBinding) != "" {
				work += " (" + agent.WorkBinding + ")"
			}
		}
		b.WriteString(fmt.Sprintf("- %s: name=%s role=%s%s home=%s%s\n", agent.Responsibility, agent.Name, agent.RoleName, alias, agent.HomeDir, work))
	}
	if len(out.NextCommands) > 0 {
		b.WriteString("\nInitialize/connect each agent workspace:\n")
		for _, command := range out.NextCommands {
			b.WriteString("  " + command + "\n")
		}
	}
	return b.String()
}
