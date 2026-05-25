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
  agents/<responsibility>/AGENTS.md
  team.yaml              maps agent responsibility dirs to aw role names

team.yaml supplies the parts that cannot be inferred safely: role bundle
metadata, each agent responsibility's role_name, and default identity names.
Agent directory names are responsibilities (for example implementation or
review), not fixed human/agent names; bootstrap prompts for the actual name
unless --yes is used.`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamBootstrap,
}

var (
	teamBootstrapHomeRoot         string
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
	teamBootstrapRegistryURL      string
	teamBootstrapAwebURL          string
	teamBootstrapDryRun           bool
	teamBootstrapYes              bool
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
	Instructions   string `json:"instructions"`
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
	WorkDirectory         string                   `json:"work_directory"`
	WorkRepoURL           string                   `json:"work_repo_url,omitempty"`
	Agents                []teamBootstrapAgentPlan `json:"agents"`
	NextCommands          []string                 `json:"next_commands,omitempty"`
}

func init() {
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapHomeRoot, "home-root", "", "Directory where agent workspaces are created (default: <template-dir>/agents)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkDirectory, "work-directory", "", "Directory symlinked into each agent workspace as ./work (mutually exclusive with --work-repo-url)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkRepoURL, "work-repo-url", "", "Git URL or local repo path to clone into <template-dir>/worktrees/<derived-name> (mutually exclusive with --work-directory)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkRepo, "work-repo", "", "Deprecated alias for --work-directory (kept for one release cycle)")
	_ = teamBootstrapCmd.Flags().MarkHidden("work-repo")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTemplateCacheDir, "template-cache-dir", "", "Directory where remote templates are cloned (advanced; defaults to cloning into the current directory)")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapRefreshTemplate, "refresh-template", false, "Re-clone the template into the destination directory before using it")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapForkTemplate, "fork", false, "Fork the template repository with gh and clone the fork into the destination directory")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapUsername, "username", "", "Hosted onboarding username to create/use (prompts when omitted and onboarding is used)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapNamespace, "namespace", "", "BYOD team namespace domain to create/use (required for one-step BYOD team bootstrap)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTeamName, "team", "", "BYOD team name/slug to create/use (required for one-step BYOD team bootstrap)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTeamDisplayName, "team-display-name", "", "Optional team display name when creating a new BYOD team")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapRegistryURL, "registry", "", "AWID registry URL override")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapAwebURL, "aweb-url", "", "Aweb server base URL to connect each generated agent workspace")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapDryRun, "dry-run", false, "Validate and print the bootstrap plan without changing files or team roles")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapYes, "yes", false, "Accept default agent names without prompting")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapSkipRoles, "skip-roles", false, "Do not install the roles bundle")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapSkipInstructions, "skip-instructions", false, "Do not install shared team instructions")

	teamTopCmd.AddCommand(teamBootstrapCmd)
	rootCmd.AddCommand(teamTopCmd)
	teamTopCmd.GroupID = groupWorkspace
	bindTeamSelector(teamTopCmd)
}

func runTeamBootstrap(cmd *cobra.Command, args []string) error {
	resolved, err := resolveTeamBootstrapTemplate(cmd, args[0])
	if err != nil {
		return err
	}
	spec, err := loadTeamBootstrapSpec(resolved.TemplateDir)
	if err != nil {
		return err
	}
	if err := validateTeamBootstrapSpec(resolved.TemplateDir, spec); err != nil {
		return err
	}

	homeRoot := strings.TrimSpace(teamBootstrapHomeRoot)
	if homeRoot == "" {
		homeRoot = filepath.Join(resolved.TemplateDir, "agents")
	}
	homeRoot, err = filepath.Abs(homeRoot)
	if err != nil {
		return err
	}

	workDirectory, workRepoURL, err := resolveTeamBootstrapWorkDirectoryAndRepoURL(resolved.TemplateDir)
	if err != nil {
		return err
	}

	plans, err := buildTeamBootstrapPlans(cmd.InOrStdin(), cmd.ErrOrStderr(), resolved.TemplateDir, homeRoot, spec, teamBootstrapYes)
	if err != nil {
		return err
	}

	out := teamBootstrapOutput{
		TemplateRef:       templateRefForOutput(args[0]),
		TemplateDir:       resolved.TemplateDir,
		TemplateCloned:    resolved.Cloned,
		TemplateRefreshed: resolved.Refreshed,
		TeamName:          spec.Name,
		DryRun:            teamBootstrapDryRun,
		HomeRoot:          homeRoot,
		WorkDirectory:     workDirectory,
		WorkRepoURL:       workRepoURL,
		Agents:            plans,
	}

	if teamBootstrapDryRun {
		out.NextCommands = plannedInitCommands(plans)
		printOutput(out, formatTeamBootstrapOutput)
		return nil
	}

	if workRepoURL != "" {
		if err := ensureTeamBootstrapWorktreesGitIgnored(resolved.TemplateDir); err != nil {
			return err
		}
	}
	if err := ensureTeamBootstrapWorkRepoReady(workDirectory, workRepoURL, spec); err != nil {
		return err
	}

	for _, plan := range plans {
		if err := materializeTeamBootstrapAgent(resolved.TemplateDir, plan, workDirectory); err != nil {
			return err
		}
	}

	autoBYOD := strings.TrimSpace(teamBootstrapNamespace) != "" || strings.TrimSpace(teamBootstrapTeamName) != ""
	autoHosted := !autoBYOD && (isTTY() || strings.TrimSpace(teamBootstrapUsername) != "")

	if autoBYOD {
		if err := bootstrapBYODTeamAndInitAgentDirs(cmd, plans); err != nil {
			return err
		}
		rolesInstalled, instructionsInstalled, err := installTeamBootstrapOverridesAfterConnect(spec, resolved.TemplateDir, plans)
		if err != nil {
			return err
		}
		out.RolesInstalled = rolesInstalled
		out.InstructionsInstalled = instructionsInstalled
		out.NextCommands = nil
	} else if autoHosted {
		if err := bootstrapHostedTeamAndInitAgentDirs(cmd, resolved.TemplateDir, plans); err != nil {
			return err
		}
		rolesInstalled, instructionsInstalled, err := installTeamBootstrapOverridesAfterConnect(spec, resolved.TemplateDir, plans)
		if err != nil {
			return err
		}
		out.RolesInstalled = rolesInstalled
		out.InstructionsInstalled = instructionsInstalled
		out.NextCommands = nil
	} else {
		if !teamBootstrapSkipRoles {
			if err := installTeamBootstrapRoles(spec, resolved.TemplateDir); err != nil {
				return err
			}
			out.RolesInstalled = true
		}
		if !teamBootstrapSkipInstructions {
			installed, err := installTeamBootstrapInstructions(spec, resolved.TemplateDir)
			if err != nil {
				return err
			}
			out.InstructionsInstalled = installed
		}
		out.NextCommands = plannedInitCommands(plans)
	}
	if out.NextCommands == nil {
		if err := bootstrapTeamBootstrapWorktreeAgents(cmd, resolved.TemplateDir, workDirectory, spec, plans); err != nil {
			return err
		}
	}

	printOutput(out, formatTeamBootstrapOutput)
	return nil
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
}

func resolveTeamBootstrapTemplate(cmd *cobra.Command, templateRef string) (*resolvedTeamBootstrapTemplate, error) {
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
	destDir, err := resolveTeamBootstrapTemplateDestDir(cmd, slug)
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
			return &resolvedTeamBootstrapTemplate{TemplateDir: destDir, Cloned: true, Refreshed: teamBootstrapRefreshTemplate}, nil
		}
		if err := os.MkdirAll(filepath.Dir(destDir), 0o755); err != nil {
			return nil, err
		}
		if err := runGitClone(cmd, cloneURL, destDir); err != nil {
			return nil, err
		}
		return &resolvedTeamBootstrapTemplate{TemplateDir: destDir, Cloned: true, Refreshed: teamBootstrapRefreshTemplate}, nil
	} else if err != nil {
		return nil, err
	}
	return &resolvedTeamBootstrapTemplate{TemplateDir: destDir, Cloned: false, Refreshed: false}, nil
}

func resolveTeamBootstrapTemplateDestDir(cmd *cobra.Command, slug string) (string, error) {
	slug = strings.TrimSpace(slug)
	if slug == "" {
		return "", fmt.Errorf("internal error: empty template slug")
	}
	// Advanced override: clone into a dedicated cache directory.
	if strings.TrimSpace(teamBootstrapTemplateCacheDir) != "" {
		base, err := filepath.Abs(strings.TrimSpace(teamBootstrapTemplateCacheDir))
		if err != nil {
			return "", err
		}
		return filepath.Join(base, slug), nil
	}

	wd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	inside, err := isInsideGitWorktree(wd)
	if err != nil {
		return "", err
	}
	if inside {
		return "", fmt.Errorf(
			"refusing to clone a template into an existing git worktree (%s). "+
				"Run from an empty directory, or pass --template-cache-dir to clone elsewhere.",
			wd,
		)
	}
	return filepath.Join(wd, slug), nil
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
		_, err = addWorktreeViaCloudBootstrap(
			worktreePath, workRepoRoot, branchName, branchCreated,
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
			_, err = addWorktreeViaCloudBootstrap(
				worktreePath, workRepoRoot, branchName, branchCreated,
				sourceServerURL, wt.Alias, wt.RoleName, workspaceState,
			)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func bootstrapBYODTeamAndInitAgentDirs(cmd *cobra.Command, plans []teamBootstrapAgentPlan) error {
	namespace := awconfig.NormalizeDomain(strings.TrimSpace(teamBootstrapNamespace))
	teamName := strings.ToLower(strings.TrimSpace(teamBootstrapTeamName))
	if namespace == "" {
		return usageError("--namespace is required for one-step team bootstrap")
	}
	if teamName == "" {
		return usageError("--team is required for one-step team bootstrap")
	}

	awebURL := strings.TrimSpace(teamBootstrapAwebURL)
	if awebURL == "" {
		awebURL = DefaultAwebURL
	}
	var err error
	awebURL, err = normalizeAwebBaseURL(awebURL)
	if err != nil {
		return fmt.Errorf("invalid --aweb-url: %w", err)
	}

	controllerKey, err := awconfig.LoadControllerKey(namespace)
	if err != nil {
		return fmt.Errorf(
			"no local namespace controller key for %s: %w\n\nRun `aw id namespace prepare-controller --domain %s` first.",
			namespace,
			err,
			namespace,
		)
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := strings.TrimSpace(teamBootstrapRegistryURL)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return fmt.Errorf("invalid --registry: %w", err)
		}
	}
	resolvedRegistryURL := strings.TrimSpace(registry.DefaultRegistryURL)

	// Ensure namespace exists at the registry.
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	plan := &idCreatePlan{Domain: namespace, RegistryURL: resolvedRegistryURL, ControllerDID: controllerDID}
	if err := ensureStandaloneNamespace(ctx, registry, plan, controllerKey); err != nil {
		return fmt.Errorf("ensure namespace %s: %w", namespace, err)
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
		return err
	}

	for _, agent := range plans {
		if err := ensureConnectTargetClean(agent.HomeDir); err != nil {
			return err
		}
		alias := strings.TrimSpace(agent.Alias)
		if alias == "" {
			alias = sanitizeSlug(agent.Name)
		}
		_, token, err := createTeamInviteToken(namespace, teamName, resolvedRegistryURL, awebURL, true)
		if err != nil {
			return err
		}
		accepted, err := acceptTeamInviteWithDetails(agent.HomeDir, token, alias, "")
		if err != nil {
			return err
		}
		if err := upsertAcceptedTeamMembershipState(agent.HomeDir, accepted.Output, accepted.Certificate, accepted.RegistryURL, awebURL, true); err != nil {
			return err
		}
		if _, err := initCertificateConnectWithOptions(agent.HomeDir, awebURL, certificateConnectOptions{Role: agent.RoleName}); err != nil {
			return err
		}
	}
	return nil
}

func bootstrapHostedTeamAndInitAgentDirs(cmd *cobra.Command, templateDir string, plans []teamBootstrapAgentPlan) error {
	_ = templateDir // reserved for future template-driven hosted defaults.

	primary, err := primaryTeamBootstrapPlan(plans)
	if err != nil {
		return err
	}

	// 1) Create/connect the first agent workspace using the same codepath as `aw init`.
	// We deliberately do not reimplement hosted onboarding here.
	username := strings.TrimSpace(teamBootstrapUsername)
	if username == "" && !isTTY() {
		return usageError("--username is required when not running in a TTY")
	}
	if err := ensureConnectTargetClean(primary.HomeDir); err != nil {
		return err
	}

	primaryAlias := strings.TrimSpace(primary.Alias)
	if primaryAlias == "" {
		primaryAlias = sanitizeSlug(primary.Name)
	}

	awebURL := strings.TrimSpace(teamBootstrapAwebURL)
	registryURL := strings.TrimSpace(teamBootstrapRegistryURL)
	result, err := guidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir:         primary.HomeDir,
		PromptIn:           cmd.InOrStdin(),
		PromptOut:          cmd.ErrOrStderr(),
		BaseURL:            awebURL,
		RegistryURL:        registryURL,
		Username:           username,
		Alias:              primaryAlias,
		Role:               primary.RoleName,
		Persistent:         false,
		InjectAgentDocs:    false,
		DoNotTouchAgentsMD: true,
		AskPostCreateSetup: false,
		NonInteractive:     !isTTY() || teamBootstrapYes,
	})
	if err != nil {
		return err
	}
	_ = result

	// Resolve the active team + server URLs from the initialized primary workspace.
	sel, err := resolveSelectionForDir(primary.HomeDir)
	if err != nil {
		return err
	}
	teamID := strings.TrimSpace(sel.TeamID)
	if teamID == "" {
		return fmt.Errorf("bootstrap: primary workspace is missing team_id")
	}
	serviceURLs, err := resolveOnboardingServiceURLs(strings.TrimSpace(sel.BaseURL))
	if err != nil {
		return err
	}

	// 2) For each additional agent: create an invite (same codepath as `aw id team invite`),
	// accept it (same codepath as `aw id team accept-invite`), then connect (same codepath as `aw init`).
	for _, agent := range plans {
		if agent.HomeDir == primary.HomeDir {
			continue
		}
		alias := strings.TrimSpace(agent.Alias)
		if alias == "" {
			alias = sanitizeSlug(agent.Name)
		}
		if err := ensureConnectTargetClean(agent.HomeDir); err != nil {
			return err
		}

		_, token, err := createHostedTeamInviteToken(primary.HomeDir, teamID, true)
		if err != nil {
			return err
		}
		accepted, err := acceptTeamInviteWithDetails(agent.HomeDir, token, alias, "")
		if err != nil {
			return err
		}
		if _, err := initCertificateConnectWithOptions(agent.HomeDir, serviceURLs.AwebURL, certificateConnectOptions{Role: agent.RoleName}); err != nil {
			return err
		}
		_ = accepted
	}

	return nil
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
		agentsMD := filepath.Join(templateDir, "agents", responsibility, "AGENTS.md")
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

func buildTeamBootstrapPlans(in io.Reader, out io.Writer, templateDir, homeRoot string, spec *teamBootstrapSpec, acceptDefaults bool) ([]teamBootstrapAgentPlan, error) {
	responsibilities := make([]string, 0, len(spec.Agents))
	for responsibility := range spec.Agents {
		responsibilities = append(responsibilities, responsibility)
	}
	sort.Strings(responsibilities)

	plans := make([]teamBootstrapAgentPlan, 0, len(responsibilities))
	for _, responsibility := range responsibilities {
		agent := spec.Agents[responsibility]
		name := strings.TrimSpace(agent.DefaultName)
		if name == "" {
			name = responsibility
		}
		if !acceptDefaults && isTTY() {
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
			Instructions:   filepath.Join(templateDir, "agents", responsibility, "AGENTS.md"),
		})
	}
	return plans, nil
}

func primaryTeamBootstrapPlan(plans []teamBootstrapAgentPlan) (teamBootstrapAgentPlan, error) {
	if len(plans) == 0 {
		return teamBootstrapAgentPlan{}, fmt.Errorf("no agents defined")
	}
	primary := plans[0]
	for _, candidate := range plans {
		if candidate.Responsibility == "implementation" {
			primary = candidate
			break
		}
	}
	return primary, nil
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

func installTeamBootstrapRoles(spec *teamBootstrapSpec, templateDir string) error {
	client, _, err := resolveClientSelection()
	if err != nil {
		return err
	}
	return installTeamBootstrapRolesWithClient(client, spec, templateDir)
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

func installTeamBootstrapInstructions(spec *teamBootstrapSpec, templateDir string) (bool, error) {
	client, _, err := resolveClientSelection()
	if err != nil {
		return false, err
	}
	return installTeamBootstrapInstructionsWithClient(client, spec, templateDir)
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
		b.WriteString(fmt.Sprintf("Work directory: %s\n", out.WorkDirectory))
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
		b.WriteString(fmt.Sprintf("- %s: name=%s role=%s%s home=%s\n", agent.Responsibility, agent.Name, agent.RoleName, alias, agent.HomeDir))
	}
	if len(out.NextCommands) > 0 {
		b.WriteString("\nInitialize/connect each agent workspace:\n")
		for _, command := range out.NextCommands {
			b.WriteString("  " + command + "\n")
		}
	}
	return b.String()
}
