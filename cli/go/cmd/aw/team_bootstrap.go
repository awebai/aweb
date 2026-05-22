package main

import (
	"context"
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
	teamBootstrapWorkRepo         string
	teamBootstrapTemplateCacheDir string
	teamBootstrapRefreshTemplate  bool
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
	WorkRepo              string                   `json:"work_repo,omitempty"`
	Agents                []teamBootstrapAgentPlan `json:"agents"`
	NextCommands          []string                 `json:"next_commands,omitempty"`
}

func init() {
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapHomeRoot, "home-root", "", "Directory where agent home/workspace dirs are created (default: ./.aw/team-agents/<template-name>)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkRepo, "work-repo", "", "Optional repository to symlink into each agent home as work")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTemplateCacheDir, "template-cache-dir", "", "Directory where remote templates are cloned (default: OS cache dir under aw/team-templates)")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapRefreshTemplate, "refresh-template", false, "Refresh an existing cloned template with git fetch before using it")
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
		homeRoot = filepath.Join(".", ".aw", "team-agents", filepath.Base(resolved.TemplateDir))
	}
	homeRoot, err = filepath.Abs(homeRoot)
	if err != nil {
		return err
	}

	workRepo := strings.TrimSpace(teamBootstrapWorkRepo)
	if workRepo != "" {
		workRepo, err = filepath.Abs(workRepo)
		if err != nil {
			return err
		}
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
		WorkRepo:          workRepo,
		Agents:            plans,
	}

	if teamBootstrapDryRun {
		out.NextCommands = plannedInitCommands(plans)
		printOutput(out, formatTeamBootstrapOutput)
		return nil
	}

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

	for _, plan := range plans {
		if err := materializeTeamBootstrapAgent(resolved.TemplateDir, plan, workRepo); err != nil {
			return err
		}
	}
	out.NextCommands = plannedInitCommands(plans)
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

	cloneURL, slug, err := resolveTeamBootstrapCloneURL(templateRef)
	if err != nil {
		return nil, err
	}
	cacheDir, err := resolveTeamBootstrapTemplateCacheDir()
	if err != nil {
		return nil, err
	}
	destDir := filepath.Join(cacheDir, slug)
	if teamBootstrapRefreshTemplate {
		if _, err := os.Stat(destDir); err == nil {
			if err := os.RemoveAll(destDir); err != nil {
				return nil, err
			}
		}
	}
	if _, err := os.Stat(destDir); errors.Is(err, os.ErrNotExist) {
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

func resolveTeamBootstrapTemplateCacheDir() (string, error) {
	if strings.TrimSpace(teamBootstrapTemplateCacheDir) != "" {
		return filepath.Abs(strings.TrimSpace(teamBootstrapTemplateCacheDir))
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "aw", "team-templates"), nil
}

func resolveTeamBootstrapCloneURL(ref string) (string, string, error) {
	ref = strings.TrimSpace(ref)
	if strings.HasPrefix(ref, "gh:") {
		repo := strings.TrimPrefix(ref, "gh:")
		repo = strings.Trim(repo, "/")
		parts := strings.Split(repo, "/")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			return "", "", fmt.Errorf("invalid gh: template ref %q (expected gh:OWNER/REPO)", ref)
		}
		slug := sanitizeSlug(parts[0] + "-" + parts[1])
		return "https://github.com/" + parts[0] + "/" + parts[1] + ".git", slug, nil
	}

	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		u, err := url.Parse(ref)
		if err != nil {
			return "", "", err
		}
		path := strings.Trim(u.Path, "/")
		path = strings.TrimSuffix(path, ".git")
		parts := strings.Split(path, "/")
		slug := sanitizeSlug(parts[len(parts)-1])
		if len(parts) >= 2 {
			slug = sanitizeSlug(parts[len(parts)-2] + "-" + parts[len(parts)-1])
		}
		return ref, slug, nil
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
			return "", "", fmt.Errorf("invalid git template ref %q", ref)
		}
		slug := sanitizeSlug(parts[len(parts)-1])
		if len(parts) >= 2 {
			slug = sanitizeSlug(parts[len(parts)-2] + "-" + parts[len(parts)-1])
		}
		return ref, slug, nil
	}

	return "", "", fmt.Errorf("template ref %q is not a directory and is not a supported git URL (use a local dir, gh:OWNER/REPO, https://..., or git@...)", ref)
}

func runGitClone(cmd *cobra.Command, cloneURL string, destDir string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	git := exec.CommandContext(ctx, "git", "clone", "--depth", "1", cloneURL, destDir)
	git.Stdout = cmd.OutOrStdout()
	git.Stderr = cmd.ErrOrStderr()
	return git.Run()
}

func templateRefForOutput(raw string) string {
	return strings.TrimSpace(raw)
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

func installTeamBootstrapRoles(spec *teamBootstrapSpec, templateDir string) error {
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

	client, _, err := resolveClientSelection()
	if err != nil {
		return err
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
	client, _, err := resolveClientSelection()
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

func materializeTeamBootstrapAgent(templateDir string, plan teamBootstrapAgentPlan, workRepo string) error {
	if err := os.MkdirAll(plan.HomeDir, 0o755); err != nil {
		return err
	}
	if err := linkOrCopyFile(plan.Instructions, filepath.Join(plan.HomeDir, "AGENTS.md")); err != nil {
		return err
	}
	claudePath := filepath.Join(plan.HomeDir, "CLAUDE.md")
	_ = os.Remove(claudePath)
	if err := os.Symlink("AGENTS.md", claudePath); err != nil {
		if err := linkOrCopyFile(plan.Instructions, claudePath); err != nil {
			return err
		}
	}
	if workRepo != "" {
		workLink := filepath.Join(plan.HomeDir, "work")
		_ = os.Remove(workLink)
		if err := os.Symlink(workRepo, workLink); err != nil {
			return err
		}
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
	if out.WorkRepo != "" {
		b.WriteString(fmt.Sprintf("Work repo: %s\n", out.WorkRepo))
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
