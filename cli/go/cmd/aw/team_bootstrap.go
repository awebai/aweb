package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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

var agentsCmd = &cobra.Command{
	Use:   "agents",
	Short: "Manage repo-local agent layouts and provisioning",
	Long: `Manage repo-local agent layouts and provisioning.

The agents command family manages the project-local agents/ convention:
shared layout, agent homes, worktree-bound agents, and per-agent workspace
provisioning. It does not manage AWID team authority in general; use aw id team
for membership and team-controller operations.

Run aw agents commands from the customer project repo root unless a subcommand
explicitly says otherwise. The repo root itself is not an aw identity; generated
agent homes live under agents/home/<responsibility>.`,
}

var teamBootstrapCmd = &cobra.Command{
	Use:   "bootstrap <template>",
	Short: "Bootstrap repo-local agents from a template repository",
	Long: `Bootstrap repo-local agents from a template repository.

The template repository is convention-first:

  docs/                  shared team/project instructions
  roles/                 role playbooks installed with aw roles set
  home/<responsibility>/AGENTS.md
  team.yaml              maps agent responsibility dirs to aw role names

team.yaml supplies the parts that cannot be inferred safely: role bundle
metadata, each agent responsibility's role_name, work binding, identity scope,
and optional naming policy. Agent directory names are responsibilities (for
example coordinator, implementation, or review), not fixed human/agent names.

By default bootstrap runs in the current project git repo and creates an
agents/ convention directory:

  agents/home/<responsibility>/      agent homes; run Codex/Claude from here
  agents/worktrees/<worktree-name>/  generated git worktrees for worktree agents

Use --agents-dir to choose a different project-local convention directory.
Passing --work-directory or --work-repo-url selects the legacy out-of-repo mode.

Bootstrap allocates per-human aliases and global addresses from the template
naming policy. If the layout uses {user}, pass --identity-prefix or set
AWEB_IDENTITY_PREFIX, AWEB_HUMAN, or USER before running non-interactively.
Pass --ask-for-agent-names only when you want an interactive prompt to override
generated display names before provisioning.`,
	Args: cobra.ExactArgs(1),
	RunE: runTeamBootstrap,
}

var agentsPlanCmd = &cobra.Command{
	Use:   "plan",
	Short: "Plan repo-local agent names and paths",
	Long: `Plan repo-local agent names and paths.

For BYOT planning with --namespace/--team, aw agents plan contacts the AWID
registry to fail closed on existing team aliases and namespace addresses.`,
	Args: cobra.NoArgs,
	RunE: runAgentsPlan,
}

var agentsProvisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Provision identities for an existing agents layout",
	Args:  cobra.NoArgs,
	RunE:  runAgentsProvision,
}

var agentsAddCmd = &cobra.Command{
	Use:   "add <responsibility>",
	Short: "Add a responsibility to the agents layout",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentsAdd,
}

var agentsAddWorktreeCmd = &cobra.Command{
	Use:   "add-worktree [role]",
	Short: "Create a repo-local git worktree and initialize a new local agent in it",
	Args:  cobra.RangeArgs(0, 1),
	RunE:  runAgentsAddWorktree,
}

var agentsRemoveCmd = &cobra.Command{
	Use:   "remove <responsibility>",
	Short: "Remove or deprovision an agent responsibility",
	Args:  cobra.ExactArgs(1),
	RunE:  runAgentsRemove,
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
	teamBootstrapLayoutOnly       bool
	teamBootstrapYes              bool // deprecated no-op; defaults are used unless --ask-for-agent-names is set
	teamBootstrapAskAgentNames    bool
	teamBootstrapSkipRoles        bool
	teamBootstrapSkipInstructions bool
	agentsIdentityPrefix          string
	agentsAddLocal                bool
	agentsAddGlobal               bool
	agentsAddRole                 string
	agentsAddWorktreeAlias        string
	agentsAddLayoutOnly           bool
	agentsRemoveDeprovisionLocal  bool
	agentsRemoveRemoveLayout      bool
	agentsRemoveDeleteAddress     bool
	agentsAddMaterializeAgent     = materializeTeamBootstrapAgent
	agentsAddInitPrimaryAgent     = initTeamBootstrapPrimaryAgent
	agentsAddInitAdditionalAgent  = initTeamBootstrapAdditionalAgent
	agentsAddClaimIdentityAddress = func(ctx context.Context, registry *awid.RegistryClient, registryURL string, params awid.AtomicAddressClaimParams) (*awid.AtomicAddressClaimResult, error) {
		return registry.ClaimIdentityAddressAt(ctx, registryURL, params)
	}
	agentsAddEnsureGlobalCertificate = ensureAgentsAddGlobalCertificate
	agentsAddConnectGlobalAgent      = initCertificateConnectWithOptions
)

type teamBootstrapSpec struct {
	Name         string                            `yaml:"name"`
	Instructions teamBootstrapInstructionsSpec     `yaml:"instructions"`
	Roles        map[string]teamBootstrapRoleSpec  `yaml:"roles"`
	Naming       teamBootstrapNamingSpec           `yaml:"naming,omitempty"`
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

type teamBootstrapNamingSpec struct {
	LocalAlias  teamBootstrapNamingRuleSpec `yaml:"local_alias,omitempty"`
	GlobalAlias teamBootstrapNamingRuleSpec `yaml:"global_alias,omitempty"`
	GlobalName  teamBootstrapNamingRuleSpec `yaml:"global_name,omitempty"`
	Worktree    teamBootstrapNamingRuleSpec `yaml:"worktree,omitempty"`
}

type teamBootstrapNamingRuleSpec struct {
	Sequence string `yaml:"sequence,omitempty"`
	Pattern  string `yaml:"pattern,omitempty"`
}

type teamBootstrapAgentSpec struct {
	RoleName      string `yaml:"role_name"`
	DefaultName   string `yaml:"default_name,omitempty"`
	DefaultAlias  string `yaml:"default_alias,omitempty"`
	IdentityScope string `yaml:"identity_scope,omitempty"`
	Work          string `yaml:"work,omitempty"`
	HomeTemplate  string `yaml:"home_template,omitempty"`
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
	IdentityScope  string `json:"identity_scope,omitempty"`
	GlobalAddress  string `json:"global_address,omitempty"`
	HomeDir        string `json:"home_dir"`
	WorkspaceDir   string `json:"workspace_dir,omitempty"`
	SourceHome     string `json:"-"`
	Instructions   string `json:"instructions"`
	WorkBinding    string `json:"work_binding,omitempty"`
	WorktreeName   string `json:"worktree_name,omitempty"`
	WorkDir        string `json:"work_dir,omitempty"`
}

type teamBootstrapOutput struct {
	TemplateRef       string `json:"template_ref,omitempty"`
	TemplateDir       string `json:"template_dir"`
	TemplateCloned    bool   `json:"template_cloned"`
	TemplateRefreshed bool   `json:"template_refreshed"`

	TeamName              string                   `json:"team_name,omitempty"`
	DryRun                bool                     `json:"dry_run"`
	LayoutOnly            bool                     `json:"layout_only,omitempty"`
	RolesInstalled        bool                     `json:"roles_installed"`
	InstructionsInstalled bool                     `json:"instructions_installed"`
	HomeRoot              string                   `json:"home_root"`
	AgentsDir             string                   `json:"agents_dir,omitempty"`
	LayoutMode            string                   `json:"layout_mode,omitempty"`
	WorkDirectory         string                   `json:"work_directory"`
	WorkRepoURL           string                   `json:"work_repo_url,omitempty"`
	IdentityPrefix        string                   `json:"identity_prefix,omitempty"`
	Availability          []agentsProvisionCheck   `json:"availability,omitempty"`
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

type agentsProvisionOutput struct {
	DryRun         bool                     `json:"dry_run"`
	AgentsDir      string                   `json:"agents_dir"`
	IdentityPrefix string                   `json:"identity_prefix"`
	TeamSource     string                   `json:"team_source,omitempty"`
	Agents         []teamBootstrapAgentPlan `json:"agents"`
	Availability   []agentsProvisionCheck   `json:"availability,omitempty"`
	NextCommands   []string                 `json:"next_commands,omitempty"`
}

type agentsProvisionCheck struct {
	Responsibility string `json:"responsibility"`
	Field          string `json:"field"`
	Value          string `json:"value"`
	Status         string `json:"status"`
	Source         string `json:"source"`
}

type agentsAddOutput struct {
	DryRun         bool                   `json:"dry_run"`
	LayoutOnly     bool                   `json:"layout_only"`
	AgentsDir      string                 `json:"agents_dir"`
	Responsibility string                 `json:"responsibility"`
	RoleName       string                 `json:"role_name"`
	RoleCreated    bool                   `json:"role_created"`
	IdentityPrefix string                 `json:"identity_prefix,omitempty"`
	Agent          teamBootstrapAgentPlan `json:"agent"`
	Availability   []agentsProvisionCheck `json:"availability,omitempty"`
	TeamSource     string                 `json:"team_source,omitempty"`
	Warnings       []string               `json:"warnings,omitempty"`
}

type agentsRemoveOutput struct {
	DryRun               bool                 `json:"dry_run"`
	AgentsDir            string               `json:"agents_dir"`
	Responsibility       string               `json:"responsibility"`
	HomeDir              string               `json:"home_dir"`
	WorkspaceDir         string               `json:"workspace_dir,omitempty"`
	WorkBinding          string               `json:"work_binding,omitempty"`
	WorkDir              string               `json:"work_dir,omitempty"`
	TeamID               string               `json:"team_id,omitempty"`
	MemberAddress        string               `json:"member_address,omitempty"`
	GlobalAddressDeleted bool                 `json:"global_address_deleted,omitempty"`
	LocalBackupDir       string               `json:"local_backup_dir,omitempty"`
	Actions              []agentsRemoveAction `json:"actions"`
	Warnings             []string             `json:"warnings,omitempty"`
}

type agentsRemoveAction struct {
	Name   string `json:"name"`
	Status string `json:"status"`
	Detail string `json:"detail,omitempty"`
}

type agentsAddGlobalPendingState struct {
	Version               int                   `yaml:"version"`
	Responsibility        string                `yaml:"responsibility"`
	RoleName              string                `yaml:"role_name"`
	Alias                 string                `yaml:"alias"`
	GlobalAddress         string                `yaml:"global_address"`
	IdentityPrefix        string                `yaml:"identity_prefix,omitempty"`
	Domain                string                `yaml:"domain"`
	AddressName           string                `yaml:"address_name"`
	TeamName              string                `yaml:"team_name"`
	TeamID                string                `yaml:"team_id"`
	DIDAW                 string                `yaml:"did_aw"`
	CurrentDIDKey         string                `yaml:"current_did_key"`
	RegistryURL           string                `yaml:"registry_url"`
	AwebURL               string                `yaml:"aweb_url"`
	AtomicClaimApplied    bool                  `yaml:"atomic_claim_applied,omitempty"`
	CertificateRegistered bool                  `yaml:"certificate_registered,omitempty"`
	Certificate           *awid.TeamCertificate `yaml:"certificate,omitempty"`
	CreatedAt             string                `yaml:"created_at"`
}

type agentsProvisionState int

const (
	agentsProvisionStateClean agentsProvisionState = iota
	agentsProvisionStateAlreadyProvisioned
)

func init() {
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapHomeRoot, "home-root", "", "Legacy mode: directory where agent workspaces are created (default: <template-dir>/agents)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapAgentsDir, "agents-dir", "agents", "Project-local directory to create for in-repo bootstrap output")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkDirectory, "work-directory", "", "Legacy mode: directory symlinked into each agent workspace as ./work (mutually exclusive with --work-repo-url)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkRepoURL, "work-repo-url", "", "Legacy mode: git URL or local repo path to clone into <template-dir>/worktrees/<derived-name> (mutually exclusive with --work-directory)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapWorkRepo, "work-repo", "", "Deprecated alias for --work-directory (kept for one release cycle)")
	_ = teamBootstrapCmd.Flags().MarkHidden("work-repo")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTemplateCacheDir, "template-cache-dir", "", "Directory where remote templates are cloned (advanced; in-repo mode defaults to a temporary checkout)")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapRefreshTemplate, "refresh-template", false, "Re-clone the template into the destination directory before using it")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapForkTemplate, "fork", false, "Fork the template repository with gh and clone the fork into the destination directory")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapUsername, "username", "", "Hosted onboarding username to create/use (prompts when omitted and onboarding is used)")
	teamBootstrapCmd.Flags().StringVar(&agentsIdentityPrefix, "identity-prefix", "", "Human-specific prefix for generated global aliases and addresses (default: AWEB_IDENTITY_PREFIX, AWEB_HUMAN, or USER)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapNamespace, "namespace", "", "BYOT team namespace domain to create/use (required for one-step BYOT agents bootstrap)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTeamName, "team", "", "BYOT team name/slug to create/use (required for one-step BYOT agents bootstrap)")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapTeamDisplayName, "team-display-name", "", "Optional team display name when creating a new BYOT team")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapInviteToken, "invite-token", "", "Team invite token to accept into the first generated agent workspace")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapRegistryURL, "registry", "", "AWID registry URL override")
	teamBootstrapCmd.Flags().StringVar(&teamBootstrapAwebURL, "aweb-url", "", "Aweb server base URL to connect each generated agent workspace")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapDryRun, "dry-run", false, "Validate and print the bootstrap plan without changing files or team roles")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapLayoutOnly, "layout-only", false, "Only create the shared agents layout; do not create identities, team memberships, roles, or instructions")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapYes, "yes", false, "Deprecated no-op; template naming policy is used unless --ask-for-agent-names is set")
	_ = teamBootstrapCmd.Flags().MarkHidden("yes")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapAskAgentNames, "ask-for-agent-names", false, "Prompt for generated display names instead of using template responsibilities")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapSkipRoles, "skip-roles", false, "Do not install the roles bundle")
	teamBootstrapCmd.Flags().BoolVar(&teamBootstrapSkipInstructions, "skip-instructions", false, "Do not install shared team instructions")

	bindAgentsProvisionFlags(agentsPlanCmd)
	bindAgentsProvisionFlags(agentsProvisionCmd)
	bindAgentsProvisionFlags(agentsAddCmd)
	agentsAddCmd.Flags().BoolVar(&agentsAddLocal, "local", false, "Add a local team-scoped agent identity (default)")
	agentsAddCmd.Flags().BoolVar(&agentsAddGlobal, "global", false, "Add a global AWID identity/address-backed agent")
	agentsAddCmd.Flags().StringVar(&agentsAddRole, "role", "", "Role name to bind this responsibility to (default: responsibility)")
	agentsAddCmd.Flags().BoolVar(&agentsAddLayoutOnly, "layout-only", false, "Only update the shared agents layout; do not create local identity state")
	agentsAddWorktreeCmd.Flags().StringVar(&teamBootstrapAgentsDir, "agents-dir", "agents", "Project-local agents directory to read")
	agentsAddWorktreeCmd.Flags().BoolVar(&teamBootstrapDryRun, "dry-run", false, "Validate and print the worktree plan without changing files or team state")
	agentsAddWorktreeCmd.Flags().StringVar(&agentsAddRole, "role", "", "Existing team role for the new worktree agent")
	agentsAddWorktreeCmd.Flags().StringVar(&agentsAddWorktreeAlias, "alias", "", "Override the default generated alias/worktree name")

	agentsRemoveCmd.Flags().BoolVar(&teamBootstrapDryRun, "dry-run", false, "Show the remove/deprovision plan without mutating local, git, or registry state")
	agentsRemoveCmd.Flags().BoolVar(&agentsRemoveDeprovisionLocal, "deprovision-local", false, "Revoke this local agent membership where authority is available, move aside local .aw state, and remove generated worktree checkout")
	agentsRemoveCmd.Flags().BoolVar(&agentsRemoveRemoveLayout, "remove-layout", false, "Remove the shared responsibility from agents/team.yaml and move aside generated home source files")
	agentsRemoveCmd.Flags().BoolVar(&agentsRemoveDeleteAddress, "delete-global-address", false, "Also delete the global namespace address after membership revocation; preserves global addresses by default")

	agentsCmd.AddCommand(
		teamBootstrapCmd,
		agentsPlanCmd,
		agentsProvisionCmd,
		agentsAddCmd,
		agentsAddWorktreeCmd,
		agentsRemoveCmd,
	)
	rootCmd.AddCommand(agentsCmd)
	agentsCmd.GroupID = groupWorkspace
	bindTeamSelector(agentsCmd)
}

func bindAgentsProvisionFlags(cmd *cobra.Command) {
	cmd.Flags().StringVar(&teamBootstrapAgentsDir, "agents-dir", "agents", "Project-local agents directory to read")
	cmd.Flags().StringVar(&agentsIdentityPrefix, "identity-prefix", "", "Human-specific prefix for generated global aliases and addresses (default: AWEB_IDENTITY_PREFIX, AWEB_HUMAN, or USER)")
	cmd.Flags().StringVar(&teamBootstrapUsername, "username", "", "Not supported for existing agents layouts; use aw agents bootstrap --username for first-time hosted setup, or join with AWEB_API_KEY, --invite-token, --namespace/--team, or current workspace forwarding")
	cmd.Flags().StringVar(&teamBootstrapNamespace, "namespace", "", "BYOT team namespace domain to create/use")
	cmd.Flags().StringVar(&teamBootstrapTeamName, "team", "", "BYOT team name/slug to create/use")
	cmd.Flags().StringVar(&teamBootstrapTeamDisplayName, "team-display-name", "", "Optional team display name when creating a new BYOT team")
	cmd.Flags().StringVar(&teamBootstrapInviteToken, "invite-token", "", "Team invite token to accept into the first generated agent workspace")
	cmd.Flags().StringVar(&teamBootstrapRegistryURL, "registry", "", "AWID registry URL override")
	cmd.Flags().StringVar(&teamBootstrapAwebURL, "aweb-url", "", "Aweb server base URL to connect each generated agent workspace")
	cmd.Flags().BoolVar(&teamBootstrapDryRun, "dry-run", false, "Validate and print the provisioning plan without changing files or team roles")
	cmd.Flags().BoolVar(&teamBootstrapSkipRoles, "skip-roles", false, "Do not install the roles bundle")
	cmd.Flags().BoolVar(&teamBootstrapSkipInstructions, "skip-instructions", false, "Do not install shared team instructions")
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
	identityPrefix, err := resolveAgentsIdentityPrefix(cmd)
	if err != nil {
		return err
	}
	namingInput, err := agentsNamingInputFromBootstrapPlans(layout, spec, plans, identityPrefix)
	if err != nil {
		return err
	}
	namingPlan, err := buildAgentsNamingPlan(namingInput)
	if err != nil {
		return err
	}
	plans, availability, err := applyAgentsNamingPlanToBootstrapPlans(plans, namingPlan)
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
		LayoutOnly:        teamBootstrapLayoutOnly,
		HomeRoot:          homeRoot,
		AgentsDir:         layout.AgentsRoot,
		LayoutMode:        string(layout.Mode),
		WorkDirectory:     workDirectory,
		WorkRepoURL:       workRepoURL,
		IdentityPrefix:    identityPrefix,
		Availability:      availability,
		Agents:            plans,
	}

	if teamBootstrapDryRun {
		out.NextCommands = plannedInitCommands(plans)
		printOutput(out, formatTeamBootstrapOutput)
		return nil
	}

	var source teamBootstrapSource
	if !teamBootstrapLayoutOnly {
		source, err = resolveTeamBootstrapSource()
		if err != nil {
			return err
		}
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

	if teamBootstrapLayoutOnly {
		out.NextCommands = plannedInitCommands(plans)
		printOutput(out, formatTeamBootstrapOutput)
		return nil
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

func runAgentsPlan(cmd *cobra.Command, args []string) error {
	out, _, _, _, err := buildAgentsProvisionOutput(cmd)
	if err != nil {
		return err
	}
	out.DryRun = true
	printOutput(out, formatAgentsProvisionOutput)
	return nil
}

func runAgentsProvision(cmd *cobra.Command, args []string) error {
	out, layout, spec, plans, err := buildAgentsProvisionOutput(cmd)
	if err != nil {
		return err
	}
	if teamBootstrapDryRun {
		out.DryRun = true
		printOutput(out, formatAgentsProvisionOutput)
		return nil
	}
	expectedTeamID, err := expectedAgentsProvisionTeamID()
	if err != nil {
		return err
	}
	state, err := assessAgentsProvisionState(plans, expectedTeamID)
	if err != nil {
		return err
	}
	var source teamBootstrapSource
	if state == agentsProvisionStateClean {
		source, err = resolveAgentsProvisionSource()
		if err != nil {
			return err
		}
	}
	if err := ensureInRepoProvisionWorktrees(layout, plans); err != nil {
		return err
	}
	for _, plan := range plans {
		planWorkDirectory := layout.CustomerRepoRoot
		if strings.TrimSpace(plan.WorkDir) != "" {
			planWorkDirectory = plan.WorkDir
		}
		if err := materializeTeamBootstrapAgent(layout.AgentsRoot, plan, planWorkDirectory); err != nil {
			return err
		}
	}
	if state == agentsProvisionStateAlreadyProvisioned {
		out.DryRun = false
		out.NextCommands = nil
		printOutput(out, formatAgentsProvisionOutput)
		return nil
	}
	rolesInstalled, instructionsInstalled, err := bootstrapTeamAndInitAgentDirs(cmd, source, spec, layout.AgentsRoot, plans)
	if err != nil {
		return err
	}
	out.DryRun = false
	out.TeamSource = string(source.Kind)
	out.NextCommands = nil
	_ = rolesInstalled
	_ = instructionsInstalled
	printOutput(out, formatAgentsProvisionOutput)
	return nil
}

func runAgentsAdd(cmd *cobra.Command, args []string) error {
	return runAgentsAddWithWorkBinding(cmd, args[0], agentsWorkRepoRoot)
}

func runAgentsAddWorktree(cmd *cobra.Command, args []string) error {
	if agentsAddGlobal {
		return usageError("aw agents add-worktree --global is not supported in v1; worktree-bound agents are local identities")
	}
	if agentsAddLayoutOnly {
		return usageError("aw agents add-worktree does not mutate the shared agents layout; --layout-only is not supported")
	}
	layout, err := resolveAgentsExistingLayoutPreflight()
	if err != nil {
		return err
	}
	lock, err := agentsLockExclusive(agentsAddLayoutLockPath(layout.AgentsRoot))
	if err != nil {
		return fmt.Errorf("lock agents layout: %w", err)
	}
	defer lock.Close()

	anchorDir, err := findAgentsProvisionAnchor(layout, "")
	if err != nil {
		return err
	}
	if anchorDir == "" {
		return usageError("aw agents add-worktree requires an existing provisioned agent in this agents layout for team-join authority; run `aw agents bootstrap` or `aw agents provision` first, or use `aw workspace add-worktree` outside an agents layout")
	}
	client, _, err := resolveClientSelectionForDir(anchorDir)
	if err != nil {
		return err
	}

	requestedRole, err := resolveAgentsAddWorktreeRequestedRole(cmd, args)
	if err != nil {
		return err
	}
	roleIn := io.Reader(os.Stdin)
	roleOut := io.Writer(os.Stderr)
	if cmd != nil {
		roleIn = cmd.InOrStdin()
		roleOut = cmd.ErrOrStderr()
	}
	allowRolePrompt := requestedRole == "" && isTTY()
	if roleIn != os.Stdin {
		allowRolePrompt = false
	}
	role, err := resolveRole(client, requestedRole, allowRolePrompt, roleIn, roleOut)
	if err != nil {
		return err
	}
	role = normalizeWorkspaceRole(role)
	if role != "" && !isValidWorkspaceRole(role) {
		return usageError("invalid role: use 1-2 words (letters/numbers) with hyphens/underscores allowed; max 50 chars")
	}

	state, teamState, _, err := awconfig.LoadWorkspaceAndTeamState(anchorDir)
	if err != nil {
		return fmt.Errorf("load anchor workspace binding: %w", err)
	}
	if !state.HasTeamBinding() {
		return usageError("anchor workspace %s is missing team binding; run `aw agents provision` first", anchorDir)
	}
	activeMembership := awconfig.ActiveMembershipFor(state, teamState)
	if activeMembership == nil {
		return usageError("anchor workspace %s is missing active_team membership; run `aw agents provision` first", anchorDir)
	}
	teamID := strings.TrimSpace(activeMembership.TeamID)
	if teamID == "" {
		return usageError("anchor workspace %s is missing team_id; run `aw agents provision` first", anchorDir)
	}
	sourceServerURL := strings.TrimSpace(state.AwebURL)
	if sourceServerURL == "" {
		return usageError("anchor workspace %s is missing aweb_url; run `aw agents provision` first", anchorDir)
	}

	alias := strings.TrimSpace(agentsAddWorktreeAlias)
	if alias != "" {
		if !isValidWorkspaceAlias(alias) {
			return usageError("invalid alias %q: must start with an alphanumeric and contain only alphanumerics, dashes, or underscores (max 64 chars)", alias)
		}
		teamAliases, err := fetchWorkspaceTeamAliases(client, strings.TrimSpace(activeMembership.WorkspaceID))
		if err != nil {
			return err
		}
		if teamAliases[strings.ToLower(alias)] {
			return usageError("alias %q is already in use by this team", alias)
		}
	} else {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		suggestion, err := client.SuggestAliasPrefix(ctx)
		cancel()
		if err != nil {
			return fmt.Errorf("suggest next alias from server: %w", err)
		}
		alias = strings.TrimSpace(suggestion.NamePrefix)
		if !isValidSuggestedAliasPrefix(alias) {
			return fmt.Errorf("server returned invalid alias suggestion %q", alias)
		}
	}

	branchName := alias
	worktreePath := filepath.Join(layout.WorktreesRoot, branchName)
	if _, err := os.Stat(worktreePath); err == nil {
		return usageError("worktree path %s already exists", worktreePath)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("stat worktree path %s: %w", worktreePath, err)
	}

	output := workspaceAddWorktreeOutput{
		Alias:        alias,
		Role:         role,
		Branch:       branchName,
		WorktreePath: worktreePath,
	}
	if teamBootstrapDryRun {
		printOutput(output, formatWorkspaceAddWorktree)
		return nil
	}

	if err := ensureAwebRuntimeUntrackedForAddWorktree(layout.CustomerRepoRoot); err != nil {
		return err
	}
	if err := ensureInRepoBootstrapGitignore(layout); err != nil {
		return err
	}
	if err := os.MkdirAll(layout.WorktreesRoot, 0o755); err != nil {
		return err
	}
	if !jsonFlag {
		fmt.Fprintf(os.Stderr, "Creating worktree for branch %q...\n", branchName)
		fmt.Fprintf(os.Stderr, "  Main repo: %s\n", layout.CustomerRepoRoot)
		fmt.Fprintf(os.Stderr, "  Worktree:  %s\n", worktreePath)
		fmt.Fprintf(os.Stderr, "  Role:      %s\n", role)
		fmt.Fprintf(os.Stderr, "  Alias:     %s\n\n", alias)
		fmt.Fprintln(os.Stderr, "Creating git worktree...")
	}
	branchCreated, err := createWorkspaceGitWorktree(layout.CustomerRepoRoot, worktreePath, branchName, jsonFlag)
	if err != nil {
		return fmt.Errorf("failed to create worktree: %w", err)
	}
	if err := ensureAwebRuntimeGitIgnored(worktreePath); err != nil {
		cleanupWorkspaceWorktree(layout.CustomerRepoRoot, worktreePath, branchName, branchCreated)
		return err
	}

	teamDomain, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		cleanupWorkspaceWorktree(layout.CustomerRepoRoot, worktreePath, branchName, branchCreated)
		return fmt.Errorf("invalid team_id in workspace.yaml: %w", err)
	}
	hasTeamKey, err := awconfig.TeamKeyExists(teamDomain, teamName)
	if err != nil {
		cleanupWorkspaceWorktree(layout.CustomerRepoRoot, worktreePath, branchName, branchCreated)
		return fmt.Errorf("check team key: %w", err)
	}

	if hasTeamKey {
		_, err = addWorktreeViaLocalTeamKey(
			worktreePath, layout.CustomerRepoRoot, branchName, branchCreated,
			teamID, teamDomain, teamName, sourceServerURL, anchorDir,
			alias, role, state,
		)
	} else if strings.TrimSpace(state.APIKey) != "" {
		_, err = addWorktreeViaCloudBootstrap(
			worktreePath, layout.CustomerRepoRoot, branchName, branchCreated,
			sourceServerURL, alias, role, state,
		)
	} else {
		_, err = addWorktreeViaPrimaryInvite(
			anchorDir, worktreePath, layout.CustomerRepoRoot, branchName, branchCreated,
			sourceServerURL, alias, role, state,
		)
	}
	if err != nil {
		return err
	}

	printOutput(output, formatWorkspaceAddWorktree)
	return nil
}

func resolveAgentsAddWorktreeRequestedRole(cmd *cobra.Command, args []string) (string, error) {
	positional := ""
	if len(args) > 0 {
		positional = strings.TrimSpace(args[0])
	}
	flag := strings.TrimSpace(agentsAddRole)
	if positional != "" && flag != "" && normalizeWorkspaceRole(positional) != normalizeWorkspaceRole(flag) {
		return "", usageError("role specified twice with different values: %q and %q", positional, flag)
	}
	if flag != "" {
		return flag, nil
	}
	return positional, nil
}

func runAgentsRemove(cmd *cobra.Command, args []string) error {
	if teamBootstrapDryRun {
		plan, err := buildAgentsRemovePlan(args[0])
		if err != nil {
			return err
		}
		plan.Output.DryRun = true
		printOutput(plan.Output, formatAgentsRemoveOutput)
		return nil
	}
	if !agentsRemoveDeprovisionLocal && !agentsRemoveRemoveLayout && !agentsRemoveDeleteAddress {
		return usageError("choose at least one remove effect: --deprovision-local, --remove-layout, or --delete-global-address. Use --dry-run to inspect the current state.")
	}
	if agentsRemoveDeleteAddress && !agentsRemoveDeprovisionLocal {
		return usageError("--delete-global-address must be paired with --deprovision-local so membership is revoked before the address is deleted")
	}
	layout, err := resolveAgentsExistingLayoutPreflight()
	if err != nil {
		return err
	}
	lock, err := agentsLockExclusive(agentsAddLayoutLockPath(layout.AgentsRoot))
	if err != nil {
		return fmt.Errorf("lock agents layout: %w", err)
	}
	defer lock.Close()

	plan, err := buildAgentsRemovePlan(args[0])
	if err != nil {
		return err
	}

	if agentsRemoveDeprovisionLocal {
		if err := executeAgentsRemoveRevokeMembership(plan); err != nil {
			return err
		}
	}
	if agentsRemoveDeleteAddress {
		if err := executeAgentsRemoveDeleteAddress(plan); err != nil {
			return err
		}
		plan.Output.GlobalAddressDeleted = true
	}

	if agentsRemoveDeprovisionLocal {
		if err := executeAgentsRemoveLocal(plan); err != nil {
			return err
		}
	}
	if agentsRemoveRemoveLayout {
		if err := executeAgentsRemoveLayout(plan); err != nil {
			return err
		}
	}

	printOutput(plan.Output, formatAgentsRemoveOutput)
	return nil
}

type agentsRemovePlan struct {
	Layout                   teamBootstrapLayout
	Spec                     *teamBootstrapSpec
	Agent                    teamBootstrapAgentSpec
	Output                   agentsRemoveOutput
	Identity                 *awconfig.WorktreeIdentity
	TeamState                *awconfig.TeamState
	Membership               *awconfig.TeamMembership
	Cert                     *awid.TeamCertificate
	HostedDeprovisionApplied bool
}

type agentsLayoutLock interface {
	Close() error
}

var agentsLockExclusive = func(lockPath string) (agentsLayoutLock, error) {
	return awconfig.LockExclusive(lockPath)
}

func buildAgentsRemovePlan(responsibilityRaw string) (*agentsRemovePlan, error) {
	layout, err := resolveAgentsExistingLayoutPreflight()
	if err != nil {
		return nil, err
	}
	spec, err := loadTeamBootstrapSpec(layout.AgentsRoot)
	if err != nil {
		return nil, err
	}
	if err := validateTeamBootstrapSpec(layout.AgentsRoot, spec); err != nil {
		return nil, err
	}
	responsibility, err := normalizeAgentsNamingField("responsibility", responsibilityRaw)
	if err != nil {
		return nil, err
	}
	agent, ok := spec.Agents[responsibility]
	if !ok {
		return nil, usageError("agents layout does not contain responsibility %q", responsibility)
	}
	homeDir := filepath.Join(layout.HomeRoot, responsibility)
	workBinding := strings.TrimSpace(agent.Work)
	if workBinding == "" {
		workBinding = agentsWorkRepoRoot
	}
	workDir := layout.CustomerRepoRoot
	if workBinding == agentsWorkGitWorktree {
		workDir = filepath.Join(layout.WorktreesRoot, responsibility)
		if target, err := os.Readlink(filepath.Join(homeDir, "work")); err == nil && strings.TrimSpace(target) != "" {
			workDir = target
		}
	}
	workspaceDir := homeDir
	legacyWorktreeState := false
	if workBinding == agentsWorkGitWorktree && strings.TrimSpace(workDir) != "" {
		workspaceDir = workDir
		if !agentsRemovePathExists(filepath.Join(workspaceDir, ".aw")) && agentsRemovePathExists(filepath.Join(homeDir, ".aw")) {
			workspaceDir = homeDir
			legacyWorktreeState = true
		}
	}

	identity, _, _ := awconfig.LoadWorktreeIdentityFromDir(workspaceDir)
	teamState, _ := awconfig.LoadTeamState(workspaceDir)
	var membership *awconfig.TeamMembership
	var cert *awid.TeamCertificate
	teamID := ""
	memberAddress := ""
	if teamState != nil {
		membership = teamState.ActiveMembership()
		if membership != nil {
			teamID = strings.TrimSpace(membership.TeamID)
			if loaded, err := awconfig.LoadTeamCertificateForTeam(workspaceDir, teamID); err == nil {
				cert = loaded
			}
		}
	}
	if cert != nil {
		if teamID == "" {
			teamID = strings.TrimSpace(cert.Team)
		}
		memberAddress = strings.TrimSpace(cert.MemberAddress)
	}
	if identity != nil {
		if memberAddress == "" {
			memberAddress = strings.TrimSpace(identity.Address)
		}
	}

	out := agentsRemoveOutput{
		AgentsDir:      layout.AgentsRoot,
		Responsibility: responsibility,
		HomeDir:        homeDir,
		WorkspaceDir:   workspaceDir,
		WorkBinding:    workBinding,
		WorkDir:        workDir,
		TeamID:         teamID,
		MemberAddress:  memberAddress,
	}
	if strings.TrimSpace(memberAddress) != "" && !agentsRemoveDeleteAddress {
		out.Warnings = append(out.Warnings, "global address is preserved by default; pass --delete-global-address to delete it after membership revocation")
	}
	if legacyWorktreeState {
		out.Warnings = append(out.Warnings, fmt.Sprintf("legacy worktree .aw state found at %s/.aw; this command will deprovision that state, then remove the git worktree. Run aw agents provision after upgrading to recreate worktree-bound runtime state under %s/.aw.", homeDir, workDir))
	}
	if agentsRemoveRemoveLayout && !agentsRemoveDeprovisionLocal && agentsRemovePathExists(filepath.Join(workspaceDir, ".aw")) {
		out.Warnings = append(out.Warnings, fmt.Sprintf("--remove-layout will leave active local .aw state for %s in %s without revoking membership; add --deprovision-local first if this agent should stop acting in the team", responsibility, workspaceDir))
	}
	if agentsRemoveDeprovisionLocal {
		out.Actions = append(out.Actions, agentsRemoveAction{Name: "revoke_membership", Status: agentsRemovePlannedOrSkipped(cert != nil), Detail: teamID})
		out.Actions = append(out.Actions, agentsRemoveAction{Name: "move_local_aw", Status: agentsRemovePlannedOrSkipped(agentsRemovePathExists(filepath.Join(workspaceDir, ".aw"))), Detail: filepath.Join(workspaceDir, ".aw")})
		if workBinding == agentsWorkGitWorktree {
			out.Actions = append(out.Actions, agentsRemoveAction{Name: "remove_git_worktree", Status: agentsRemovePlannedOrSkipped(agentsRemovePathExists(workDir)), Detail: workDir})
		}
	}
	if agentsRemoveDeleteAddress {
		out.Actions = append(out.Actions, agentsRemoveAction{Name: "delete_global_address", Status: agentsRemovePlannedOrSkipped(strings.TrimSpace(memberAddress) != ""), Detail: memberAddress})
	}
	if agentsRemoveRemoveLayout {
		out.Actions = append(out.Actions, agentsRemoveAction{Name: "remove_layout", Status: "planned", Detail: filepath.Join(layout.AgentsRoot, "team.yaml")})
		out.Actions = append(out.Actions, agentsRemoveAction{Name: "move_home", Status: agentsRemovePlannedOrSkipped(agentsRemovePathExists(homeDir)), Detail: homeDir})
	}
	if len(out.Actions) == 0 {
		out.Actions = append(out.Actions, agentsRemoveAction{Name: "none", Status: "pending_flags", Detail: "choose --deprovision-local, --remove-layout, or --delete-global-address"})
	}

	return &agentsRemovePlan{
		Layout:     layout,
		Spec:       spec,
		Agent:      agent,
		Output:     out,
		Identity:   identity,
		TeamState:  teamState,
		Membership: membership,
		Cert:       cert,
	}, nil
}

func agentsRemovePlannedOrSkipped(ok bool) string {
	if ok {
		return "planned"
	}
	return "skipped"
}

func agentsRemovePathExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func executeAgentsRemoveRevokeMembership(plan *agentsRemovePlan) error {
	if plan == nil {
		return nil
	}
	if plan.Cert == nil {
		if agentsRemoveDeleteAddress {
			return usageError("cannot delete global address for %s: no active team certificate was found in %s/.aw, so membership cannot be revoked first. Restore the matching team certificate or rerun without --delete-global-address.", plan.Output.Responsibility, agentsRemoveWorkspaceDir(plan))
		}
		return nil
	}
	teamID := strings.TrimSpace(plan.Output.TeamID)
	domain, team, err := splitAWIDTeamID(teamID)
	if err != nil {
		return err
	}
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		if hostedErr := executeAgentsRemoveHostedDeprovision(plan); hostedErr == nil {
			return nil
		} else {
			return usageError("cannot revoke team certificate for %s: self-custodial team controller key is unavailable (%v), and hosted self-deprovision failed (%v). Restore the matching ~/.awid/team-keys/%s/%s.key for customer-controlled teams, or ensure this hosted workspace has a valid aweb_url, .aw/signing.key, and active team certificate before retrying.", teamID, err, hostedErr, domain, team)
		}
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := agentsRemoveRegistryURL(plan)
	if registryURL == "" {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := registry.RevokeCertificate(ctx, registryURL, domain, team, plan.Cert.CertificateID, teamKey); err != nil {
		return fmt.Errorf("revoke team certificate for %s: %w. Local state was not moved; retry after revocation succeeds or rerun without --deprovision-local if you only intend a layout change.", plan.Output.Responsibility, err)
	}
	agentsRemoveMarkAction(&plan.Output, "revoke_membership", "done", plan.Cert.CertificateID)
	return nil
}

type agentsRemoveHostedDeprovisionRequest struct {
	DeleteGlobalAddress bool `json:"delete_global_address"`
}

type agentsRemoveHostedDeprovisionResponse struct {
	AgentID string `json:"agent_id"`
	Status  string `json:"status"`
}

func executeAgentsRemoveHostedDeprovision(plan *agentsRemovePlan) error {
	if plan == nil || plan.Cert == nil {
		return fmt.Errorf("missing active team certificate in local .aw state")
	}
	awebURL := agentsRemoveAwebURL(plan)
	if awebURL == "" {
		return fmt.Errorf("missing hosted service URL in .aw/teams.yaml")
	}
	workspaceDir := agentsRemoveWorkspaceDir(plan)
	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(workspaceDir))
	if err != nil {
		return fmt.Errorf("load local signing key for hosted self-deprovision: %w", err)
	}
	client, err := awid.NewWithCertificate(awebURL, signingKey, plan.Cert)
	if err != nil {
		return fmt.Errorf("create hosted certificate client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out agentsRemoveHostedDeprovisionResponse
	req := agentsRemoveHostedDeprovisionRequest{DeleteGlobalAddress: agentsRemoveDeleteAddress}
	if err := client.Post(ctx, "/api/v1/agents/me/deprovision", req, &out); err != nil {
		if agentsRemoveHostedAlreadyDeprovisioned(err) {
			plan.HostedDeprovisionApplied = true
			agentsRemoveMarkAction(&plan.Output, "revoke_membership", "done", "hosted self-deprovision already applied")
			if agentsRemoveDeleteAddress {
				agentsRemoveMarkAction(&plan.Output, "delete_global_address", "done", strings.TrimSpace(plan.Output.MemberAddress))
			}
			return nil
		}
		return fmt.Errorf("hosted self-deprovision: %w", err)
	}
	status := strings.TrimSpace(out.Status)
	if status == "" {
		status = "done"
	}
	plan.HostedDeprovisionApplied = true
	agentsRemoveMarkAction(&plan.Output, "revoke_membership", "done", "hosted self-deprovision "+status)
	if agentsRemoveDeleteAddress {
		agentsRemoveMarkAction(&plan.Output, "delete_global_address", "done", strings.TrimSpace(plan.Output.MemberAddress))
	}
	return nil
}

func agentsRemoveHostedAlreadyDeprovisioned(err error) bool {
	status, ok := awid.HTTPStatusCode(err)
	if !ok || status != http.StatusBadRequest && status != http.StatusNotFound {
		return false
	}
	body, ok := awid.HTTPErrorBody(err)
	if !ok {
		return false
	}
	code := hostedDeprovisionErrorCode(body)
	return code == "agent_not_found" || code == "agent_already_deprovisioned"
}

func hostedDeprovisionErrorCode(body string) string {
	body = strings.TrimSpace(body)
	if body == "" {
		return ""
	}
	var envelope struct {
		Detail struct {
			Code string `json:"code"`
		} `json:"detail"`
	}
	if err := json.Unmarshal([]byte(body), &envelope); err != nil {
		return ""
	}
	return strings.TrimSpace(envelope.Detail.Code)
}

func executeAgentsRemoveDeleteAddress(plan *agentsRemovePlan) error {
	if plan != nil && plan.HostedDeprovisionApplied {
		if strings.TrimSpace(plan.Output.MemberAddress) != "" {
			agentsRemoveMarkAction(&plan.Output, "delete_global_address", "done", strings.TrimSpace(plan.Output.MemberAddress))
		}
		return nil
	}
	address := strings.TrimSpace(plan.Output.MemberAddress)
	if address == "" {
		return usageError("--delete-global-address requested but no global member address was found in %s/.aw; local state was not moved", agentsRemoveWorkspaceDir(plan))
	}
	domain, name, err := parseAddress(address)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := executeIDNamespaceDeleteAddress(ctx, idNamespaceDeleteAddressOptions{
		Domain:      domain,
		Name:        name,
		RegistryURL: agentsRemoveRegistryURL(plan),
		Reason:      "aw agents remove --delete-global-address",
	}); err != nil {
		return fmt.Errorf("delete global address %s: %w. Local state was not moved; for self-custodial namespaces restore the matching ~/.awid controller key, for hosted custodial namespaces use the hosted session/API deletion path.", address, err)
	}
	agentsRemoveMarkAction(&plan.Output, "delete_global_address", "done", address)
	return nil
}

func executeAgentsRemoveLocal(plan *agentsRemovePlan) error {
	backupRoot, err := agentsRemoveBackupRoot(plan.Layout, plan.Output.Responsibility)
	if err != nil {
		return err
	}
	awDir := filepath.Join(agentsRemoveWorkspaceDir(plan), ".aw")
	if agentsRemovePathExists(awDir) {
		dst, err := movePathIntoBackup(awDir, backupRoot)
		if err != nil {
			return err
		}
		plan.Output.LocalBackupDir = backupRoot
		agentsRemoveMarkAction(&plan.Output, "move_local_aw", "done", dst)
	}
	if plan.Output.WorkBinding == agentsWorkGitWorktree && strings.TrimSpace(plan.Output.WorkDir) != "" {
		branchName, err := agentsAddGitWorktreeBranchName(teamBootstrapAgentPlan{
			Responsibility: plan.Output.Responsibility,
			WorkBinding:    agentsWorkGitWorktree,
			WorkDir:        plan.Output.WorkDir,
		})
		if err != nil {
			return err
		}
		cleanupWorkspaceWorktree(plan.Layout.CustomerRepoRoot, plan.Output.WorkDir, branchName, true)
		agentsRemoveMarkAction(&plan.Output, "remove_git_worktree", "done", plan.Output.WorkDir)
	}
	return nil
}

func agentsRemoveWorkspaceDir(plan *agentsRemovePlan) string {
	if plan == nil {
		return ""
	}
	if dir := strings.TrimSpace(plan.Output.WorkspaceDir); dir != "" {
		return dir
	}
	return strings.TrimSpace(plan.Output.HomeDir)
}

func executeAgentsRemoveLayout(plan *agentsRemovePlan) error {
	backupRoot, err := agentsRemoveBackupRoot(plan.Layout, plan.Output.Responsibility)
	if err != nil {
		return err
	}
	if agentsRemovePathExists(plan.Output.HomeDir) {
		dst, err := movePathIntoBackup(plan.Output.HomeDir, backupRoot)
		if err != nil {
			return err
		}
		plan.Output.LocalBackupDir = backupRoot
		agentsRemoveMarkAction(&plan.Output, "move_home", "done", dst)
	}
	delete(plan.Spec.Agents, plan.Output.Responsibility)
	if err := writeAgentsAddLayoutYAML(plan.Layout, plan.Spec); err != nil {
		return fmt.Errorf("remove layout for %s: %w. The home directory may already have been moved to backup %s; retry `aw agents remove --remove-layout %s` to finish removing the shared layout entry, or restore the backup before retrying if you want to keep the layout.", plan.Output.Responsibility, err, backupRoot, plan.Output.Responsibility)
	}
	agentsRemoveMarkAction(&plan.Output, "remove_layout", "done", filepath.Join(plan.Layout.AgentsRoot, "team.yaml"))
	return nil
}

func agentsRemoveBackupRoot(layout teamBootstrapLayout, responsibility string) (string, error) {
	sum := sha256.Sum256([]byte(filepath.Clean(layout.CustomerRepoRoot)))
	stamp := time.Now().UTC().Format("20060102T150405Z")
	safeResponsibility := sanitizeSlug(responsibility)
	if safeResponsibility == "" {
		safeResponsibility = "agent"
	}
	return awconfig.PathInAWIDState("agents-remove-backups", hex.EncodeToString(sum[:6])+"-"+safeResponsibility+"-"+stamp)
}

func movePathIntoBackup(src, backupRoot string) (string, error) {
	if err := os.MkdirAll(backupRoot, 0o700); err != nil {
		return "", err
	}
	dst := filepath.Join(backupRoot, filepath.Base(filepath.Clean(src)))
	for i := 2; agentsRemovePathExists(dst); i++ {
		dst = filepath.Join(backupRoot, fmt.Sprintf("%s-%d", filepath.Base(filepath.Clean(src)), i))
	}
	if err := os.Rename(src, dst); err != nil {
		return "", fmt.Errorf("move %s to %s: %w", src, dst, err)
	}
	return dst, nil
}

func agentsRemoveRegistryURL(plan *agentsRemovePlan) string {
	if plan == nil {
		return ""
	}
	if plan.Membership != nil && strings.TrimSpace(plan.Membership.RegistryURL) != "" {
		return strings.TrimSpace(plan.Membership.RegistryURL)
	}
	if plan.Identity != nil && strings.TrimSpace(plan.Identity.RegistryURL) != "" {
		return strings.TrimSpace(plan.Identity.RegistryURL)
	}
	return strings.TrimSpace(teamBootstrapRegistryURL)
}

func agentsRemoveAwebURL(plan *agentsRemovePlan) string {
	if plan == nil {
		return ""
	}
	if plan.Membership != nil {
		if u := strings.TrimSpace(plan.Membership.AwebURL); u != "" {
			return u
		}
	}
	return ""
}

func agentsRemoveMarkAction(out *agentsRemoveOutput, name, status, detail string) {
	if out == nil {
		return
	}
	for i := range out.Actions {
		if out.Actions[i].Name == name {
			out.Actions[i].Status = status
			out.Actions[i].Detail = detail
			return
		}
	}
	out.Actions = append(out.Actions, agentsRemoveAction{Name: name, Status: status, Detail: detail})
}

func splitAWIDTeamID(teamID string) (string, string, error) {
	team, domain, ok := strings.Cut(strings.TrimSpace(teamID), ":")
	if !ok || strings.TrimSpace(team) == "" || strings.TrimSpace(domain) == "" {
		return "", "", usageError("team_id %q is not in <team>:<namespace> form", teamID)
	}
	return awconfig.NormalizeDomain(domain), strings.ToLower(strings.TrimSpace(team)), nil
}

func teamBootstrapAgentWorkspaceDir(plan teamBootstrapAgentPlan) string {
	if dir := strings.TrimSpace(plan.WorkspaceDir); dir != "" {
		return dir
	}
	if strings.TrimSpace(plan.WorkBinding) == agentsWorkGitWorktree && strings.TrimSpace(plan.WorkDir) != "" {
		return strings.TrimSpace(plan.WorkDir)
	}
	return strings.TrimSpace(plan.HomeDir)
}

func runAgentsAddWithWorkBinding(cmd *cobra.Command, responsibilityRaw, workBinding string) error {
	if !teamBootstrapDryRun {
		layout, err := resolveAgentsExistingLayoutPreflight()
		if err != nil {
			return err
		}
		lock, err := agentsLockExclusive(agentsAddLayoutLockPath(layout.AgentsRoot))
		if err != nil {
			return fmt.Errorf("lock agents layout: %w", err)
		}
		defer lock.Close()
	}
	out, layout, spec, plan, err := buildAgentsAddOutput(cmd, responsibilityRaw, workBinding)
	if err != nil {
		return err
	}
	if teamBootstrapDryRun {
		out.DryRun = true
		printOutput(out, formatAgentsAddOutput)
		return nil
	}
	if plan.IdentityScope == agentsIdentityScopeGlobal && !agentsAddLayoutOnly {
		if workBinding == agentsWorkGitWorktree {
			return usageError("aw agents add-worktree --global is not supported in v1; use `aw agents add --global` for a repo-root global agent, or add a local worktree-bound agent")
		}
		return runAgentsAddGlobal(cmd, out, layout, spec, plan)
	}
	var source teamBootstrapSource
	anchorDir := ""
	if !agentsAddLayoutOnly {
		anchorDir, err = findAgentsProvisionAnchor(layout, plan.HomeDir)
		if err != nil {
			return err
		}
		if anchorDir == "" {
			source, err = resolveAgentsProvisionSource()
			if err != nil {
				return err
			}
			out.TeamSource = string(source.Kind)
		} else {
			out.TeamSource = string(teamBootstrapSourceCurrent)
		}
	}
	branchCreated := false
	if !agentsAddLayoutOnly && workBinding == agentsWorkGitWorktree {
		var err error
		branchCreated, err = createAgentsAddGitWorktree(layout, plan)
		if err != nil {
			return err
		}
	}
	if err := writeAgentsAddLayout(layout, spec, plan, out.RoleCreated); err != nil {
		if workBinding == agentsWorkGitWorktree {
			cleanupAgentsAddGitWorktree(layout, plan, branchCreated)
		}
		return err
	}
	if agentsAddLayoutOnly {
		out.DryRun = false
		printOutput(out, formatAgentsAddOutput)
		return nil
	}
	planWorkDirectory := layout.CustomerRepoRoot
	if strings.TrimSpace(plan.WorkDir) != "" {
		planWorkDirectory = plan.WorkDir
	}
	if err := agentsAddMaterializeAgent(layout.AgentsRoot, plan, planWorkDirectory); err != nil {
		if workBinding == agentsWorkGitWorktree {
			cleanupAgentsAddGitWorktree(layout, plan, branchCreated)
			if rollbackErr := revertAgentsAddLayoutMaterialization(layout, spec, plan, out.RoleCreated); rollbackErr != nil {
				return fmt.Errorf("materialize agent home for %s: %w (rollback failed: %v)", plan.Responsibility, err, rollbackErr)
			}
		}
		return err
	}
	if anchorDir != "" {
		if err := agentsAddInitAdditionalAgent(anchorDir, plan); err != nil {
			if workBinding == agentsWorkGitWorktree {
				return agentsAddWorktreeProvisionFailureError(layout, plan, err)
			}
			return err
		}
	} else if err := agentsAddInitPrimaryAgent(cmd, source, plan); err != nil {
		if workBinding == agentsWorkGitWorktree {
			return agentsAddWorktreeProvisionFailureError(layout, plan, err)
		}
		return err
	}
	out.DryRun = false
	printOutput(out, formatAgentsAddOutput)
	return nil
}

func agentsAddLayoutLockPath(agentsRoot string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(agentsRoot)))
	return filepath.Join(os.TempDir(), "aw-agents-layout-"+hex.EncodeToString(sum[:8])+".lock")
}

func runAgentsAddGlobal(cmd *cobra.Command, out agentsAddOutput, layout teamBootstrapLayout, spec *teamBootstrapSpec, plan teamBootstrapAgentPlan) error {
	lock, err := awconfig.LockExclusive(agentsAddGlobalLockPath(plan.HomeDir))
	if err != nil {
		return fmt.Errorf("lock global add state: %w", err)
	}
	defer lock.Close()

	pending, signingKey, pendingCreated, err := prepareAgentsAddGlobalPending(layout, out, plan)
	if err != nil {
		return err
	}
	registry, registryURL, controllerKey, err := resolveAgentsAddGlobalAuthority(pending)
	if err != nil {
		if pendingCreated {
			cleanupNewAgentsAddGlobalPending(plan.HomeDir)
		}
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if !pending.AtomicClaimApplied {
		if _, err := agentsAddClaimIdentityAddress(ctx, registry, registryURL, awid.AtomicAddressClaimParams{
			Domain:                        pending.Domain,
			AddressName:                   pending.AddressName,
			DIDAW:                         pending.DIDAW,
			CurrentDIDKey:                 pending.CurrentDIDKey,
			IdentitySigningKey:            signingKey,
			NamespaceControllerSigningKey: controllerKey,
			IdentityCustody:               string(awid.AddressClaimCustodySelf),
			NamespaceCustody:              string(awid.AddressClaimCustodySelf),
		}); err != nil {
			if pendingCreated {
				cleanupNewAgentsAddGlobalPending(plan.HomeDir)
			}
			return agentsAddGlobalClaimError(pending, err)
		}
		pending.AtomicClaimApplied = true
		if err := saveAgentsAddGlobalPending(plan.HomeDir, pending); err != nil {
			return agentsAddGlobalRetryError(plan.HomeDir, pending, fmt.Errorf("save pending atomic-claim state: %w", err))
		}
	}

	if err := writeAgentsAddLayout(layout, spec, plan, out.RoleCreated); err != nil {
		return agentsAddGlobalRetryError(plan.HomeDir, pending, err)
	}
	if err := materializeTeamBootstrapAgent(layout.AgentsRoot, plan, layout.CustomerRepoRoot); err != nil {
		return agentsAddGlobalRetryError(plan.HomeDir, pending, err)
	}

	teamResult, err := agentsAddEnsureGlobalCertificate(ctx, registry, registryURL, controllerKey, signingKey, pending, plan.HomeDir)
	if err != nil {
		return agentsAddGlobalRetryError(plan.HomeDir, pending, err)
	}
	if err := saveAgentsAddGlobalLocalState(plan.HomeDir, pending, teamResult); err != nil {
		return agentsAddGlobalRetryError(plan.HomeDir, pending, err)
	}
	if err := ensureLocalIdentityEncryptionKeyForDir(plan.HomeDir); err != nil {
		return agentsAddGlobalRetryError(plan.HomeDir, pending, err)
	}
	if _, err := agentsAddConnectGlobalAgent(plan.HomeDir, pending.AwebURL, certificateConnectOptions{Role: strings.TrimSpace(plan.RoleName)}); err != nil {
		return agentsAddGlobalRetryError(plan.HomeDir, pending, err)
	}
	_ = os.Remove(agentsAddGlobalPendingPath(plan.HomeDir))

	out.DryRun = false
	out.TeamSource = string(teamBootstrapSourceBYOT)
	printOutput(out, formatAgentsAddOutput)
	return nil
}

func agentsAddGlobalPendingPath(homeDir string) string {
	return filepath.Join(filepath.Clean(homeDir), ".aw", "agents-add-global-pending.yaml")
}

func agentsAddGlobalLockPath(homeDir string) string {
	sum := sha256.Sum256([]byte(filepath.Clean(homeDir)))
	return filepath.Join(os.TempDir(), "aw-agents-add-global-"+hex.EncodeToString(sum[:8])+".lock")
}

func loadAgentsAddGlobalPending(homeDir string) (*agentsAddGlobalPendingState, error) {
	path := agentsAddGlobalPendingPath(homeDir)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("read pending global add state %s: %w", path, err)
	}
	var state agentsAddGlobalPendingState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parse pending global add state %s: %w", path, err)
	}
	return &state, nil
}

func saveAgentsAddGlobalPending(homeDir string, state *agentsAddGlobalPendingState) error {
	if state == nil {
		return fmt.Errorf("pending global add state is required")
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	path := agentsAddGlobalPendingPath(homeDir)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return os.WriteFile(path, []byte(strings.TrimRight(string(data), "\n")+"\n"), 0o600)
}

func prepareAgentsAddGlobalPending(layout teamBootstrapLayout, out agentsAddOutput, plan teamBootstrapAgentPlan) (*agentsAddGlobalPendingState, ed25519.PrivateKey, bool, error) {
	if existing, err := loadAgentsAddGlobalPending(plan.HomeDir); err != nil {
		return nil, nil, false, err
	} else if existing != nil {
		signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(plan.HomeDir))
		if err != nil {
			return nil, nil, false, fmt.Errorf("load pending global add signing key: %w", err)
		}
		if got := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); got != strings.TrimSpace(existing.CurrentDIDKey) {
			return nil, nil, false, usageError("pending global add signing key does not match %s; restore the original .aw/signing.key or remove the pending state after backing it up", agentsAddGlobalPendingPath(plan.HomeDir))
		}
		return existing, signingKey, false, nil
	}

	domain, name, err := parseAddress(plan.GlobalAddress)
	if err != nil {
		return nil, nil, false, err
	}
	teamID, err := expectedAgentsProvisionTeamID()
	if err != nil {
		return nil, nil, false, err
	}
	namespace, teamName, err := awid.ParseTeamID(teamID)
	if err != nil {
		return nil, nil, false, err
	}
	if domain != namespace {
		return nil, nil, false, usageError("global address namespace %s does not match team namespace %s", domain, namespace)
	}
	awebURL := strings.TrimSpace(teamBootstrapAwebURL)
	if awebURL == "" {
		awebURL = DefaultAwebURL
	}
	awebURL, err = normalizeAwebBaseURL(awebURL)
	if err != nil {
		return nil, nil, false, fmt.Errorf("invalid --aweb-url: %w", err)
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, nil, false, err
	}
	registryURL := strings.TrimSpace(teamBootstrapRegistryURL)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return nil, nil, false, fmt.Errorf("invalid --registry: %w", err)
		}
	}
	registryURL = strings.TrimSpace(registry.DefaultRegistryURL)

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return nil, nil, false, err
	}
	pending := &agentsAddGlobalPendingState{
		Version:        1,
		Responsibility: strings.TrimSpace(plan.Responsibility),
		RoleName:       strings.TrimSpace(plan.RoleName),
		Alias:          strings.TrimSpace(plan.Alias),
		GlobalAddress:  strings.TrimSpace(plan.GlobalAddress),
		IdentityPrefix: strings.TrimSpace(out.IdentityPrefix),
		Domain:         namespace,
		AddressName:    name,
		TeamName:       teamName,
		TeamID:         teamID,
		DIDAW:          awid.ComputeStableID(pub),
		CurrentDIDKey:  awid.ComputeDIDKey(pub),
		RegistryURL:    registryURL,
		AwebURL:        awebURL,
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	}
	if err := os.MkdirAll(filepath.Join(plan.HomeDir, ".aw"), 0o700); err != nil {
		return nil, nil, false, err
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(plan.HomeDir), signingKey); err != nil {
		cleanupNewAgentsAddGlobalPending(plan.HomeDir)
		return nil, nil, false, err
	}
	if err := saveAgentsAddGlobalPending(plan.HomeDir, pending); err != nil {
		cleanupNewAgentsAddGlobalPending(plan.HomeDir)
		return nil, nil, false, err
	}
	return pending, signingKey, true, nil
}

func resolveAgentsAddGlobalAuthority(pending *agentsAddGlobalPendingState) (*awid.RegistryClient, string, ed25519.PrivateKey, error) {
	if pending == nil {
		return nil, "", nil, fmt.Errorf("pending global add state is required")
	}
	controllerKey, err := awconfig.LoadControllerKey(pending.Domain)
	if err != nil {
		return nil, "", nil, fmt.Errorf("load namespace controller key for %s: %w", pending.Domain, err)
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, "", nil, err
	}
	if strings.TrimSpace(pending.RegistryURL) != "" {
		if err := registry.SetFallbackRegistryURL(pending.RegistryURL); err != nil {
			return nil, "", nil, err
		}
	}
	return registry, strings.TrimSpace(registry.DefaultRegistryURL), controllerKey, nil
}

func cleanupNewAgentsAddGlobalPending(homeDir string) {
	_ = os.RemoveAll(filepath.Join(filepath.Clean(homeDir), ".aw"))
	_ = os.Remove(filepath.Clean(homeDir))
}

var agentsAddGlobalSpecificConflictCodes = map[string]bool{
	awid.AtomicAddressClaimCodeAddressTakenDifferentOwner: true,
	awid.AtomicAddressClaimCodeDIDTakenDifferentKey:       true,
	awid.AtomicAddressClaimCodeNamespaceAuthorityInvalid:  true,
	awid.AtomicAddressClaimCodeNamespaceNotRegistered:     true,
	awid.AtomicAddressClaimCodePrimitiveDisabled:          true,
	awid.AtomicAddressClaimCodePrimitiveNotSupported:      true,
}

var agentsAddGlobalDefaultConflictCodes = map[string]bool{
	awid.AtomicAddressClaimCodeIdentitySignatureInvalid:      true,
	awid.AtomicAddressClaimCodeTimestampStale:                true,
	awid.AtomicAddressClaimCodePayloadCanonicalization:       true,
	awid.AtomicAddressClaimCodeCustodyCombinationUnsupported: true,
	awid.AtomicAddressClaimCodeDIDLogProofRequired:           true,
	awid.AtomicAddressClaimCodeDIDLogProofInvalid:            true,
}

func agentsAddGlobalClaimError(pending *agentsAddGlobalPendingState, err error) error {
	var conflict *awid.AtomicAddressClaimConflictError
	if errors.As(err, &conflict) {
		switch conflict.Code {
		case awid.AtomicAddressClaimCodeAddressTakenDifferentOwner:
			return usageError("global address %s is already claimed by another identity; rerun aw agents add --global with a different --identity-prefix or naming pattern", pending.GlobalAddress)
		case awid.AtomicAddressClaimCodeDIDTakenDifferentKey:
			return usageError("global identity %s is already registered to a different key; restore the original .aw/signing.key or choose a different global name", pending.DIDAW)
		case awid.AtomicAddressClaimCodeNamespaceAuthorityInvalid:
			return usageError("namespace controller key for %s does not match AWID; run aw id namespace check-txt --domain %s and restore the matching ~/.awid controller key", pending.Domain, pending.Domain)
		case awid.AtomicAddressClaimCodeNamespaceNotRegistered:
			return usageError("namespace %s is not registered at AWID; run aw id namespace prepare-controller, publish/check _awid, then retry", pending.Domain)
		case awid.AtomicAddressClaimCodePrimitiveDisabled, awid.AtomicAddressClaimCodePrimitiveNotSupported:
			return usageError("AWID registry at %s does not support atomic address claims; upgrade awid-service before using aw agents add --global", pending.RegistryURL)
		default:
			return usageError("atomic global address claim failed with %s: %s", conflict.Code, conflict.Message)
		}
	}
	return fmt.Errorf("claim global address %s at AWID: %w", pending.GlobalAddress, err)
}

func agentsAddGlobalRetryError(homeDir string, pending *agentsAddGlobalPendingState, cause error) error {
	return fmt.Errorf("%w\n\nAWID accepted the global address claim for %s. Retry with:\n  aw agents add --global %s --namespace %s --team %s\nDo not delete %s or .aw/signing.key unless you intentionally abandon this claim.",
		cause,
		pending.GlobalAddress,
		pending.Responsibility,
		pending.Domain,
		pending.TeamName,
		agentsAddGlobalPendingPath(homeDir),
	)
}

func ensureAgentsAddGlobalCertificate(ctx context.Context, registry *awid.RegistryClient, registryURL string, controllerKey, signingKey ed25519.PrivateKey, pending *agentsAddGlobalPendingState, homeDir string) (*localTeamBootstrapResult, error) {
	registration, err := ensureLocalTeamRegistered(ctx, registry, registryURL, pending.Domain, pending.TeamName, "", controllerKey)
	if err != nil {
		return nil, err
	}
	if pending.Certificate == nil {
		cert, err := awid.SignTeamCertificate(registration.TeamKey, awid.TeamCertificateFields{
			Team:          registration.TeamID,
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
		if err := saveAgentsAddGlobalPending(homeDir, pending); err != nil {
			return nil, err
		}
	}
	if !pending.CertificateRegistered {
		if err := registry.RegisterCertificate(ctx, registryURL, pending.Domain, pending.TeamName, pending.Certificate, registration.TeamKey); err != nil {
			var alreadyRegistered *awid.CertificateAlreadyRegisteredError
			if !errors.As(err, &alreadyRegistered) {
				return nil, fmt.Errorf("register team certificate: %w", err)
			}
		}
		pending.CertificateRegistered = true
		if err := saveAgentsAddGlobalPending(homeDir, pending); err != nil {
			return nil, err
		}
	}
	return &localTeamBootstrapResult{
		TeamID:      registration.TeamID,
		TeamDIDKey:  registration.TeamDIDKey,
		TeamKeyPath: registration.TeamKeyPath,
		Certificate: pending.Certificate,
	}, nil
}

func saveAgentsAddGlobalLocalState(homeDir string, pending *agentsAddGlobalPendingState, teamResult *localTeamBootstrapResult) error {
	if pending == nil || teamResult == nil || teamResult.Certificate == nil {
		return fmt.Errorf("global add local state is incomplete")
	}
	certPath, err := awconfig.SaveTeamCertificateForTeam(homeDir, pending.TeamID, teamResult.Certificate)
	if err != nil {
		return err
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(homeDir, awconfig.DefaultWorktreeIdentityRelativePath()), &awconfig.WorktreeIdentity{
		DID:            pending.CurrentDIDKey,
		StableID:       pending.DIDAW,
		Address:        pending.GlobalAddress,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    pending.RegistryURL,
		RegistryStatus: "registered",
		CreatedAt:      pending.CreatedAt,
	}); err != nil {
		return err
	}
	return upsertAcceptedTeamMembershipState(homeDir, &teamAcceptInviteOutput{
		Status:   "installed",
		TeamID:   pending.TeamID,
		Alias:    pending.Alias,
		CertPath: certPath,
	}, teamResult.Certificate, pending.RegistryURL, pending.AwebURL, true)
}

func buildAgentsAddOutput(cmd *cobra.Command, responsibilityRaw, workBinding string) (agentsAddOutput, teamBootstrapLayout, *teamBootstrapSpec, teamBootstrapAgentPlan, error) {
	layout, err := resolveAgentsExistingLayoutPreflight()
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	spec, err := loadTeamBootstrapSpec(layout.AgentsRoot)
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	if err := validateTeamBootstrapSpec(layout.AgentsRoot, spec); err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	responsibility, err := normalizeAgentsNamingField("responsibility", responsibilityRaw)
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	scope, err := resolveAgentsAddScope()
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	pending, err := loadAgentsAddGlobalPending(filepath.Join(layout.HomeRoot, responsibility))
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	existingSpec, exists := spec.Agents[responsibility]
	resumeGlobal := exists && scope == agentsIdentityScopeGlobal && !agentsAddLayoutOnly && pending != nil
	if exists && !resumeGlobal {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, usageError("agents layout already contains responsibility %q", responsibility)
	}
	if scope == agentsIdentityScopeGlobal && strings.TrimSpace(teamBootstrapNamespace) == "" {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, usageError("--namespace is required when adding a global agent")
	}
	if scope == agentsIdentityScopeGlobal && !agentsAddLayoutOnly && strings.TrimSpace(teamBootstrapTeamName) == "" {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, usageError("--team is required when adding a global agent")
	}
	workBinding = strings.TrimSpace(workBinding)
	if workBinding == "" {
		workBinding = agentsWorkRepoRoot
	}
	if workBinding != agentsWorkRepoRoot && workBinding != agentsWorkGitWorktree {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, usageError("unsupported agents add work binding %q", workBinding)
	}
	roleCreated := false
	roleName := ""
	if resumeGlobal {
		roleName = strings.TrimSpace(pending.RoleName)
		if roleName == "" {
			roleName = strings.TrimSpace(existingSpec.RoleName)
		}
		if roleName == "" {
			return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, usageError("pending global add for %q is missing role_name", responsibility)
		}
	} else {
		roleName, err = normalizeAgentsNamingField("role", firstNonEmpty(agentsAddRole, responsibility))
		if err != nil {
			return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
		}
		if spec.Roles == nil {
			spec.Roles = map[string]teamBootstrapRoleSpec{}
		}
		if _, ok := spec.Roles[roleName]; !ok {
			roleCreated = true
			spec.Roles[roleName] = teamBootstrapRoleSpec{
				Title: titleFromSlug(roleName),
				File:  filepath.ToSlash(filepath.Join("roles", roleName+".md")),
			}
		}
		spec.Agents[responsibility] = teamBootstrapAgentSpec{
			RoleName:      roleName,
			IdentityScope: scope,
			HomeTemplate:  filepath.ToSlash(filepath.Join("home", responsibility)),
			Work:          workBinding,
		}
		if err := ensureAgentsAddPathsAvailable(layout, spec, responsibility, roleName, roleCreated); err != nil {
			return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
		}
	}
	if resumeGlobal {
		identityPrefix := strings.TrimSpace(pending.IdentityPrefix)
		warnings := []string{}
		if cmd != nil && cmd.Flags().Changed("identity-prefix") {
			requestedPrefix, err := normalizeAgentsNamingField("identity-prefix", agentsIdentityPrefix)
			if err != nil {
				return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
			}
			if requestedPrefix != "" && requestedPrefix != identityPrefix {
				warnings = append(warnings, fmt.Sprintf("using pending identity prefix %s; --identity-prefix %s is ignored on retry", identityPrefix, requestedPrefix))
			}
		}
		plan := teamBootstrapAgentPlan{
			Responsibility: responsibility,
			RoleName:       roleName,
			Name:           strings.TrimSpace(pending.Alias),
			Alias:          strings.TrimSpace(pending.Alias),
			IdentityScope:  agentsIdentityScopeGlobal,
			GlobalAddress:  strings.TrimSpace(pending.GlobalAddress),
			HomeDir:        filepath.Join(layout.HomeRoot, responsibility),
			WorkspaceDir:   filepath.Join(layout.HomeRoot, responsibility),
			SourceHome:     filepath.Join(layout.HomeRoot, responsibility),
			Instructions:   filepath.Join(layout.HomeRoot, responsibility, "AGENTS.md"),
			WorkBinding:    agentsWorkRepoRoot,
			WorkDir:        layout.CustomerRepoRoot,
		}
		out := agentsAddOutput{
			DryRun:         true,
			LayoutOnly:     false,
			AgentsDir:      layout.AgentsRoot,
			Responsibility: responsibility,
			RoleName:       roleName,
			RoleCreated:    false,
			IdentityPrefix: identityPrefix,
			Agent:          plan,
			TeamSource:     string(teamBootstrapSourceBYOT),
			Warnings:       warnings,
		}
		return out, layout, spec, plan, nil
	}
	identityPrefix, err := resolveAgentsIdentityPrefix(cmd)
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	namingInput, err := agentsAddNamingInput(layout, spec, responsibility, scope, identityPrefix, workBinding)
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	namingPlan, err := buildAgentsNamingPlan(namingInput)
	if err != nil {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
	}
	if len(namingPlan.Agents) != 1 {
		return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, fmt.Errorf("internal error: add naming plan returned %d agents", len(namingPlan.Agents))
	}
	agentPlan := namingPlan.Agents[0]
	workDir := layout.CustomerRepoRoot
	workspaceDir := filepath.Join(layout.HomeRoot, responsibility)
	if workBinding == agentsWorkGitWorktree {
		if strings.TrimSpace(agentPlan.WorktreeName) == "" {
			return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, fmt.Errorf("internal error: worktree add did not allocate a worktree name")
		}
		workDir = filepath.Join(layout.WorktreesRoot, agentPlan.WorktreeName)
		workspaceDir = workDir
	}
	plan := teamBootstrapAgentPlan{
		Responsibility: responsibility,
		RoleName:       roleName,
		Name:           agentPlan.TeamAlias,
		Alias:          agentPlan.TeamAlias,
		IdentityScope:  agentPlan.IdentityScope,
		GlobalAddress:  agentPlan.GlobalAddress,
		HomeDir:        filepath.Join(layout.HomeRoot, responsibility),
		WorkspaceDir:   workspaceDir,
		SourceHome:     filepath.Join(layout.HomeRoot, responsibility),
		Instructions:   filepath.Join(layout.HomeRoot, responsibility, "AGENTS.md"),
		WorkBinding:    workBinding,
		WorkDir:        workDir,
	}
	checks := make([]agentsProvisionCheck, 0, len(agentPlan.Availability))
	for _, check := range agentPlan.Availability {
		checks = append(checks, agentsProvisionCheck{
			Responsibility: responsibility,
			Field:          check.Field,
			Value:          check.Value,
			Status:         check.Status,
			Source:         check.Source,
		})
	}
	out := agentsAddOutput{
		DryRun:         true,
		LayoutOnly:     agentsAddLayoutOnly,
		AgentsDir:      layout.AgentsRoot,
		Responsibility: responsibility,
		RoleName:       roleName,
		RoleCreated:    roleCreated,
		IdentityPrefix: identityPrefix,
		Agent:          plan,
		Availability:   checks,
	}
	if !agentsAddLayoutOnly {
		if anchorDir, err := findAgentsProvisionAnchor(layout, plan.HomeDir); err == nil && anchorDir != "" {
			out.TeamSource = string(teamBootstrapSourceCurrent)
		} else if source, err := resolveAgentsProvisionSource(); err == nil {
			out.TeamSource = string(source.Kind)
		} else if hasAgentsProvisionExplicitSource() {
			return agentsAddOutput{}, teamBootstrapLayout{}, nil, teamBootstrapAgentPlan{}, err
		}
	}
	return out, layout, spec, plan, nil
}

func buildAgentsProvisionOutput(cmd *cobra.Command) (agentsProvisionOutput, teamBootstrapLayout, *teamBootstrapSpec, []teamBootstrapAgentPlan, error) {
	layout, err := resolveAgentsExistingLayoutPreflight()
	if err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	spec, err := loadTeamBootstrapSpec(layout.AgentsRoot)
	if err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	if err := validateTeamBootstrapSpec(layout.AgentsRoot, spec); err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	plans, err := buildTeamBootstrapPlans(cmd.InOrStdin(), cmd.ErrOrStderr(), layout.AgentsRoot, layout.HomeRoot, spec, false)
	if err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	identityPrefix, err := resolveAgentsIdentityPrefix(cmd)
	if err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	namingInput, err := agentsNamingInputFromBootstrapPlans(layout, spec, plans, identityPrefix)
	if err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	namingPlan, err := buildAgentsNamingPlan(namingInput)
	if err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	plans, checks, err := applyAgentsNamingPlanToBootstrapPlans(plans, namingPlan)
	if err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	if err := applyInRepoBootstrapWorkBindings(layout, plans); err != nil {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	out := agentsProvisionOutput{
		DryRun:         true,
		AgentsDir:      layout.AgentsRoot,
		IdentityPrefix: identityPrefix,
		Agents:         plans,
		Availability:   checks,
		NextCommands:   plannedInitCommands(plans),
	}
	if source, err := resolveAgentsProvisionSource(); err == nil {
		out.TeamSource = string(source.Kind)
	} else if hasAgentsProvisionExplicitSource() {
		return agentsProvisionOutput{}, teamBootstrapLayout{}, nil, nil, err
	}
	return out, layout, spec, plans, nil
}

func resolveAgentsExistingLayoutPreflight() (teamBootstrapLayout, error) {
	wd, err := os.Getwd()
	if err != nil {
		return teamBootstrapLayout{}, err
	}
	repoRoot, err := currentGitWorktreeRootFromDir(wd)
	if err != nil {
		return teamBootstrapLayout{}, usageError("aw agents provision must be run from inside a git repository")
	}
	agentsDir, err := validateTeamBootstrapAgentsDir(teamBootstrapAgentsDir)
	if err != nil {
		return teamBootstrapLayout{}, err
	}
	agentsRoot := filepath.Join(repoRoot, agentsDir)
	if info, err := os.Stat(agentsRoot); err != nil {
		if os.IsNotExist(err) {
			return teamBootstrapLayout{}, usageError("agents layout not found at %s; run aw agents bootstrap first or pass --agents-dir", agentsRoot)
		}
		return teamBootstrapLayout{}, fmt.Errorf("stat agents directory %s: %w", agentsRoot, err)
	} else if !info.IsDir() {
		return teamBootstrapLayout{}, usageError("agents layout path %s is not a directory", agentsRoot)
	}
	if _, err := os.Stat(filepath.Join(agentsRoot, "team.yaml")); err != nil {
		return teamBootstrapLayout{}, fmt.Errorf("read agents layout team.yaml: %w", err)
	}
	if _, err := os.Stat(filepath.Join(repoRoot, ".aw")); err == nil {
		return teamBootstrapLayout{}, usageError("repo root %s is already initialized as an aw workspace; aw agents provision must not create or use repo-root .aw state. Run from a clean project root and start agents from agents/home/<responsibility>.", repoRoot)
	} else if err != nil && !os.IsNotExist(err) {
		return teamBootstrapLayout{}, fmt.Errorf("stat repo-root .aw: %w", err)
	}
	return teamBootstrapLayout{
		Mode:             teamBootstrapLayoutInRepo,
		CustomerRepoRoot: repoRoot,
		AgentsDirName:    agentsDir,
		AgentsRoot:       agentsRoot,
		HomeRoot:         filepath.Join(agentsRoot, "home"),
		WorktreesRoot:    filepath.Join(agentsRoot, "worktrees"),
		WorkDirectory:    repoRoot,
	}, nil
}

func resolveAgentsIdentityPrefix(cmd *cobra.Command) (string, error) {
	raw := strings.TrimSpace(agentsIdentityPrefix)
	if raw == "" {
		for _, key := range []string{"AWEB_IDENTITY_PREFIX", "AWEB_HUMAN", "USER"} {
			if value := strings.TrimSpace(os.Getenv(key)); value != "" {
				raw = sanitizeSlug(value)
				break
			}
		}
	}
	if raw == "" {
		return "", nil
	}
	return normalizeAgentsNamingField("identity-prefix", raw)
}

func agentsNamingInputFromBootstrapPlans(layout teamBootstrapLayout, spec *teamBootstrapSpec, plans []teamBootstrapAgentPlan, identityPrefix string) (agentsNamingInput, error) {
	input := agentsNamingInput{
		AgentsDir: layout.AgentsDirName,
		Namespace: teamBootstrapNamespace,
		User:      identityPrefix,
		Policy:    agentsNamingPolicyFromBootstrapSpec(spec),
		Agents:    make([]agentsNamingAgentInput, 0, len(plans)),
	}
	if strings.TrimSpace(teamBootstrapNamespace) != "" && strings.TrimSpace(teamBootstrapTeamName) != "" {
		aliases, globalNames, err := existingBYOTNamesForAgentsProvision(teamBootstrapNamespace, teamBootstrapTeamName)
		if err != nil {
			return agentsNamingInput{}, err
		}
		input.ExistingAliases = aliases
		input.ExistingGlobalNames = globalNames
	}
	for _, plan := range plans {
		agent := spec.Agents[plan.Responsibility]
		scope := strings.TrimSpace(agent.IdentityScope)
		if scope == "" {
			scope = agentsIdentityScopeLocal
		}
		input.Agents = append(input.Agents, agentsNamingAgentInput{
			Responsibility: plan.Responsibility,
			IdentityScope:  scope,
			WorkBinding:    strings.TrimSpace(agent.Work),
		})
	}
	return input, nil
}

func agentsNamingPolicyFromBootstrapSpec(spec *teamBootstrapSpec) agentsNamingPolicy {
	if spec == nil {
		return agentsNamingPolicy{}
	}
	return agentsNamingPolicy{
		LocalAliasSequence:  strings.TrimSpace(spec.Naming.LocalAlias.Sequence),
		LocalAliasPattern:   strings.TrimSpace(spec.Naming.LocalAlias.Pattern),
		GlobalAliasSequence: strings.TrimSpace(spec.Naming.GlobalAlias.Sequence),
		GlobalAliasPattern:  strings.TrimSpace(spec.Naming.GlobalAlias.Pattern),
		GlobalNameSequence:  strings.TrimSpace(spec.Naming.GlobalName.Sequence),
		GlobalNamePattern:   strings.TrimSpace(spec.Naming.GlobalName.Pattern),
		WorktreeSequence:    strings.TrimSpace(spec.Naming.Worktree.Sequence),
		WorktreePattern:     strings.TrimSpace(spec.Naming.Worktree.Pattern),
	}
}

func expectedAgentsProvisionTeamID() (string, error) {
	namespace := strings.TrimSpace(teamBootstrapNamespace)
	teamName := strings.TrimSpace(teamBootstrapTeamName)
	if namespace == "" && teamName == "" {
		return "", nil
	}
	if namespace == "" {
		return "", usageError("--namespace is required with --team")
	}
	if teamName == "" {
		return "", usageError("--team is required with --namespace")
	}
	normalizedNamespace, err := normalizeAgentsNamespace(namespace)
	if err != nil {
		return "", err
	}
	normalizedTeam, err := normalizeAgentsNamingField("team", teamName)
	if err != nil {
		return "", err
	}
	return awid.BuildTeamID(normalizedNamespace, normalizedTeam), nil
}

func resolveAgentsAddScope() (string, error) {
	if agentsAddLocal && agentsAddGlobal {
		return "", usageError("--local and --global are mutually exclusive")
	}
	if agentsAddGlobal {
		return agentsIdentityScopeGlobal, nil
	}
	return agentsIdentityScopeLocal, nil
}

func agentsAddNamingInput(layout teamBootstrapLayout, spec *teamBootstrapSpec, responsibility, scope, identityPrefix, workBinding string) (agentsNamingInput, error) {
	input := agentsNamingInput{
		AgentsDir: layout.AgentsDirName,
		Namespace: teamBootstrapNamespace,
		User:      identityPrefix,
		Policy:    agentsNamingPolicyFromBootstrapSpec(spec),
		Agents: []agentsNamingAgentInput{{
			Responsibility: responsibility,
			IdentityScope:  scope,
			WorkBinding:    workBinding,
		}},
		ExistingAliases:     map[string]bool{},
		ExistingGlobalNames: map[string]bool{},
		ExistingHomeNames:   map[string]bool{},
	}
	for existing := range spec.Agents {
		if existing == responsibility {
			continue
		}
		normalized, err := normalizeAgentsNamingField("existing responsibility", existing)
		if err != nil {
			return agentsNamingInput{}, err
		}
		input.ExistingHomeNames[normalized] = true
	}
	if entries, err := os.ReadDir(layout.HomeRoot); err == nil {
		for _, entry := range entries {
			if !entry.IsDir() || entry.Name() == responsibility {
				continue
			}
			normalized, err := normalizeAgentsNamingField("existing home", entry.Name())
			if err != nil {
				return agentsNamingInput{}, err
			}
			input.ExistingHomeNames[normalized] = true
		}
	} else if !os.IsNotExist(err) {
		return agentsNamingInput{}, fmt.Errorf("read existing agent homes: %w", err)
	}
	for _, membership := range existingAgentsMemberships(layout, responsibility) {
		if alias := strings.ToLower(strings.TrimSpace(membership.Alias)); alias != "" {
			input.ExistingAliases[alias] = true
		}
	}
	if strings.TrimSpace(teamBootstrapNamespace) != "" && strings.TrimSpace(teamBootstrapTeamName) != "" {
		aliases, globalNames, err := existingBYOTNamesForAgentsProvision(teamBootstrapNamespace, teamBootstrapTeamName)
		if err != nil {
			return agentsNamingInput{}, err
		}
		for alias := range aliases {
			input.ExistingAliases[alias] = true
		}
		for name := range globalNames {
			input.ExistingGlobalNames[name] = true
		}
	}
	if workBinding == agentsWorkGitWorktree {
		worktrees, err := existingAgentsWorktreeNames(layout)
		if err != nil {
			return agentsNamingInput{}, err
		}
		branches, err := existingAgentsBranchNames(layout)
		if err != nil {
			return agentsNamingInput{}, err
		}
		input.ExistingWorktrees = worktrees
		input.ExistingBranches = branches
	}
	return input, nil
}

func existingAgentsWorktreeNames(layout teamBootstrapLayout) (map[string]bool, error) {
	out := map[string]bool{}
	entries, err := os.ReadDir(layout.WorktreesRoot)
	if err != nil {
		if os.IsNotExist(err) {
			return out, nil
		}
		return nil, fmt.Errorf("read existing agent worktrees: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name, err := normalizeAgentsNamingField("existing worktree", entry.Name())
		if err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, nil
}

func existingAgentsBranchNames(layout teamBootstrapLayout) (map[string]bool, error) {
	out := map[string]bool{}
	if strings.TrimSpace(layout.CustomerRepoRoot) == "" {
		return out, nil
	}
	cmd := exec.Command("git", "-C", layout.CustomerRepoRoot, "for-each-ref", "--format=%(refname:short)", "refs/heads")
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("list git branches: %w", err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		name, err := normalizeAgentsNamingField("existing branch", line)
		if err != nil {
			// Generated worktree branches are slug-only, so branch names with
			// slashes or other git-specific punctuation cannot collide.
			continue
		}
		out[name] = true
	}
	return out, nil
}

func existingAgentsMemberships(layout teamBootstrapLayout, skipResponsibility string) []awconfig.WorktreeMembership {
	memberships := []awconfig.WorktreeMembership{}
	seen := map[string]bool{}
	for responsibility := range mapExistingAgentHomes(layout) {
		if responsibility == skipResponsibility {
			continue
		}
		home := filepath.Join(layout.HomeRoot, responsibility)
		memberships = append(memberships, existingAgentsMembershipsFromDir(home, seen)...)
	}
	for _, worktree := range mapExistingAgentWorktrees(layout) {
		memberships = append(memberships, existingAgentsMembershipsFromDir(worktree, seen)...)
	}
	return memberships
}

func existingAgentsMembershipsFromDir(dir string, seen map[string]bool) []awconfig.WorktreeMembership {
	dir = filepath.Clean(strings.TrimSpace(dir))
	if dir == "." || dir == "" || seen[dir] {
		return nil
	}
	seen[dir] = true
	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(dir)
	if err != nil || workspace == nil {
		return nil
	}
	return append([]awconfig.WorktreeMembership(nil), workspace.Memberships...)
}

func mapExistingAgentHomes(layout teamBootstrapLayout) map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir(layout.HomeRoot)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if entry.IsDir() {
			out[entry.Name()] = true
		}
	}
	return out
}

func mapExistingAgentWorktrees(layout teamBootstrapLayout) []string {
	out := []string{}
	entries, err := os.ReadDir(layout.WorktreesRoot)
	if err != nil {
		return out
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		out = append(out, filepath.Join(layout.WorktreesRoot, entry.Name()))
	}
	sort.Strings(out)
	return out
}

func ensureAgentsAddPathsAvailable(layout teamBootstrapLayout, spec *teamBootstrapSpec, responsibility, roleName string, roleCreated bool) error {
	home := filepath.Join(layout.HomeRoot, responsibility)
	if _, err := os.Stat(home); err == nil {
		return usageError("agent home %s already exists; choose another responsibility or remove the existing directory after backing up any .aw state", home)
	} else if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("stat agent home %s: %w", home, err)
	}
	if roleCreated {
		role := spec.Roles[roleName]
		rolePath := filepath.Join(layout.AgentsRoot, filepath.FromSlash(strings.TrimSpace(role.File)))
		if _, err := os.Stat(rolePath); err == nil {
			return usageError("role file %s already exists but role %q is not declared in team.yaml; add the role explicitly or choose --role", rolePath, roleName)
		} else if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("stat role file %s: %w", rolePath, err)
		}
	}
	return nil
}

func findAgentsProvisionAnchor(layout teamBootstrapLayout, skipHome string) (string, error) {
	for _, root := range []string{layout.HomeRoot, layout.WorktreesRoot} {
		entries, err := os.ReadDir(root)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return "", fmt.Errorf("read agent homes: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			home := filepath.Join(root, entry.Name())
			if filepath.Clean(home) == filepath.Clean(skipHome) {
				continue
			}
			if _, err := os.Stat(filepath.Join(home, ".aw")); err != nil {
				continue
			}
			if _, err := resolveSelectionForDir(home); err == nil {
				return home, nil
			}
		}
	}
	return "", nil
}

func writeAgentsAddLayout(layout teamBootstrapLayout, spec *teamBootstrapSpec, plan teamBootstrapAgentPlan, roleCreated bool) error {
	teamYAMLPath := filepath.Join(layout.AgentsRoot, "team.yaml")
	sanitizeTeamBootstrapSpecForWrite(spec)
	data, err := yaml.Marshal(spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(teamYAMLPath, []byte(strings.TrimRight(string(data), "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", teamYAMLPath, err)
	}
	if roleCreated {
		role := spec.Roles[plan.RoleName]
		rolePath := filepath.Join(layout.AgentsRoot, filepath.FromSlash(strings.TrimSpace(role.File)))
		if err := os.MkdirAll(filepath.Dir(rolePath), 0o755); err != nil {
			return err
		}
		body := fmt.Sprintf("# %s\n\nRole playbook for %s.\n", titleFromSlug(plan.RoleName), plan.RoleName)
		if err := os.WriteFile(rolePath, []byte(body), 0o644); err != nil {
			return fmt.Errorf("write role file %s: %w", rolePath, err)
		}
	}
	home := filepath.Join(layout.HomeRoot, plan.Responsibility)
	if err := os.MkdirAll(home, 0o755); err != nil {
		return err
	}
	agentsMD := filepath.Join(home, "AGENTS.md")
	body := fmt.Sprintf("# %s\n\nRole: %s\n", titleFromSlug(plan.Responsibility), plan.RoleName)
	if err := os.WriteFile(agentsMD, []byte(body), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", agentsMD, err)
	}
	return nil
}

func revertAgentsAddLayoutMaterialization(layout teamBootstrapLayout, spec *teamBootstrapSpec, plan teamBootstrapAgentPlan, roleCreated bool) error {
	if spec == nil {
		return nil
	}
	delete(spec.Agents, plan.Responsibility)
	if roleCreated {
		if role, ok := spec.Roles[plan.RoleName]; ok {
			rolePath := filepath.Join(layout.AgentsRoot, filepath.FromSlash(strings.TrimSpace(role.File)))
			if err := os.Remove(rolePath); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("remove generated role file %s: %w", rolePath, err)
			}
		}
		delete(spec.Roles, plan.RoleName)
	}
	if err := os.RemoveAll(plan.HomeDir); err != nil {
		return fmt.Errorf("remove generated home %s: %w", plan.HomeDir, err)
	}
	return writeAgentsAddLayoutYAML(layout, spec)
}

var writeAgentsAddLayoutYAML = writeAgentsAddLayoutYAMLImpl

func writeAgentsAddLayoutYAMLImpl(layout teamBootstrapLayout, spec *teamBootstrapSpec) error {
	teamYAMLPath := filepath.Join(layout.AgentsRoot, "team.yaml")
	sanitizeTeamBootstrapSpecForWrite(spec)
	data, err := yaml.Marshal(spec)
	if err != nil {
		return err
	}
	if err := os.WriteFile(teamYAMLPath, []byte(strings.TrimRight(string(data), "\n")+"\n"), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", teamYAMLPath, err)
	}
	return nil
}

func agentsAddWorktreeProvisionFailureError(layout teamBootstrapLayout, plan teamBootstrapAgentPlan, err error) error {
	branchName := ""
	if computed, cerr := agentsAddGitWorktreeBranchName(plan); cerr == nil {
		branchName = computed
	}
	if strings.TrimSpace(branchName) == "" {
		branchName = plan.Responsibility
	}
	return fmt.Errorf("agent home was created but identity provisioning failed for %s: %w\n\nUse `aw agents remove --remove-layout %s` to remove the shared layout entry after deciding whether to keep or back up local identity state. Manual cleanup: rm -rf %s; git -C %s worktree remove %s; git -C %s branch -D %s; then edit %s to remove the %q responsibility entry",
		plan.Responsibility,
		err,
		plan.Responsibility,
		plan.HomeDir,
		layout.CustomerRepoRoot,
		plan.WorkDir,
		layout.CustomerRepoRoot,
		branchName,
		filepath.Join(layout.AgentsRoot, "team.yaml"),
		plan.Responsibility,
	)
}

func sanitizeTeamBootstrapSpecForWrite(spec *teamBootstrapSpec) {
	if spec == nil {
		return
	}
	for key, agent := range spec.Agents {
		agent.DefaultName = ""
		agent.DefaultAlias = ""
		spec.Agents[key] = agent
	}
	if spec.Worktrees == nil {
		spec.Worktrees = []teamBootstrapWorktreeAgentSpec{}
	}
}

func titleFromSlug(slug string) string {
	parts := strings.Split(strings.TrimSpace(slug), "-")
	for i, part := range parts {
		if part == "" {
			continue
		}
		parts[i] = strings.ToUpper(part[:1]) + part[1:]
	}
	return strings.Join(parts, " ")
}

func resolveAgentsProvisionSource() (teamBootstrapSource, error) {
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
		return teamBootstrapSource{}, usageError("aw agents provision does not create a hosted team from --username; use `aw agents bootstrap --username <name>` for first-time hosted setup, or ask an existing team member for an invite and run `aw agents provision --invite-token <token> --identity-prefix <you>`")
	}
	if currentHasTeamWorkspace() {
		return teamBootstrapSource{Kind: teamBootstrapSourceCurrent}, nil
	}
	return teamBootstrapSource{}, usageError("aw agents provision requires a team source before it can mutate files: set AWEB_API_KEY, --invite-token, --username, --namespace/--team, or run from an initialized aw workspace to forward its current team")
}

func hasAgentsProvisionExplicitSource() bool {
	return resolveInitAPIKey() != "" ||
		strings.TrimSpace(teamBootstrapInviteToken) != "" ||
		strings.TrimSpace(teamBootstrapNamespace) != "" ||
		strings.TrimSpace(teamBootstrapTeamName) != "" ||
		strings.TrimSpace(teamBootstrapUsername) != ""
}

func existingBYOTNamesForAgentsProvision(namespace, teamName string) (map[string]bool, map[string]bool, error) {
	aliases := map[string]bool{}
	globalNames := map[string]bool{}
	namespace, err := normalizeAgentsNamespace(namespace)
	if err != nil {
		return nil, nil, err
	}
	teamName, err = normalizeAgentsNamingField("team", strings.TrimSpace(teamName))
	if err != nil {
		return nil, nil, err
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, nil, err
	}
	registryURL := strings.TrimSpace(teamBootstrapRegistryURL)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return nil, nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	certs, err := registry.ListCertificates(ctx, registryURL, namespace, teamName, true)
	if err != nil {
		if code, ok := registryStatusCode(err); ok && code == http.StatusNotFound {
			return aliases, globalNames, nil
		}
		return nil, nil, fmt.Errorf("list existing team certificates for preflight: %w", err)
	}
	for _, cert := range certs {
		if alias := strings.ToLower(strings.TrimSpace(cert.Alias)); alias != "" {
			aliases[alias] = true
		}
		if address := strings.TrimSpace(cert.MemberAddress); address != "" {
			if _, name, ok := strings.Cut(address, "/"); ok && name != "" {
				globalNames[strings.ToLower(strings.TrimSpace(name))] = true
			}
		}
	}
	return aliases, globalNames, nil
}

func applyAgentsNamingPlanToBootstrapPlans(plans []teamBootstrapAgentPlan, naming agentsNamingPlan) ([]teamBootstrapAgentPlan, []agentsProvisionCheck, error) {
	byResponsibility := map[string]agentsNamingAgentPlan{}
	for _, agent := range naming.Agents {
		byResponsibility[agent.Responsibility] = agent
	}
	checks := []agentsProvisionCheck{}
	for i := range plans {
		named, ok := byResponsibility[plans[i].Responsibility]
		if !ok {
			return nil, nil, fmt.Errorf("missing naming plan for %s", plans[i].Responsibility)
		}
		plans[i].Name = named.TeamAlias
		plans[i].Alias = named.TeamAlias
		plans[i].IdentityScope = named.IdentityScope
		plans[i].GlobalAddress = named.GlobalAddress
		plans[i].WorktreeName = named.WorktreeName
		for _, check := range named.Availability {
			checks = append(checks, agentsProvisionCheck{
				Responsibility: plans[i].Responsibility,
				Field:          check.Field,
				Value:          check.Value,
				Status:         check.Status,
				Source:         check.Source,
			})
		}
	}
	return plans, checks, nil
}

func assessAgentsProvisionState(plans []teamBootstrapAgentPlan, expectedTeamID string) (agentsProvisionState, error) {
	existing := 0
	clean := 0
	existingTeamID := ""
	for _, plan := range plans {
		workspaceDir := teamBootstrapAgentWorkspaceDir(plan)
		awDir := filepath.Join(workspaceDir, ".aw")
		if _, err := os.Stat(awDir); err != nil {
			if os.IsNotExist(err) {
				clean++
				continue
			}
			return agentsProvisionStateClean, fmt.Errorf("stat agent .aw state %s: %w", awDir, err)
		}
		existing++
		sel, err := resolveSelectionForDir(workspaceDir)
		if err != nil {
			return agentsProvisionStateClean, usageError("agent workspace %s has partial or unreadable .aw state: %v. aw agents provision does not auto-recover or merge partial identity state in v1; inspect and back up %s, then move it aside before retrying.", workspaceDir, err, awDir)
		}
		alias := strings.TrimSpace(plan.Alias)
		if alias == "" {
			alias = sanitizeSlug(plan.Name)
		}
		if !strings.EqualFold(strings.TrimSpace(sel.Alias), alias) {
			return agentsProvisionStateClean, usageError("agent workspace %s already belongs to alias %q, but this layout plans alias %q. aw agents provision does not merge mismatched identity state; inspect and back up %s, then move it aside or use a different identity prefix.", workspaceDir, sel.Alias, alias, awDir)
		}
		if expectedTeamID != "" && !strings.EqualFold(strings.TrimSpace(sel.TeamID), expectedTeamID) {
			return agentsProvisionStateClean, usageError("agent workspace %s already belongs to team %q, but this provision targets %q. Move aside %s or run with the matching team source.", workspaceDir, sel.TeamID, expectedTeamID, awDir)
		}
		if existingTeamID == "" {
			existingTeamID = strings.TrimSpace(sel.TeamID)
		} else if !strings.EqualFold(existingTeamID, strings.TrimSpace(sel.TeamID)) {
			return agentsProvisionStateClean, usageError("agents layout has existing .aw state for multiple teams (%q and %q). aw agents provision requires all existing homes to match the same team; inspect and back up the mismatched .aw directories before retrying.", existingTeamID, sel.TeamID)
		}
		if strings.TrimSpace(plan.GlobalAddress) != "" && !strings.EqualFold(strings.TrimSpace(sel.Address), strings.TrimSpace(plan.GlobalAddress)) {
			return agentsProvisionStateClean, usageError("agent workspace %s already has address %q, but this layout plans %q. aw agents provision does not merge mismatched global identity state; inspect and back up %s, then move it aside or choose a different identity prefix.", workspaceDir, sel.Address, plan.GlobalAddress, awDir)
		}
	}
	if existing > 0 && clean > 0 {
		return agentsProvisionStateClean, usageError("agents layout is partially provisioned (%d existing workspaces, %d clean workspaces). aw agents provision does not auto-recover partial state in v1; inspect and back up existing .aw directories, then either provision from a clean layout or rerun after every planned workspace has matching .aw state.", existing, clean)
	}
	if existing > 0 {
		return agentsProvisionStateAlreadyProvisioned, nil
	}
	return agentsProvisionStateClean, nil
}

func ensureInRepoProvisionWorktrees(layout teamBootstrapLayout, plans []teamBootstrapAgentPlan) error {
	if layout.Mode != teamBootstrapLayoutInRepo {
		return nil
	}
	if err := ensureAwebRuntimeUntrackedForAddWorktree(layout.CustomerRepoRoot); err != nil {
		return err
	}
	for _, plan := range plans {
		if plan.WorkBinding != teamBootstrapWorkGitWorktree {
			continue
		}
		if strings.TrimSpace(plan.WorkDir) == "" {
			return fmt.Errorf("agent %s missing worktree path", plan.Responsibility)
		}
		if _, err := os.Stat(plan.WorkDir); err == nil {
			continue
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("stat worktree path %s: %w", plan.WorkDir, err)
		}
		if err := os.MkdirAll(layout.WorktreesRoot, 0o755); err != nil {
			return err
		}
		branchName, err := teamBootstrapWorktreeName(plan)
		if err != nil {
			return err
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

func createAgentsAddGitWorktree(layout teamBootstrapLayout, plan teamBootstrapAgentPlan) (bool, error) {
	if plan.WorkBinding != agentsWorkGitWorktree {
		return false, nil
	}
	if strings.TrimSpace(plan.WorkDir) == "" {
		return false, fmt.Errorf("agent %s missing worktree path", plan.Responsibility)
	}
	if err := ensureAwebRuntimeUntrackedForAddWorktree(layout.CustomerRepoRoot); err != nil {
		return false, err
	}
	if err := ensureInRepoBootstrapGitignore(layout); err != nil {
		return false, err
	}
	if _, err := os.Stat(plan.WorkDir); err == nil {
		return false, usageError("worktree path %s already exists", plan.WorkDir)
	} else if !os.IsNotExist(err) {
		return false, fmt.Errorf("stat worktree path %s: %w", plan.WorkDir, err)
	}
	if err := os.MkdirAll(layout.WorktreesRoot, 0o755); err != nil {
		return false, err
	}
	branchName, err := agentsAddGitWorktreeBranchName(plan)
	if err != nil {
		return false, err
	}
	branchCreated, err := createWorkspaceGitWorktree(layout.CustomerRepoRoot, plan.WorkDir, branchName, jsonFlag)
	if err != nil {
		return false, fmt.Errorf("failed to create git worktree for %s: %w", plan.Responsibility, err)
	}
	if err := ensureAwebRuntimeGitIgnored(plan.WorkDir); err != nil {
		cleanupWorkspaceWorktree(layout.CustomerRepoRoot, plan.WorkDir, branchName, branchCreated)
		return false, err
	}
	return branchCreated, nil
}

func cleanupAgentsAddGitWorktree(layout teamBootstrapLayout, plan teamBootstrapAgentPlan, branchCreated bool) {
	if plan.WorkBinding != agentsWorkGitWorktree {
		return
	}
	branchName, err := agentsAddGitWorktreeBranchName(plan)
	if err != nil {
		return
	}
	cleanupWorkspaceWorktree(layout.CustomerRepoRoot, plan.WorkDir, branchName, branchCreated)
}

func agentsAddGitWorktreeBranchName(plan teamBootstrapAgentPlan) (string, error) {
	if strings.TrimSpace(plan.WorkDir) != "" {
		base := filepath.Base(filepath.Clean(plan.WorkDir))
		if strings.TrimSpace(base) != "" && base != "." && base != string(filepath.Separator) {
			name := sanitizeSlug(base)
			if name != "" {
				return name, nil
			}
		}
	}
	return teamBootstrapWorktreeName(plan)
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
		return teamBootstrapLayout{}, usageError("in-repo agents bootstrap must be run from inside a git repository; run from your project repo or pass --work-directory/--work-repo-url for legacy bootstrap")
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
			"aw agents bootstrap does not adopt, merge, or overwrite existing agents directories in v1. "+
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
			plans[i].WorkspaceDir = plans[i].HomeDir
		case teamBootstrapWorkGitWorktree:
			name, err := teamBootstrapWorktreeName(plans[i])
			if err != nil {
				return err
			}
			plans[i].WorkDir = filepath.Join(layout.WorktreesRoot, name)
			plans[i].WorkspaceDir = plans[i].WorkDir
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
		branchName, err := teamBootstrapWorktreeName(plan)
		if err != nil {
			return err
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

func teamBootstrapWorktreeName(plan teamBootstrapAgentPlan) (string, error) {
	for _, candidate := range []string{plan.WorktreeName, plan.Alias, plan.Name, plan.Responsibility} {
		if strings.TrimSpace(candidate) == "" {
			continue
		}
		name := sanitizeSlug(candidate)
		if name != "" {
			return name, nil
		}
	}
	return "", fmt.Errorf("cannot derive worktree name for %s", plan.Responsibility)
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
	workLinkPattern := "/" + filepath.ToSlash(filepath.Join(layout.AgentsDirName, "home", "*", "work"))
	worktreesPattern := "/" + filepath.ToSlash(filepath.Join(layout.AgentsDirName, "worktrees")) + "/"
	hasHome := false
	hasWorkLink := false
	hasWorktrees := false
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == homePattern {
			hasHome = true
		}
		if trimmed == workLinkPattern {
			hasWorkLink = true
		}
		if trimmed == worktreesPattern {
			hasWorktrees = true
		}
	}
	if hasHome && hasWorkLink && hasWorktrees {
		return nil
	}
	var addition string
	if len(data) > 0 && !strings.HasSuffix(string(data), "\n") {
		addition += "\n"
	}
	if len(data) > 0 {
		addition += "\n"
	}
	addition += "# Auto-written by aw agents (do not remove)\n"
	if !hasHome {
		addition += homePattern + "\n"
	}
	if !hasWorkLink {
		addition += workLinkPattern + "\n"
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
		if agent.Responsibility == primary.Responsibility {
			continue
		}
		if err := initTeamBootstrapAdditionalAgent(teamBootstrapAgentWorkspaceDir(primary), agent); err != nil {
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
	return teamBootstrapSource{}, usageError("non-interactive agents bootstrap requires a team source: AWEB_API_KEY, --invite-token, --username, --namespace/--team, or run from an initialized aw workspace to forward its current team")
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
	workspaceDir := teamBootstrapAgentWorkspaceDir(primary)
	if err := ensureConnectTargetClean(workspaceDir); err != nil {
		return err
	}

	switch source.Kind {
	case teamBootstrapSourceAPIKey:
		return initTeamBootstrapAgentViaAPIKey(workspaceDir, alias, primary.RoleName)
	case teamBootstrapSourceInvite:
		_, err := acceptInviteAndConnectTeamBootstrapAgent(workspaceDir, teamBootstrapInvite{Token: source.InviteToken}, alias, primary.RoleName, primary.GlobalAddress)
		return err
	case teamBootstrapSourceCurrent:
		invite, err := createTeamBootstrapInviteFromCurrentWorkspace()
		if err != nil {
			return err
		}
		_, err = acceptInviteAndConnectTeamBootstrapAgent(workspaceDir, invite, alias, primary.RoleName, primary.GlobalAddress)
		return err
	case teamBootstrapSourceBYOT:
		invite, err := createTeamBootstrapBYOTInvite()
		if err != nil {
			return err
		}
		_, err = acceptInviteAndConnectTeamBootstrapAgent(workspaceDir, invite, alias, primary.RoleName, primary.GlobalAddress)
		return err
	case teamBootstrapSourceHostedNew:
		_, err := guidedOnboardingWizard(guidedOnboardingRequest{
			WorkingDir:         workspaceDir,
			PromptIn:           cmd.InOrStdin(),
			PromptOut:          cmd.ErrOrStderr(),
			BaseURL:            strings.TrimSpace(teamBootstrapAwebURL),
			RegistryURL:        strings.TrimSpace(teamBootstrapRegistryURL),
			Username:           strings.TrimSpace(teamBootstrapUsername),
			Alias:              alias,
			Role:               primary.RoleName,
			Persistent:         strings.TrimSpace(primary.IdentityScope) == agentsIdentityScopeGlobal,
			InjectAgentDocs:    false,
			DoNotTouchAgentsMD: true,
			AskPostCreateSetup: false,
			NonInteractive:     !isTTY(),
		})
		return err
	default:
		return fmt.Errorf("unsupported agents bootstrap source %q", source.Kind)
	}
}

func initTeamBootstrapAdditionalAgent(primaryDir string, agent teamBootstrapAgentPlan) error {
	alias := strings.TrimSpace(agent.Alias)
	if alias == "" {
		alias = sanitizeSlug(agent.Name)
	}
	workspaceDir := teamBootstrapAgentWorkspaceDir(agent)
	if err := ensureConnectTargetClean(workspaceDir); err != nil {
		return err
	}

	invite, err := createTeamBootstrapInviteFromWorkspace(primaryDir)
	if err != nil {
		return err
	}
	_, err = acceptInviteAndConnectTeamBootstrapAgent(workspaceDir, invite, alias, agent.RoleName, agent.GlobalAddress)
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

func acceptInviteAndConnectTeamBootstrapAgent(homeDir string, invite teamBootstrapInvite, alias, roleName, addressOverride string) (connectOutput, error) {
	accepted, err := acceptTeamInviteWithBootstrapAwebURL(homeDir, invite, alias, addressOverride)
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

func acceptTeamInviteWithBootstrapAwebURL(homeDir string, invite teamBootstrapInvite, alias, addressOverride string) (*acceptedTeamInvite, error) {
	preferredAwebURL := strings.TrimSpace(invite.AwebURL)
	if preferredAwebURL == "" {
		preferredAwebURL = strings.TrimSpace(teamBootstrapAwebURL)
	}
	if preferredAwebURL == "" {
		return acceptTeamInviteWithDetails(homeDir, invite.Token, alias, addressOverride)
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
	return acceptTeamInviteWithDetails(homeDir, invite.Token, alias, addressOverride)
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
		return teamBootstrapInvite{}, usageError("--namespace is required for one-step agents bootstrap")
	}
	if teamName == "" {
		return teamBootstrapInvite{}, usageError("--team is required for one-step agents bootstrap")
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

	accepted, err := acceptTeamInviteWithBootstrapAwebURL(worktreePath, invite, alias, "")
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
			WorkspaceDir:   filepath.Join(homeRoot, responsibility),
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
	client, _, err := resolveClientSelectionForDir(teamBootstrapAgentWorkspaceDir(primary))
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
		commands = append(commands, "cd "+shellQuote(teamBootstrapAgentWorkspaceDir(plan))+" && "+formatShellCommand(initParts))
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
		b.WriteString("Agents bootstrap plan (dry run)\n")
	} else {
		b.WriteString("Agents bootstrap complete\n")
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
	if out.LayoutOnly {
		b.WriteString("Mode: layout-only\n")
	}
	b.WriteString(fmt.Sprintf("Agent home root: %s\n", out.HomeRoot))
	if strings.TrimSpace(out.IdentityPrefix) != "" {
		b.WriteString(fmt.Sprintf("Identity prefix: %s\n", out.IdentityPrefix))
	}
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
		scope := strings.TrimSpace(agent.IdentityScope)
		if scope == "" {
			scope = agentsIdentityScopeLocal
		}
		address := ""
		if strings.TrimSpace(agent.GlobalAddress) != "" {
			address = " address=" + agent.GlobalAddress
		}
		work := ""
		if strings.TrimSpace(agent.WorkDir) != "" {
			work = " work=" + agent.WorkDir
			if strings.TrimSpace(agent.WorkBinding) != "" {
				work += " (" + agent.WorkBinding + ")"
			}
		}
		workspace := ""
		if dir := teamBootstrapAgentWorkspaceDir(agent); dir != "" && dir != agent.HomeDir {
			workspace = " workspace=" + dir
		}
		b.WriteString(fmt.Sprintf("- %s: scope=%s name=%s role=%s%s%s home=%s%s%s\n", agent.Responsibility, scope, agent.Name, agent.RoleName, alias, address, agent.HomeDir, workspace, work))
		for _, check := range out.Availability {
			if check.Responsibility != agent.Responsibility {
				continue
			}
			b.WriteString(fmt.Sprintf("    %s: %s (%s: %s)\n", check.Field, check.Status, check.Source, check.Value))
		}
	}
	if len(out.NextCommands) > 0 {
		b.WriteString("\nInitialize/connect each agent workspace:\n")
		for _, command := range out.NextCommands {
			b.WriteString("  " + command + "\n")
		}
	}
	return b.String()
}

func formatAgentsProvisionOutput(v any) string {
	out := v.(agentsProvisionOutput)
	var b strings.Builder
	if out.DryRun {
		b.WriteString("Agents provision plan (dry run)\n")
	} else {
		b.WriteString("Agents provision complete\n")
	}
	b.WriteString(fmt.Sprintf("Agents dir: %s\n", out.AgentsDir))
	b.WriteString(fmt.Sprintf("Identity prefix: %s\n", out.IdentityPrefix))
	if strings.TrimSpace(out.TeamSource) != "" {
		b.WriteString(fmt.Sprintf("Team source: %s\n", out.TeamSource))
	}
	b.WriteString("\nAgents:\n")
	for _, agent := range out.Agents {
		alias := ""
		if agent.Alias != "" {
			alias = " alias=" + agent.Alias
		}
		scope := strings.TrimSpace(agent.IdentityScope)
		if scope == "" {
			scope = agentsIdentityScopeLocal
		}
		address := ""
		if strings.TrimSpace(agent.GlobalAddress) != "" {
			address = " address=" + agent.GlobalAddress
		}
		work := ""
		if strings.TrimSpace(agent.WorkDir) != "" {
			work = " work=" + agent.WorkDir
			if strings.TrimSpace(agent.WorkBinding) != "" {
				work += " (" + agent.WorkBinding + ")"
			}
		}
		workspace := ""
		if dir := teamBootstrapAgentWorkspaceDir(agent); dir != "" && dir != agent.HomeDir {
			workspace = " workspace=" + dir
		}
		b.WriteString(fmt.Sprintf("- %s: scope=%s name=%s role=%s%s%s home=%s%s%s\n", agent.Responsibility, scope, agent.Name, agent.RoleName, alias, address, agent.HomeDir, workspace, work))
		for _, check := range out.Availability {
			if check.Responsibility != agent.Responsibility {
				continue
			}
			b.WriteString(fmt.Sprintf("    %s: %s (%s: %s)\n", check.Field, check.Status, check.Source, check.Value))
		}
	}
	if len(out.NextCommands) > 0 {
		b.WriteString("\nAfter provisioning, start agents from:\n")
		for _, agent := range out.Agents {
			b.WriteString("  cd " + shellQuote(teamBootstrapAgentWorkspaceDir(agent)) + "\n")
		}
	}
	return b.String()
}

func formatAgentsAddOutput(v any) string {
	out := v.(agentsAddOutput)
	var b strings.Builder
	if out.DryRun {
		b.WriteString("Agents add plan (dry run)\n")
	} else {
		b.WriteString("Agents add complete\n")
	}
	b.WriteString(fmt.Sprintf("Agents dir: %s\n", out.AgentsDir))
	b.WriteString(fmt.Sprintf("Responsibility: %s\n", out.Responsibility))
	b.WriteString(fmt.Sprintf("Role: %s", out.RoleName))
	if out.RoleCreated {
		b.WriteString(" (new)")
	}
	b.WriteString("\n")
	if strings.TrimSpace(out.IdentityPrefix) != "" {
		b.WriteString(fmt.Sprintf("Identity prefix: %s\n", out.IdentityPrefix))
	}
	if out.LayoutOnly {
		b.WriteString("Mode: layout-only\n")
	}
	if strings.TrimSpace(out.TeamSource) != "" {
		b.WriteString(fmt.Sprintf("Team source: %s\n", out.TeamSource))
	}
	if len(out.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, warning := range out.Warnings {
			b.WriteString("- " + warning + "\n")
		}
	}
	b.WriteString("\nAgent:\n")
	agent := out.Agent
	scope := strings.TrimSpace(agent.IdentityScope)
	if scope == "" {
		scope = agentsIdentityScopeLocal
	}
	address := ""
	if strings.TrimSpace(agent.GlobalAddress) != "" {
		address = " address=" + agent.GlobalAddress
	}
	workspace := ""
	if dir := teamBootstrapAgentWorkspaceDir(agent); dir != "" && dir != agent.HomeDir {
		workspace = " workspace=" + dir
	}
	b.WriteString(fmt.Sprintf("- %s: scope=%s alias=%s%s home=%s%s work=%s\n", agent.Responsibility, scope, agent.Alias, address, agent.HomeDir, workspace, agent.WorkDir))
	for _, check := range out.Availability {
		b.WriteString(fmt.Sprintf("    %s: %s (%s: %s)\n", check.Field, check.Status, check.Source, check.Value))
	}
	return b.String()
}

func formatAgentsRemoveOutput(v any) string {
	out := v.(agentsRemoveOutput)
	var b strings.Builder
	if out.DryRun {
		b.WriteString("Agents remove plan (dry run)\n")
	} else {
		b.WriteString("Agents remove complete\n")
	}
	b.WriteString(fmt.Sprintf("Agents dir: %s\n", out.AgentsDir))
	b.WriteString(fmt.Sprintf("Responsibility: %s\n", out.Responsibility))
	b.WriteString(fmt.Sprintf("Home: %s\n", out.HomeDir))
	if strings.TrimSpace(out.WorkDir) != "" {
		b.WriteString(fmt.Sprintf("Work: %s", out.WorkDir))
		if strings.TrimSpace(out.WorkBinding) != "" {
			b.WriteString(" (" + out.WorkBinding + ")")
		}
		b.WriteString("\n")
	}
	if strings.TrimSpace(out.TeamID) != "" {
		b.WriteString(fmt.Sprintf("Team: %s\n", out.TeamID))
	}
	if strings.TrimSpace(out.MemberAddress) != "" {
		b.WriteString(fmt.Sprintf("Member address: %s\n", out.MemberAddress))
	}
	if strings.TrimSpace(out.LocalBackupDir) != "" {
		b.WriteString(fmt.Sprintf("Local backup: %s\n", out.LocalBackupDir))
	}
	if len(out.Warnings) > 0 {
		b.WriteString("\nWarnings:\n")
		for _, warning := range out.Warnings {
			b.WriteString("- " + warning + "\n")
		}
	}
	b.WriteString("\nActions:\n")
	for _, action := range out.Actions {
		b.WriteString(fmt.Sprintf("- %s: %s", action.Name, action.Status))
		if strings.TrimSpace(action.Detail) != "" {
			b.WriteString(" (" + action.Detail + ")")
		}
		b.WriteString("\n")
	}
	return b.String()
}
