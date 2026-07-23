package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	blueprintpkg "github.com/awebai/aw/internal/blueprint"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

var (
	teamHumanCreateBYOT        bool
	teamHumanCreateName        string
	teamHumanCreateNamespace   string
	teamHumanCreateDisplayName string
	teamHumanCreateServiceURL  string
	teamHumanCreateRegistryURL string
	teamHumanCreateAlias       string
	teamHumanCreateUsername    string
	teamHumanCreateHome        string
	teamHumanCreateRuntime     string
	teamHumanCreateLibraryURL  string
	teamHumanCreateProfiles    []string
	teamHumanCreateAgents      []string
	teamHumanCreateBlueprint   string
	teamHumanCreateFirstLocal  bool
	teamHumanCreateFirstGlobal bool
	teamHumanInviteTeamID      string
	teamHumanAddLocal          bool
	teamHumanAddGlobal         bool
	teamHumanAddLayoutOnly     bool
	teamHumanAddStart          bool
	teamHumanAddAttach         bool
	teamHumanAddNoAttach       bool
	teamHumanAddSession        string
	teamHumanAddHome           string
	teamHumanAddWorkDir        string
	teamHumanAddRuntime        string
	teamHumanAddLibraryURL     string
	teamHumanAddBlueprint      string
	teamHumanExtendAPIKey      string
	teamHumanExtendTeamID      string
	teamHumanRemoveTeamID      string
	teamHumanRemoveRegistryURL string
	teamHumanRemoveAwebURL     string
	teamHumanRemoveAPIKey      string
)

var teamHumanCmd = &cobra.Command{
	Use:   "team",
	Short: "Everyday teams: create, add, invite, join, list, switch, leave, replace-key, remove-agent",
	Long: "Everyday team membership commands.\n\n" +
		"Use these commands for the normal hosted invite/join membership flow and for\n" +
		"checking or switching this identity's installed team memberships. Protocol/admin\n" +
		"controller operations remain under `aw id team`.",
}

var teamHumanCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a local empty-profile team workspace",
	Long: "Create a local empty-profile team workspace.\n\n" +
		"This wraps aw init for the aw-local path. No --agent/--profile means no Library call\n" +
		"and no profile materialization. --agent accepts [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]\n" +
		"(or NAME[:local|global] for an empty-profile agent). Omitted names use the\n" +
		"server-authoritative next classic name; omitted scope comes from profile.yaml.\n" +
		"All --agent/--profile specs populate agents/instances for aw team up; only\n" +
		"--home with a single spec uses that spec for the root workspace profile.\n" +
		"Deprecated --profile is accepted as --agent for transition; @VERSION is dropped.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanCreate,
}

var teamHumanAddCmd = &cobra.Command{
	Use:   "add <agent-spec>...",
	Short: "Add agents to this team's agents/instances layout",
	Long:  "Add one or more agents to agents/instances/<name>/. Specs use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME] or NAME[:local|global] for empty-profile homes. Omitted names use the server-authoritative next classic name; omitted scope comes from profile.yaml. @VERSION is no longer supported.",
	Args:  cobra.MinimumNArgs(1),
	RunE:  runTeamHumanAdd,
}

var teamHumanInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Invite an agent or workspace to the active team",
	Long: "Invite an agent or workspace to the active team.\n\n" +
		"This creates an invite token using the current team's authority for a separate\n" +
		"workspace or machine, then the joining workspace runs `aw team join <token>`.\n" +
		"For local empty-profile homes under agents/instances/, use `aw team add`.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := applyHumanTeamIDToInvite(teamHumanInviteTeamID); err != nil {
			return err
		}
		return runTeamInvite(cmd, args)
	},
}

var teamHumanJoinCmd = &cobra.Command{
	Use:   "join <invite-token>",
	Short: "Join a team from an invite token",
	Long: "Join a team from an invite token.\n\n" +
		"Run this in a clean target directory. It refuses to overwrite an existing\n" +
		".aw identity/key. After joining, run `aw init` if the output says the\n" +
		"workspace still needs to be connected to the service.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamAcceptInvite,
}

var teamHumanListCmd = &cobra.Command{
	Use:   "list",
	Short: "List team memberships for this identity",
	RunE:  runTeamList,
}

var teamHumanSwitchCmd = &cobra.Command{
	Use:   "switch <team_id>",
	Short: "Switch the active team for this identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamSwitch,
}

var teamHumanLeaveCmd = &cobra.Command{
	Use:   "leave <team_id>",
	Short: "Remove a team membership from this identity",
	Args:  cobra.ExactArgs(1),
	RunE:  runTeamLeave,
}

var teamHumanRemoveAgentCmd = &cobra.Command{
	Use:   "remove-agent <member-address>",
	Short: "Remove an agent from a team",
	Long: "Remove an agent from a team.\n\n" +
		"This everyday verb maps to the identity/certificate revocation primitive.\n" +
		"Customer-controlled teams revoke with the local team controller key; hosted\n" +
		"aweb.ai teams call the cloud-mediated controller revoke endpoint.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanRemoveAgent,
}

func registerTeamMemberAddFlags(cmd *cobra.Command, includePlacementFlags bool) {
	cmd.Flags().BoolVar(&teamHumanAddLocal, "local", false, "Add a local team-scoped agent identity (default)")
	cmd.Flags().BoolVar(&teamHumanAddGlobal, "global", false, "Add a global AWID identity/address-backed agent")
	if includePlacementFlags {
		cmd.Flags().BoolVar(&teamHumanAddLayoutOnly, "layout-only", false, "Only create agents/instances/<name>; do not create identity state")
	}
	cmd.Flags().BoolVar(&teamHumanAddStart, "start", false, "Launch the added agent in tmux after materializing it")
	cmd.Flags().BoolVar(&teamHumanAddAttach, "attach", true, "Attach or switch to the tmux session after --start launch")
	cmd.Flags().BoolVar(&teamHumanAddNoAttach, "no-attach", false, "Do not attach or switch to the tmux session after --start launch")
	cmd.Flags().StringVar(&teamHumanAddSession, "session", "", "tmux session name for --start (default: active team name or aw-team)")
	if includePlacementFlags {
		cmd.Flags().StringVar(&teamHumanAddHome, "home", "", "Agent home directory override for a single added agent (default: agents/instances/<name>)")
	}
	cmd.Flags().StringVar(&teamHumanAddWorkDir, "work-dir", "", "Git repo to use for the agent's worktree (default: repo containing the home, if any)")
	cmd.Flags().StringVar(&teamHumanAddRuntime, "runtime", "", "Materialization runtime for profile-bound agents (claude-code|codex|pi|local-shell; default claude-code)")
	cmd.Flags().StringVar(&teamHumanAddLibraryURL, "library-url", "", "Public Library catalog base URL (default: AWEB_LIBRARY_URL or https://library.aweb.ai)")
	cmd.Flags().StringVar(&teamHumanAddBlueprint, "blueprint", "", "Default public Library blueprint for profile-only selectors (default: AWEB_BLUEPRINT or aweb.team)")
}

func init() {
	teamHumanCmd.GroupID = groupIdentity

	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateBYOT, "byot", false, "Create a customer-controlled AWID team with local namespace controller authority")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateName, "name", "", "Team name")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateNamespace, "namespace", "", "Namespace domain for --byot")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateDisplayName, "display-name", "", "Team display name")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateServiceURL, "service", "", "Hosted service URL for dashboard guidance")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateRegistryURL, "registry", "", "Registry origin override for --byot")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateAlias, "first-agent-name", "", "Initial workspace member name (defaults to <name>)")
	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateFirstLocal, "first-agent-local", false, "Enroll the first agent as a local team-scoped identity (default)")
	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateFirstGlobal, "first-agent-global", false, "Enroll the first agent as a global identity, reusing an existing global identity or creating one when founding with hosted/namespace authority")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateAlias, "alias", "", "Deprecated alias for --first-agent-name")
	markDeprecatedHiddenFlag(teamHumanCreateCmd, "alias", "first-agent-name")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateUsername, "username", "", "Hosted username to create when founding through managed aweb onboarding")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateHome, "home", "", "Agent home directory override for single-agent --profile create")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateRuntime, "runtime", "", "Materialization runtime for agent/profile homes (claude-code|codex|pi|local-shell; default claude-code)")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateLibraryURL, "library-url", "", "Public Library catalog base URL (default: AWEB_LIBRARY_URL or https://library.aweb.ai)")
	teamHumanCreateCmd.Flags().StringArrayVar(&teamHumanCreateAgents, "agent", nil, "Agent spec [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME] or NAME[:local|global]")
	teamHumanCreateCmd.Flags().StringArrayVar(&teamHumanCreateProfiles, "profile", nil, "Deprecated alias for --agent; use [NAME@]BLUEPRINT/PROFILE[:local|global][=RUNTIME]")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateBlueprint, "blueprint", "", "With --agent/--profile, default public Library blueprint for profile-only selectors; without agents, materialize all profiles in a local blueprint directory")
	teamHumanCmd.AddCommand(teamHumanCreateCmd)

	teamHumanAddAttach = true
	registerTeamMemberAddFlags(teamHumanAddCmd, true)
	teamHumanCmd.AddCommand(teamHumanAddCmd)

	teamHumanExtendCmd.Flags().StringVar(&teamHumanExtendAPIKey, "api-key", "", "Team API key for extending a team (overrides AWEB_API_KEY)")
	teamHumanExtendCmd.Flags().StringVar(&teamHumanExtendTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to extend when discovery is ambiguous or when asserting an API key's team")
	registerTeamMemberAddFlags(teamHumanExtendCmd, false)
	teamHumanCmd.AddCommand(teamHumanExtendCmd)

	teamHumanInviteCmd.Flags().StringVar(&teamHumanInviteTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to invite from (defaults to active team)")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteMemberLocal, "member-local", false, "Create local workspace member invite (default)")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteMemberGlobal, "member-global", false, "Create global member invite")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteLocal, "local", false, "Deprecated alias for --member-local")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteGlobal, "global", false, "Deprecated alias for --member-global")
	markDeprecatedHiddenFlag(teamHumanInviteCmd, "local", "member-local")
	markDeprecatedHiddenFlag(teamHumanInviteCmd, "global", "member-global")
	teamHumanCmd.AddCommand(teamHumanInviteCmd)

	teamHumanJoinCmd.Flags().StringVar(&teamAcceptAlias, "name", "", "Member name for the accepting agent (defaults to identity name)")
	teamHumanJoinCmd.Flags().StringVar(&teamAcceptAlias, "alias", "", "Deprecated alias for --name")
	markDeprecatedHiddenFlag(teamHumanJoinCmd, "alias", "name")
	teamHumanJoinCmd.Flags().BoolVar(&teamAcceptLocal, "local", false, "Join with a local workspace identity (default)")
	teamHumanJoinCmd.Flags().BoolVar(&teamAcceptGlobal, "global", false, "Join by reusing the existing global identity in this workspace")
	teamHumanJoinCmd.Flags().BoolVar(&teamAcceptNoAddress, "no-address", false, "For --global, join with did:aw continuity but no member address")
	teamHumanJoinCmd.Flags().StringVar(&teamAcceptAddress, "address", "", "Advanced: existing owned address to place in the global member certificate")
	teamHumanCmd.AddCommand(teamHumanJoinCmd)

	teamHumanCmd.AddCommand(teamHumanListCmd)
	teamHumanCmd.AddCommand(teamHumanSwitchCmd)
	teamHumanCmd.AddCommand(teamHumanLeaveCmd)
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to remove from (defaults to active team)")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveRegistryURL, "registry", "", "Registry origin override")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveAwebURL, "aweb-url", "", "Hosted aweb API URL override for cloud-mediated removal")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveAPIKey, "api-key", "", "Team API key for hosted removal (overrides AWEB_API_KEY; workspace-bound API keys are rejected by hosted aweb)")
	teamHumanCmd.AddCommand(teamHumanRemoveAgentCmd)
	rootCmd.AddCommand(teamHumanCmd)
}

type teamAgentSpec struct {
	Raw               string
	Name              string
	Scope             string
	Profile           *libraryProfileSelector
	LocalBlueprintDir string
	LayoutOnly        bool
	RuntimeKind       string
	ResolvedName      string
}

func teamHumanCreateAgentSpecs() ([]teamAgentSpec, error) {
	raws := append([]string{}, teamHumanCreateAgents...)
	if len(teamHumanCreateProfiles) > 0 {
		for _, rawProfile := range teamHumanCreateProfiles {
			rawProfile = strings.TrimSpace(rawProfile)
			compat := rawProfile
			if !strings.Contains(rawProfile, "@") {
				profilePart := rawProfile
				if before, _, ok := strings.Cut(profilePart, "="); ok {
					profilePart = before
				}
				if before, _, ok := strings.Cut(profilePart, ":"); ok {
					profilePart = before
				}
				if _, profileRef, ok := strings.Cut(profilePart, "/"); ok && isValidWorkspaceAlias(profileRef) {
					compat = profileRef + "@" + rawProfile
				}
			}
			raws = append(raws, compat)
		}
	}
	localBlueprintDir := ""
	if strings.TrimSpace(teamHumanCreateBlueprint) != "" && len(raws) == 0 {
		absBlueprint, err := filepath.Abs(strings.TrimSpace(teamHumanCreateBlueprint))
		if err != nil {
			return nil, err
		}
		bp, err := blueprintpkg.LoadLocalDir(absBlueprint)
		if err != nil {
			return nil, fmt.Errorf("load blueprint: %w", err)
		}
		localBlueprintDir = absBlueprint
		for _, profile := range bp.LoadedProfiles {
			spec := bp.ID + "/" + profile.ID
			if scope := strings.TrimSpace(profile.Scope); scope != "" {
				spec += ":" + scope
			}
			raws = append(raws, spec)
		}
	}
	specs := make([]teamAgentSpec, 0, len(raws))
	for _, raw := range raws {
		spec, err := parseTeamAgentSpec(raw)
		if err != nil {
			return nil, err
		}
		if localBlueprintDir != "" {
			spec.LocalBlueprintDir = localBlueprintDir
		}
		if spec.Profile != nil {
			parsed, err := applyMaterializeRuntimePolicy(*spec.Profile, teamHumanCreateRuntime)
			if err != nil {
				return nil, err
			}
			if localBlueprintDir == "" {
				parsed, err = resolveLibraryProfileSelectorSource(parsed, teamHumanCreateLibraryURL, teamHumanCreateBlueprint)
				if err != nil {
					return nil, err
				}
			}
			spec.Profile = &parsed
			spec.RuntimeKind = parsed.RuntimeKind
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func parseTeamAgentSpec(raw string) (teamAgentSpec, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return teamAgentSpec{}, usageError("agent spec is required")
	}
	runtimeKind := ""
	body := trimmed
	if before, after, ok := strings.Cut(trimmed, "="); ok {
		body = strings.TrimSpace(before)
		runtimeKind = strings.TrimSpace(after)
		if runtimeKind == "" {
			return teamAgentSpec{}, usageError("runtime is required after =")
		}
		var err error
		runtimeKind, err = normalizeMaterializeRuntimeKind(runtimeKind)
		if err != nil {
			return teamAgentSpec{}, err
		}
	}
	name := ""
	profilePart := body
	if before, after, ok := strings.Cut(body, "@"); ok {
		name = strings.TrimSpace(before)
		profilePart = strings.TrimSpace(after)
		if name == "" {
			return teamAgentSpec{}, usageError("agent name is required before @")
		}
		if strings.Contains(name, "/") {
			return teamAgentSpec{}, usageError("versioned Library profile selectors are not supported; @ now separates NAME from BLUEPRINT/PROFILE")
		}
		if !isValidWorkspaceAlias(name) {
			return teamAgentSpec{}, usageError("invalid agent name %q: must start with an alphanumeric and contain only alphanumerics, dashes, or underscores (max 64 chars)", name)
		}
	}
	if strings.Contains(profilePart, "/") || name != "" {
		selector, err := parseLibraryProfileSelector(profilePart)
		if err != nil {
			return teamAgentSpec{}, err
		}
		if runtimeKind != "" && strings.TrimSpace(selector.RuntimeKind) == "" {
			selector.RuntimeKind = runtimeKind
		}
		return teamAgentSpec{Raw: trimmed, Name: name, Profile: &selector, RuntimeKind: selector.RuntimeKind, Scope: selector.IdentityScope}, nil
	}
	if runtimeKind != "" {
		return teamAgentSpec{}, usageError("=RUNTIME is only valid with BLUEPRINT/PROFILE agent specs")
	}
	emptyName := profilePart
	scope := ""
	if before, after, ok := strings.Cut(profilePart, ":"); ok {
		emptyName = strings.TrimSpace(before)
		var err error
		scope, err = normalizeTeamAgentScope(after)
		if err != nil {
			return teamAgentSpec{}, err
		}
	}
	emptyName = strings.TrimSpace(emptyName)
	if emptyName == "" {
		return teamAgentSpec{}, usageError("empty-profile agent name is required")
	}
	if !isValidWorkspaceAlias(emptyName) {
		return teamAgentSpec{}, usageError("invalid agent name %q: must start with an alphanumeric and contain only alphanumerics, dashes, or underscores (max 64 chars)", emptyName)
	}
	return teamAgentSpec{Raw: trimmed, Name: emptyName, Scope: scope}, nil
}

type teamHumanCreateOutput struct {
	Status       string `json:"status"`
	TeamName     string `json:"team_name"`
	ProfileMode  string `json:"profile_mode"`
	TeamID       string `json:"team_id,omitempty"`
	Alias        string `json:"alias,omitempty"`
	WorkspaceID  string `json:"workspace_id,omitempty"`
	AwebURL      string `json:"aweb_url,omitempty"`
	RegistryURL  string `json:"registry_url,omitempty"`
	HomeDir      string `json:"home_dir,omitempty"`
	NoLibrary    bool   `json:"no_library"`
	NoProfile    bool   `json:"no_profile"`
	IdentityOnly bool   `json:"identity_only"`
}

type teamHumanCreateFoundingResult struct {
	HomeDir           string
	Selector          *libraryProfileSelector
	LocalBlueprintDir string
	HumanOutput       *teamHumanCreateOutput
	TeamOutput        *teamCreateOutput
	GuidedResult      *guidedOnboardingResult
}

func runTeamHumanCreate(cmd *cobra.Command, args []string) error {
	teamName := strings.TrimSpace(args[0])
	if teamName == "" {
		return usageError("team name is required")
	}
	agentSpecs, err := teamHumanCreateAgentSpecs()
	if err != nil {
		return err
	}
	wd, _ := os.Getwd()
	printTeamCreateExtendNotice(wd)
	createHomeOverride := ""
	if strings.TrimSpace(teamHumanCreateHome) != "" {
		if len(agentSpecs) == 0 {
			return usageError("aw team create --home requires --profile/--agent")
		}
		if len(agentSpecs) > 1 {
			return usageError("aw team create --home can only be used with a single --agent/--profile")
		}
		homeDir, err := filepath.Abs(strings.TrimSpace(teamHumanCreateHome))
		if err != nil {
			return err
		}
		if err := preflightProfileAgentHome(homeDir); err != nil {
			return err
		}
		createHomeOverride = homeDir
	}
	rootSpecIsAgentHome := createHomeOverride != ""
	var firstSpec teamAgentSpec
	var selector *libraryProfileSelector
	if rootSpecIsAgentHome && len(agentSpecs) > 0 {
		firstSpec = agentSpecs[0]
		if firstSpec.Profile != nil {
			selector = firstSpec.Profile
		}
	}
	rosterSpecs, err := teamHumanCreateRosterSpecs(agentSpecs, rootSpecIsAgentHome)
	if err != nil {
		return err
	}
	rosterSpecs, err = resolveTeamHumanCreateRosterScopes(rosterSpecs)
	if err != nil {
		return err
	}
	if err := preflightTeamHumanCreateRosterHomes(wd, rosterSpecs); err != nil {
		return err
	}
	if err := preflightTeamHumanCreateRosterAuthority(wd, rosterSpecs); err != nil {
		return err
	}
	firstAgentScope, err := resolveTeamHumanCreateFirstAgentScope()
	if err != nil {
		return err
	}
	if rootSpecIsAgentHome {
		if scope := strings.TrimSpace(firstSpec.Scope); scope != "" {
			if (teamHumanCreateFirstLocal || teamHumanCreateFirstGlobal) && scope != firstAgentScope {
				return usageError("first agent scope %q conflicts with --first-agent-%s", scope, firstAgentScope)
			}
			firstAgentScope = scope
		}
	}
	alias := strings.TrimSpace(teamHumanCreateAlias)
	if rootSpecIsAgentHome {
		if name := strings.TrimSpace(firstSpec.Name); name != "" {
			if alias != "" && !strings.EqualFold(alias, name) {
				return usageError("the first listed --agent is the first team member when --home is used; --first-agent-name cannot name a separate/additional agent for a single-home create")
			}
			alias = name
		}
	}
	if alias == "" {
		alias = strings.ToLower(teamName)
	}
	if err := preflightTeamHumanCreateRootAlias(alias, rosterSpecs); err != nil {
		return err
	}
	if teamHumanCreateBYOT {
		name := strings.TrimSpace(teamHumanCreateName)
		if name == "" {
			name = teamName
		}
		domain := awconfig.NormalizeDomain(teamHumanCreateNamespace)
		if domain == "" {
			return usageError("aw team create --byot requires --namespace")
		}
		if firstAgentScope == awid.IdentityModeGlobal {
			identityExists, err := teamCreateHasIdentityMaterial(wd)
			if err != nil {
				return err
			}
			if !identityExists {
				if err := bootstrapTeamCreateGlobalIdentity(wd, alias, domain, strings.TrimSpace(teamHumanCreateRegistryURL)); err != nil {
					return err
				}
			}
		}
		teamOut, err := foundTeamWithNamespaceControllerAuthority(wd, name, alias, domain, strings.TrimSpace(teamHumanCreateRegistryURL), strings.TrimSpace(teamHumanCreateDisplayName), firstAgentScope)
		if err != nil {
			return err
		}
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HomeDir: wd, Selector: selector, LocalBlueprintDir: firstSpec.LocalBlueprintDir, TeamOutput: teamOut}, rosterSpecs)
	}
	if strings.TrimSpace(teamHumanCreateNamespace) != "" || strings.TrimSpace(teamHumanCreateRegistryURL) != "" {
		return usageError("aw team create does not use --namespace or --registry in the local empty-profile path")
	}
	if createHomeOverride != "" {
		if err := os.MkdirAll(createHomeOverride, 0o755); err != nil {
			return err
		}
		wd = createHomeOverride
	}
	if selector != nil {
		if sel, err := resolveSelectionForDir(wd); err == nil && strings.TrimSpace(sel.TeamID) != "" {
			out := teamHumanCreateOutput{Status: "created", TeamName: teamName, ProfileMode: "empty", TeamID: sel.TeamID, Alias: sel.Alias, WorkspaceID: sel.WorkspaceID, AwebURL: sel.AwebURL, HomeDir: wd, NoLibrary: true, NoProfile: true, IdentityOnly: true}
			return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HomeDir: wd, Selector: selector, HumanOutput: &out}, nil)
		}
	}
	identityExists, err := teamCreateHasIdentityMaterial(wd)
	if err != nil {
		return err
	}
	if identityExists {
		teamOut, err := runTeamHumanCreateForExistingIdentity(wd, teamName, alias, firstAgentScope, selector)
		if err != nil {
			return err
		}
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HomeDir: wd, TeamOutput: teamOut}, rosterSpecs)
	}
	awebURL, err := resolveInitAwebURL()
	if err != nil {
		return err
	}
	registryURL, err := resolveInitAWIDRegistryURL()
	if err != nil {
		return err
	}
	if apiKey := resolveInitAPIKey(); apiKey != "" {
		// The API-key workspace-init endpoint is reached at <base>/api/v1/..., so an
		// /api-suffixed AWEB_URL must be stripped to its base here, matching aw init.
		apiKeyAwebURL, err := resolveAPIKeyInitAwebURL()
		if err != nil {
			return err
		}
		firstAgentGlobal := firstAgentScope == awid.IdentityModeGlobal
		apiAlias := alias
		apiName := ""
		if firstAgentGlobal {
			apiAlias = ""
			apiName = alias
		}
		result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
			WorkingDir:  wd,
			AwebURL:     apiKeyAwebURL,
			RegistryURL: registryURL,
			APIKey:      apiKey,
			Name:        apiName,
			Alias:       apiAlias,
			Persistent:  firstAgentGlobal,
			HumanName:   resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:   resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		})
		if err != nil {
			return err
		}
		out := teamHumanCreateOutputFromConnect(teamName, result, wd)
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HomeDir: wd, Selector: selector, HumanOutput: &out}, rosterSpecs)
	}
	if !initShouldUseImplicitLocalFlow(registryURL) {
		guidedResult, err := runTeamHumanCreateHostedInitBundle(wd, awebURL, registryURL, strings.TrimSpace(teamHumanCreateUsername), alias, firstAgentScope)
		if err != nil {
			return err
		}
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HomeDir: wd, Selector: selector, GuidedResult: guidedResult}, rosterSpecs)
	}
	if firstAgentScope == awid.IdentityModeGlobal {
		return usageError("--first-agent-global requires an existing global identity or namespace/hosted context; run `aw id create`, pass --namespace with --byot, or use hosted onboarding")
	}
	result, err := initRunImplicitLocalFlow(implicitLocalInitRequest{
		WorkingDir:  wd,
		AwebURL:     awebURL,
		RegistryURL: registryURL,
		Alias:       alias,
		TeamName:    teamName,
		HumanName:   resolveHumanNameValue(strings.TrimSpace(initHumanName)),
		AgentType:   resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
	})
	if err != nil {
		if isRegistryUnavailableError(err) {
			return fmt.Errorf("local awid registry %s is not reachable; start the local stack and retry: %w", registryURL, err)
		}
		return err
	}
	out := teamHumanCreateOutputFromConnect(teamName, result, wd)
	return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HomeDir: wd, Selector: selector, HumanOutput: &out}, rosterSpecs)
}

func finishTeamHumanCreateFounding(result teamHumanCreateFoundingResult, rosterSpecs []teamAgentSpec) error {
	if result.Selector != nil {
		if strings.TrimSpace(result.LocalBlueprintDir) != "" {
			if _, _, err := applyLocalBlueprintProfileToHome(result.HomeDir, *result.Selector, result.LocalBlueprintDir, true); err != nil {
				return err
			}
			if err := configureMaterializedAgentHome(result.HomeDir); err != nil {
				return err
			}
		} else if _, _, err := applyPublicLibraryProfileToHomeAndConfigure(result.HomeDir, *result.Selector, true); err != nil {
			return err
		}
		if result.HumanOutput != nil {
			result.HumanOutput.ProfileMode = "library"
			result.HumanOutput.NoLibrary = false
			result.HumanOutput.NoProfile = false
			result.HumanOutput.IdentityOnly = false
		}
	}
	if result.HumanOutput != nil {
		printOutput(*result.HumanOutput, formatTeamHumanCreate)
	}
	if result.TeamOutput != nil {
		printOutput(*result.TeamOutput, formatTeamCreate)
	}
	if result.GuidedResult != nil && !jsonFlag {
		initPrintGuidedOnboardingReady(result.GuidedResult)
	}
	return runTeamHumanCreateRosterAdd(rosterSpecs)
}

func teamHumanCreateRosterSpecs(agents []teamAgentSpec, rootSpecIsAgentHome bool) ([]teamAgentSpec, error) {
	seenExplicit := map[string]bool{}
	for _, agent := range agents {
		name := strings.TrimSpace(agent.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if seenExplicit[key] {
			return nil, usageError("duplicate roster agent name %q", name)
		}
		seenExplicit[key] = true
	}
	if len(agents) == 0 {
		return nil, nil
	}
	if rootSpecIsAgentHome {
		if len(agents) <= 1 {
			return nil, nil
		}
		specs := make([]teamAgentSpec, 0, len(agents)-1)
		specs = append(specs, agents[1:]...)
		return specs, nil
	}
	return append([]teamAgentSpec(nil), agents...), nil
}

func preflightTeamHumanCreateRootAlias(rootAlias string, specs []teamAgentSpec) error {
	rootAlias = strings.TrimSpace(rootAlias)
	for _, spec := range specs {
		name := strings.TrimSpace(spec.Name)
		if name != "" && strings.EqualFold(name, rootAlias) {
			return usageError("roster agent name %q conflicts with root operator alias %q; choose a different --agent name or set --first-agent-name to a distinct root alias", name, rootAlias)
		}
	}
	return nil
}

func resolveTeamHumanCreateRosterScopes(specs []teamAgentSpec) ([]teamAgentSpec, error) {
	resolved := append([]teamAgentSpec(nil), specs...)
	for i := range resolved {
		scope := strings.TrimSpace(resolved[i].Scope)
		if scope == "" && resolved[i].Profile != nil {
			if strings.TrimSpace(resolved[i].LocalBlueprintDir) != "" {
				scope = awid.IdentityModeLocal
			} else {
				profile, profileScope, err := resolveLibraryProfileScopeAndCache(*resolved[i].Profile)
				if err != nil {
					return nil, fmt.Errorf("resolve agent %s identity scope: %w", teamHumanCreateRosterSpecName(resolved[i]), err)
				}
				resolved[i].Profile = &profile
				scope = profileScope
			}
		}
		if scope == "" {
			scope = awid.IdentityModeLocal
		}
		resolved[i].Scope = scope
	}
	return resolved, nil
}

func preflightTeamHumanCreateRosterHomes(wd string, specs []teamAgentSpec) error {
	agentsRoot := filepath.Join(resolveRepoRoot(wd), "agents", "instances")
	for _, spec := range specs {
		name := strings.TrimSpace(spec.Name)
		if name == "" {
			continue
		}
		homeDir := filepath.Join(agentsRoot, name)
		if spec.Profile != nil {
			if err := preflightProfileAgentHome(homeDir); err != nil {
				return err
			}
		} else if err := preflightEmptyAgentHome(homeDir); err != nil {
			return err
		}
	}
	return nil
}

func preflightTeamHumanCreateRosterAuthority(wd string, specs []teamAgentSpec) error {
	if initIsTTY() || teamHumanCreateBYOT || strings.TrimSpace(resolveInitAPIKey()) != "" {
		return nil
	}
	identityExists, err := teamCreateHasIdentityMaterial(wd)
	if err != nil {
		return err
	}
	if identityExists {
		return nil
	}
	registryURL, err := resolveInitAWIDRegistryURL()
	if err != nil {
		return err
	}
	if initShouldUseImplicitLocalFlow(registryURL) {
		return nil
	}
	for _, spec := range specs {
		if strings.TrimSpace(spec.Scope) != awid.IdentityModeGlobal {
			continue
		}
		name := teamHumanCreateRosterSpecName(spec)
		if spec.Profile == nil {
			return usageError("agent %s resolves to global identity scope; global agents cannot be enrolled through non-interactive hosted create; pass %s:local (or use an API key/controller-authority flow that supports global identity enrollment)", name, name)
		}
		profileRef := strings.TrimSpace(spec.Profile.SourceBlueprintRef) + "/" + strings.TrimSpace(spec.Profile.ProfileRef)
		override := name + "@" + profileRef + ":local"
		if runtimeKind := strings.TrimSpace(spec.RuntimeKind); runtimeKind != "" {
			override += "=" + runtimeKind
		}
		return usageError("agent %s resolves to global identity scope (from profile %s); global agents cannot be enrolled through non-interactive hosted create; pass %s (or use an API key/controller-authority flow that supports global identity enrollment)", name, profileRef, override)
	}
	return nil
}

func teamHumanCreateRosterSpecName(spec teamAgentSpec) string {
	if name := strings.TrimSpace(spec.Name); name != "" {
		return name
	}
	if spec.Profile != nil {
		return strings.TrimSpace(spec.Profile.ProfileRef)
	}
	return strings.TrimSpace(spec.Raw)
}

func runTeamHumanCreateRosterAdd(specs []teamAgentSpec) error {
	if len(specs) == 0 {
		return nil
	}
	args := make([]string, 0, len(specs))
	for _, spec := range specs {
		args = append(args, spec.Raw)
	}
	return runTeamHumanAddWithOptions(nil, args, teamHumanAddRunOptions{Specs: append([]teamAgentSpec(nil), specs...)})
}

func bootstrapTeamCreateGlobalIdentity(wd, alias, domain, registryURL string) error {
	domain = awconfig.NormalizeDomain(domain)
	if domain == "" {
		return usageError("--first-agent-global requires --namespace with --byot when no global identity exists")
	}
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return err
	}
	if !exists {
		return usageError("--first-agent-global with --byot requires namespace controller authority for %s; run `aw id create --domain %s --name %s` first, or use hosted onboarding", domain, domain, alias)
	}
	_, err = executeIDCreate(wd, idCreateOptions{
		Name:        alias,
		Domain:      domain,
		RegistryURL: registryURL,
		Now:         time.Now,
	})
	return err
}

func teamCreateHasIdentityMaterial(workingDir string) (bool, error) {
	if _, _, err := awconfig.LoadWorktreeIdentityFromDir(workingDir); err == nil {
		return true, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if _, err := os.Stat(awconfig.WorktreeSigningKeyPath(workingDir)); err == nil {
		return true, nil
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	return false, nil
}

func runTeamHumanCreateHostedInitBundle(wd, awebURL, registryURL, username, alias, firstAgentScope string) (*guidedOnboardingResult, error) {
	canPrompt := initIsTTY() && !jsonFlag
	askPostCreateSetup := canPrompt && !initHasExplicitOnboardingArgs()
	firstAgentGlobal := firstAgentScope == awid.IdentityModeGlobal
	requestAlias := alias
	requestName := ""
	if firstAgentGlobal {
		requestAlias = ""
		requestName = alias
	}
	req := guidedOnboardingRequest{
		WorkingDir:         wd,
		PromptIn:           os.Stdin,
		PromptOut:          os.Stderr,
		BaseURL:            awebURL,
		RegistryURL:        registryURL,
		ServerName:         serverFlag,
		BYOD:               false,
		Username:           strings.TrimSpace(firstNonEmptyLibraryValue(username, initUsername)),
		Domain:             strings.TrimSpace(initDomain),
		Alias:              requestAlias,
		Name:               requestName,
		HumanName:          resolveHumanNameValue(strings.TrimSpace(initHumanName)),
		AgentType:          resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		Role:               resolveRequestedRole(strings.TrimSpace(initRole)),
		Persistent:         firstAgentGlobal,
		InboundMode:        canonicalInitInboundModeForWire(initInboundMode),
		InjectAgentDocs:    !initDoNotTouchAgentsMD && !jsonFlag,
		DoNotTouchAgentsMD: initDoNotTouchAgentsMD,
		AskPostCreateSetup: askPostCreateSetup,
		NonInteractive:     !canPrompt,
	}
	if err := validateHostedNonInteractiveRequired(req); err != nil {
		return nil, err
	}
	result, err := guidedOnboardingWizard(req)
	if err != nil {
		return nil, err
	}
	return result, nil
}

func resolveTeamHumanCreateFirstAgentScope() (string, error) {
	if teamHumanCreateFirstLocal && teamHumanCreateFirstGlobal {
		return "", usageError("--first-agent-local and --first-agent-global cannot be used together")
	}
	if teamHumanCreateFirstGlobal {
		return awid.IdentityModeGlobal, nil
	}
	return awid.IdentityModeLocal, nil
}

func runTeamHumanCreateForExistingIdentity(wd, teamName, alias, firstAgentScope string, selector *libraryProfileSelector) (*teamCreateOutput, error) {
	if selector != nil {
		return nil, usageError("aw team create --profile for an existing identity is not supported yet; use aw team add NAME@BLUEPRINT/PROFILE after creating the team")
	}
	return foundTeamWithNamespaceControllerAuthority(wd, teamName, alias, "", "", strings.TrimSpace(teamHumanCreateDisplayName), firstAgentScope)
}

func foundTeamWithNamespaceControllerAuthority(wd, teamName, alias, explicitDomain, explicitRegistryURL, displayName, firstAgentScope string) (*teamCreateOutput, error) {
	domain := awconfig.NormalizeDomain(explicitDomain)
	identity, _, identityErr := awconfig.LoadWorktreeIdentityFromDir(wd)
	if domain == "" {
		if identityErr != nil {
			if errors.Is(identityErr, os.ErrNotExist) {
				return nil, usageError("current workspace has no identity namespace; use --byot/--namespace for a domain you control, or run aw init first")
			}
			return nil, identityErr
		}
		identityDomain, _, ok := awconfig.CutIdentityAddress(identity.Address)
		if !ok {
			return nil, usageError("current identity has no namespace address; run aw init for first-team setup or use --byot/--namespace for a domain you control")
		}
		domain = identityDomain
	}
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, usageError("current identity is hosted-managed for namespace %s; creating another hosted team is not supported yet (tracked in default-aaas.3.15)", domain)
	}
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return nil, fmt.Errorf("load controller key for %s: %w", domain, err)
	}
	registryURL := strings.TrimSpace(explicitRegistryURL)
	if registryURL == "" && identityErr == nil && identity != nil {
		registryURL = strings.TrimSpace(identity.RegistryURL)
	}
	if registryURL == "" {
		registryURL, err = resolveInitAWIDRegistryURL()
		if err != nil {
			return nil, err
		}
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(registryURL) != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return nil, err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	firstAgentAddress := ""
	if firstAgentScope == awid.IdentityModeGlobal && identityErr == nil && identity != nil {
		firstAgentAddress = strings.TrimSpace(identity.Address)
	}
	plan, err := resolveTeamMemberEnrollment(ctx, teamMemberEnrollmentResolveOptions{
		WorkingDir:        wd,
		TeamDomain:        domain,
		Name:              alias,
		Address:           firstAgentAddress,
		Scope:             firstAgentScope,
		RegistryURL:       strings.TrimSpace(registry.DefaultRegistryURL),
		Registry:          registry,
		AllowLocalMint:    true,
		AllowDefaultClaim: false,
	})
	if err != nil {
		return nil, err
	}
	registration, err := ensureLocalTeamRegistered(ctx, registry, strings.TrimSpace(registry.DefaultRegistryURL), domain, strings.ToLower(strings.TrimSpace(teamName)), strings.TrimSpace(displayName), controllerKey)
	if err != nil {
		return nil, err
	}
	cert, err := awid.SignTeamCertificate(registration.TeamKey, awid.TeamCertificateFields{
		Team:          registration.TeamID,
		MemberDIDKey:  plan.MemberDIDKey,
		MemberDIDAW:   strings.TrimSpace(plan.MemberDIDAW),
		MemberAddress: strings.TrimSpace(plan.MemberAddress),
		Alias:         strings.TrimSpace(plan.Name),
		Lifetime:      strings.TrimSpace(plan.Lifetime),
	})
	if err != nil {
		return nil, err
	}
	if err := registry.RegisterCertificate(ctx, strings.TrimSpace(registry.DefaultRegistryURL), domain, strings.ToLower(strings.TrimSpace(teamName)), cert, registration.TeamKey); err != nil {
		return nil, fmt.Errorf("register certificate at registry: %w", err)
	}
	bootstrap := &localTeamBootstrapResult{TeamID: registration.TeamID, TeamDIDKey: registration.TeamDIDKey, TeamKeyPath: registration.TeamKeyPath, Certificate: cert}
	certPath, err := awconfig.SaveTeamCertificateForTeam(wd, bootstrap.TeamID, bootstrap.Certificate)
	if err != nil {
		return nil, err
	}
	accepted := &teamAcceptInviteOutput{Status: "accepted", TeamID: bootstrap.TeamID, Alias: alias, CertPath: certPath}
	awebURL, err := resolveInitAwebURL()
	if err != nil {
		return nil, err
	}
	// The creator self-enrolls as the team's first member and produces a
	// ready-to-run identity, so the worktree binding is written now.
	if err := recordAcceptedTeamMembership(wd, accepted, bootstrap.Certificate, strings.TrimSpace(registry.DefaultRegistryURL), awebURL, recordMembershipOptions{SetActive: true, WriteWorkspaceBinding: true}); err != nil {
		return nil, err
	}
	return &teamCreateOutput{Status: "created", TeamID: bootstrap.TeamID, TeamDIDKey: bootstrap.TeamDIDKey, TeamKeyPath: bootstrap.TeamKeyPath, RegistryURL: strings.TrimSpace(registry.DefaultRegistryURL)}, nil
}

func teamHumanCreateOutputFromConnect(teamName string, result connectOutput, homeDir string) teamHumanCreateOutput {
	return teamHumanCreateOutput{
		Status:       "created",
		TeamName:     strings.TrimSpace(teamName),
		ProfileMode:  "empty",
		TeamID:       strings.TrimSpace(result.TeamID),
		Alias:        strings.TrimSpace(result.Alias),
		WorkspaceID:  strings.TrimSpace(result.WorkspaceID),
		AwebURL:      strings.TrimSpace(result.AwebURL),
		HomeDir:      strings.TrimSpace(homeDir),
		NoLibrary:    true,
		NoProfile:    true,
		IdentityOnly: true,
	}
}

func formatTeamHumanCreate(v any) string {
	out := v.(teamHumanCreateOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Created empty-profile team %s", out.TeamName)
	if out.TeamID != "" {
		fmt.Fprintf(&b, " (%s)", out.TeamID)
	}
	if out.Alias != "" {
		fmt.Fprintf(&b, " as name %s", out.Alias)
	}
	b.WriteString("\n")
	if out.HomeDir != "" {
		fmt.Fprintf(&b, "Agent home: %s\n", out.HomeDir)
	}
	if out.ProfileMode == "library" {
		b.WriteString("Library profile adopted and materialized.\n")
	} else {
		b.WriteString("No Library profile was adopted; no profile home was materialized.\n")
	}
	return b.String()
}

type teamHumanAddOutput struct {
	Status        string                `json:"status"`
	AgentsRoot    string                `json:"agents_root"`
	TeamID        string                `json:"team_id,omitempty"`
	AuthorityTier string                `json:"authority_tier,omitempty"`
	HomeOverride  bool                  `json:"home_override,omitempty"`
	LayoutOnly    bool                  `json:"layout_only"`
	NoLibrary     bool                  `json:"no_library"`
	NoProfile     bool                  `json:"no_profile"`
	Agents        []teamHumanAddedAgent `json:"agents"`
}

type teamHumanAddedAgent struct {
	Name              string                  `json:"name"`
	HomeDir           string                  `json:"home_dir"`
	ProfileMode       string                  `json:"profile_mode"`
	Profile           *libraryProfileSelector `json:"-"`
	LocalBlueprintDir string                  `json:"-"`
	Scope             string                  `json:"scope,omitempty"`
	Alias             string                  `json:"alias,omitempty"`
	TeamID            string                  `json:"team_id,omitempty"`
	CertPath          string                  `json:"cert_path,omitempty"`
	Connected         bool                    `json:"-"`
}

func resolveTeamHumanAddAgentSpecs(wd string, args []string, specs []teamAgentSpec) ([]teamAgentSpec, error) {
	var client *aweb.Client
	used := map[string]bool{}
	inputSpecs := append([]teamAgentSpec(nil), specs...)
	if inputSpecs == nil {
		inputSpecs = make([]teamAgentSpec, 0, len(args))
		for _, raw := range args {
			spec, err := parseTeamAgentSpec(raw)
			if err != nil {
				return nil, err
			}
			inputSpecs = append(inputSpecs, spec)
		}
	}
	resolved := make([]teamAgentSpec, 0, len(inputSpecs))
	for _, spec := range inputSpecs {
		scope := strings.TrimSpace(spec.Scope)
		if spec.Profile != nil && teamHumanAddLayoutOnly {
			return nil, usageError("aw team add --layout-only cannot be used with profile selector %s", spec.Raw)
		}
		if spec.Profile != nil {
			parsed, err := applyMaterializeRuntimePolicy(*spec.Profile, teamHumanAddRuntime)
			if err != nil {
				return nil, err
			}
			if strings.TrimSpace(spec.LocalBlueprintDir) == "" {
				parsed, err = resolveLibraryProfileSelectorSource(parsed, teamHumanAddLibraryURL, teamHumanAddBlueprint)
				if err != nil {
					return nil, err
				}
			}
			spec.Profile = &parsed
			if scope == "" {
				if strings.TrimSpace(spec.LocalBlueprintDir) != "" {
					scope = awid.IdentityModeLocal
				} else {
					parsed, scope, err = resolveLibraryProfileScopeAndCache(parsed)
					if err != nil {
						if !isMissingLibraryPluginError(err) {
							return nil, err
						}
						scope = awid.IdentityModeLocal
					}
					spec.Profile = &parsed
				}
			}
		}
		if scope == "" {
			scope = awid.IdentityModeLocal
		}
		if teamHumanAddGlobal {
			scope = awid.IdentityModeGlobal
		} else if teamHumanAddLocal {
			scope = awid.IdentityModeLocal
		}
		if scope != awid.IdentityModeLocal && scope != awid.IdentityModeGlobal {
			return nil, usageError("scope %q is not supported; use local or global", scope)
		}
		name := strings.TrimSpace(spec.Name)
		var err error
		if name == "" {
			if client == nil {
				var err error
				client, _, err = resolveClientSelectionForDir(wd)
				if err != nil {
					return nil, err
				}
			}
			name, err = suggestTeamHumanAgentName(client, scope, used)
			if err != nil {
				return nil, err
			}
		}
		key := strings.ToLower(name)
		if used[key] {
			return nil, usageError("duplicate agent name %q", name)
		}
		used[key] = true
		spec.ResolvedName = name
		spec.Name = name
		spec.Scope = scope
		resolved = append(resolved, spec)
	}
	return resolved, nil
}

func suggestTeamHumanAgentName(client *aweb.Client, scope string, used map[string]bool) (string, error) {
	exclude := make([]string, 0, len(used))
	for name := range used {
		exclude = append(exclude, name)
	}
	sort.Strings(exclude)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	suggestion, err := client.SuggestAgentNames(ctx, awid.SuggestAgentNamesRequest{
		Scope:   scope,
		Exclude: exclude,
		Count:   1,
	})
	cancel()
	if err != nil {
		return "", fmt.Errorf("suggest next name from server: %w", err)
	}
	for _, suggested := range suggestion.Names {
		name := strings.TrimSpace(suggested.Name)
		if name == "" || !isValidWorkspaceAlias(name) {
			return "", fmt.Errorf("server returned invalid name suggestion %q", name)
		}
		if !used[strings.ToLower(name)] {
			return name, nil
		}
	}
	return "", fmt.Errorf("server returned no available names for %s agent", scope)
}

func preflightTeamHumanAddRosterAliases(wd, agentsRoot string, specs []teamAgentSpec) error {
	client, selection, err := resolveClientSelectionForDir(wd)
	if err != nil || client == nil || client.Client == nil || selection == nil {
		if err != nil {
			debugLog("resolve team roster for agent-name preflight: %v", err)
		}
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	roster, err := client.Client.ListAgents(ctx)
	cancel()
	if err != nil {
		debugLog("list team roster for agent-name preflight: %v", err)
		return nil
	}
	freshSpecs := make([]teamAgentSpec, 0, len(specs))
	for _, spec := range specs {
		homeSelection, homeErr := resolveSelectionForDir(filepath.Join(agentsRoot, strings.TrimSpace(spec.Name)))
		if homeErr == nil && strings.EqualFold(strings.TrimSpace(homeSelection.TeamID), strings.TrimSpace(selection.TeamID)) && strings.EqualFold(strings.TrimSpace(homeSelection.Alias), strings.TrimSpace(spec.Name)) {
			continue
		}
		freshSpecs = append(freshSpecs, spec)
	}
	return teamHumanAddRosterCollisionError(roster.Agents, freshSpecs)
}

func teamHumanAddRosterCollisionError(agents []awid.AgentView, specs []teamAgentSpec) error {
	existing := make(map[string]struct{}, len(agents))
	for _, agent := range agents {
		if alias := strings.TrimSpace(agent.Alias); alias != "" {
			existing[strings.ToLower(alias)] = struct{}{}
		}
	}
	for _, spec := range specs {
		name := strings.TrimSpace(spec.Name)
		if _, found := existing[strings.ToLower(name)]; found {
			return usageError("agent name %q already appears in the current team roster; choose a different name and retry", name)
		}
	}
	return nil
}

func shouldUseAPIKeyBootstrapForTeamAdd(wd string) (bool, error) {
	if strings.TrimSpace(resolveInitAPIKey()) == "" {
		return false, nil
	}
	if _, _, _, _, err := resolveTeamInviteTarget(wd); err == nil {
		return false, nil
	} else if errors.Is(err, errTeamInviteTargetHasNoActiveTeam) {
		return true, nil
	} else {
		return false, err
	}
}

func bootstrapTeamHumanAddAgentWithAPIKey(homeDir string, plan teamHumanAddedAgent, apiKey string) (*acceptedTeamInvite, error) {
	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		apiKey = resolveInitAPIKey()
	}
	if strings.TrimSpace(apiKey) == "" {
		return nil, usageError("%s is required for API-key team add bootstrap", initAPIKeyEnvVar)
	}
	awebURL, err := resolveAPIKeyInitAwebURL()
	if err != nil {
		return nil, err
	}
	registryURL, err := resolveInitAWIDRegistryURL()
	if err != nil {
		return nil, err
	}
	global := strings.TrimSpace(plan.Scope) == awid.IdentityModeGlobal
	request := apiKeyInitRequest{
		WorkingDir:  homeDir,
		AwebURL:     awebURL,
		RegistryURL: registryURL,
		APIKey:      apiKey,
		Role:        teamHumanAddRoleForPlan(plan),
		Persistent:  global,
	}
	if global {
		request.Name = strings.TrimSpace(plan.Name)
	} else {
		request.Alias = strings.TrimSpace(plan.Name)
	}
	out, err := runAPIKeyBootstrapInit(request)
	if err != nil {
		return nil, err
	}
	certPath := awconfig.TeamCertificatePath(homeDir, strings.TrimSpace(out.TeamID))
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return nil, fmt.Errorf("load API-key team add certificate: %w", err)
	}
	domain, teamName, _ := awid.ParseTeamID(strings.TrimSpace(out.TeamID))
	acceptedAwebURL := strings.TrimSpace(out.AwebURL)
	if acceptedAwebURL == "" {
		acceptedAwebURL = strings.TrimSpace(awebURL)
	}
	return &acceptedTeamInvite{
		Output: &teamAcceptInviteOutput{
			Status:   "accepted",
			TeamID:   strings.TrimSpace(out.TeamID),
			Alias:    strings.TrimSpace(out.Alias),
			CertPath: filepath.ToSlash(certPath),
		},
		Certificate: cert,
		RegistryURL: strings.TrimSpace(registryURL),
		AwebURL:     acceptedAwebURL,
		Domain:      domain,
		TeamName:    teamName,
	}, nil
}

func teamHumanAddRoleForPlan(plan teamHumanAddedAgent) string {
	if plan.Profile == nil {
		return ""
	}
	return strings.TrimSpace(plan.Profile.ProfileRef)
}

func resolveOrCreateTeamMemberIdentity(inviteAnchorDir string, plan teamHumanAddedAgent, apiKeyBootstrapMode bool, apiKey string) (*acceptedTeamInvite, error) {
	if apiKeyBootstrapMode {
		return bootstrapTeamHumanAddAgentWithAPIKey(plan.HomeDir, plan, apiKey)
	}
	globalAgent := strings.TrimSpace(plan.Scope) == awid.IdentityModeGlobal
	return createAndAcceptTeamInviteForEmptyAgent(inviteAnchorDir, plan.HomeDir, plan.Name, globalAgent)
}

type teamHumanAddRunOptions struct {
	CWD                 string
	InviteAnchorDir     string
	AgentsRoot          string
	WorktreeAnchorDir   string
	APIKey              string
	ForceAPIKey         bool
	ExpectedTeamID      string
	OutputStatus        string
	OutputAuthorityTier string
	Specs               []teamAgentSpec
}

func runTeamHumanAdd(cmd *cobra.Command, args []string) error {
	return runTeamHumanAddWithOptions(cmd, args, teamHumanAddRunOptions{})
}

func runTeamHumanAddWithOptions(cmd *cobra.Command, args []string, opts teamHumanAddRunOptions) error {
	if teamHumanAddLocal && teamHumanAddGlobal {
		return usageError("--local and --global cannot be used together")
	}
	if teamHumanAddStart && teamHumanAddLayoutOnly {
		return usageError("aw team add --start cannot be used with --layout-only")
	}
	wd := strings.TrimSpace(opts.CWD)
	var err error
	if wd == "" {
		wd, err = os.Getwd()
		if err != nil {
			return err
		}
	}
	inviteAnchorDir := strings.TrimSpace(opts.InviteAnchorDir)
	if inviteAnchorDir == "" {
		inviteAnchorDir = wd
	}
	worktreeAnchorDir := strings.TrimSpace(opts.WorktreeAnchorDir)
	if worktreeAnchorDir == "" {
		worktreeAnchorDir = wd
	}
	homeOverride := strings.TrimSpace(teamHumanAddHome)
	if homeOverride != "" && len(args) != 1 {
		return usageError("aw team add --home can only be used with a single agent")
	}
	var explicitHome string
	if homeOverride != "" {
		explicitHome, err = filepath.Abs(homeOverride)
		if err != nil {
			return err
		}
	}
	repoRoot := resolveRepoRoot(wd)
	agentsRoot := strings.TrimSpace(opts.AgentsRoot)
	if agentsRoot == "" {
		agentsRoot = filepath.Join(repoRoot, "agents", "instances")
	} else {
		repoRoot = filepath.Dir(filepath.Dir(agentsRoot))
	}
	resolvedSpecs, err := resolveTeamHumanAddAgentSpecs(wd, args, opts.Specs)
	if err != nil {
		return err
	}
	if err := preflightTeamHumanAddRosterAliases(wd, agentsRoot, resolvedSpecs); err != nil {
		return err
	}
	apiKeyBootstrapMode := opts.ForceAPIKey
	if !apiKeyBootstrapMode {
		apiKeyBootstrapMode, err = shouldUseAPIKeyBootstrapForTeamAdd(inviteAnchorDir)
		if err != nil {
			return err
		}
	}
	plans := make([]teamHumanAddedAgent, 0, len(resolvedSpecs))
	for _, spec := range resolvedSpecs {
		if spec.Profile != nil && teamHumanAddLayoutOnly {
			return usageError("aw team add --layout-only cannot be used with profile selector %s", spec.Raw)
		}
		profileMode := "empty"
		if spec.Profile != nil {
			profileMode = "library"
		}
		homeDir := filepath.Join(agentsRoot, spec.Name)
		if explicitHome != "" {
			homeDir = explicitHome
		}
		plans = append(plans, teamHumanAddedAgent{Name: spec.Name, HomeDir: homeDir, ProfileMode: profileMode, Profile: spec.Profile, Scope: spec.Scope, LocalBlueprintDir: spec.LocalBlueprintDir})
	}
	if teamHumanAddStart && len(plans) != 1 {
		return usageError("aw team add --start requires exactly one agent")
	}
	for _, plan := range plans {
		if plan.Profile != nil {
			if err := preflightProfileAgentHome(plan.HomeDir); err != nil {
				return err
			}
			continue
		}
		if err := preflightEmptyAgentHome(plan.HomeDir); err != nil {
			return err
		}
	}
	createdTeamID := ""
	for i := range plans {
		var rollback *agentHomeRollback
		if plans[i].Profile != nil || strings.TrimSpace(opts.ExpectedTeamID) != "" {
			var err error
			rollback, err = captureAgentHomeRollback(plans[i].HomeDir)
			if err != nil {
				return err
			}
		}
		if err := os.MkdirAll(plans[i].HomeDir, 0o755); err != nil {
			return err
		}
		if teamHumanAddLayoutOnly {
			continue
		}
		createdProfileIdentity := false
		var acceptedProfileIdentity *acceptedTeamInvite
		if plans[i].Profile != nil {
			if sel, err := resolveSelectionForDir(plans[i].HomeDir); err == nil && strings.TrimSpace(sel.TeamID) != "" {
				plans[i].Alias = strings.TrimSpace(sel.Alias)
				plans[i].TeamID = strings.TrimSpace(sel.TeamID)
			} else {
				accepted, err := resolveOrCreateTeamMemberIdentity(inviteAnchorDir, plans[i], apiKeyBootstrapMode, opts.APIKey)
				if err != nil {
					if rollback != nil {
						_ = rollback.Rollback()
					}
					return err
				}
				createdProfileIdentity = true
				acceptedProfileIdentity = accepted
				plans[i].Alias = accepted.Output.Alias
				plans[i].TeamID = accepted.Output.TeamID
				plans[i].CertPath = accepted.Output.CertPath
				plans[i].Connected = apiKeyBootstrapMode
			}
		} else {
			accepted, err := resolveOrCreateTeamMemberIdentity(inviteAnchorDir, plans[i], apiKeyBootstrapMode, opts.APIKey)
			if err != nil {
				if rollback != nil {
					_ = rollback.Rollback()
				}
				return err
			}
			createdProfileIdentity = true
			acceptedProfileIdentity = accepted
			plans[i].Alias = accepted.Output.Alias
			plans[i].TeamID = accepted.Output.TeamID
			plans[i].CertPath = accepted.Output.CertPath
			plans[i].Connected = apiKeyBootstrapMode
		}
		rollbackOnErr := func(err error) error {
			return err
		}
		if plans[i].Profile != nil {
			rollbackOnErr = func(err error) error {
				if !createdProfileIdentity {
					return err
				}
				memberRollbackErr := rollbackJustCreatedTeamMember(inviteAnchorDir, acceptedProfileIdentity)
				var homeRollbackErr error
				if rollback != nil {
					homeRollbackErr = rollback.Rollback()
				}
				return addPostJoinRollbackError(err, acceptedProfileIdentity, memberRollbackErr, homeRollbackErr)
			}
			// Materialize the profile home, connect the member to the aweb service,
			// then run the coordination configure step. Connect sits between the two:
			// the configure step injects the team's active instructions, which the
			// aweb server serves only to a connected agent, and self-hosted create/add
			// install the awid certificate but not the aweb connection. Connecting only
			// after materialize succeeds avoids an orphaned aweb connection on a
			// materialize failure. (default-aabq.21)
			if strings.TrimSpace(plans[i].LocalBlueprintDir) != "" {
				if _, _, err := applyLocalBlueprintProfileToHome(plans[i].HomeDir, *plans[i].Profile, plans[i].LocalBlueprintDir, true); err != nil {
					return rollbackOnErr(err)
				}
			} else if _, _, err := applyPublicLibraryProfileToHome(plans[i].HomeDir, *plans[i].Profile, true); err != nil {
				return rollbackOnErr(err)
			}
			if !plans[i].Connected {
				if sel, selErr := resolveSelectionForDir(plans[i].HomeDir); selErr == nil && strings.TrimSpace(sel.AwebURL) != "" {
					if _, err := initCertificateConnectWithOptions(plans[i].HomeDir, strings.TrimSpace(sel.AwebURL), certificateConnectOptions{
						Role: strings.TrimSpace(plans[i].Profile.ProfileRef),
					}); err != nil {
						return rollbackOnErr(fmt.Errorf("connect agent to aweb service: %w", err))
					}
				}
			}
			if err := configureMaterializedAgentHome(plans[i].HomeDir); err != nil {
				return rollbackOnErr(err)
			}
		}
		if createdTeamID == "" {
			createdTeamID = strings.TrimSpace(plans[i].TeamID)
		}
		if expected := strings.TrimSpace(opts.ExpectedTeamID); expected != "" && !strings.EqualFold(strings.TrimSpace(plans[i].TeamID), expected) {
			mismatchErr := usageError("--team-id %s does not match API key team %s", expected, strings.TrimSpace(plans[i].TeamID))
			memberRollbackErr := rollbackJustCreatedTeamMemberWithExplicitHostedAuth(plans[i].HomeDir, acceptedProfileIdentity, opts.APIKey)
			var homeRollbackErr error
			if rollback != nil {
				homeRollbackErr = rollback.Rollback()
			}
			return addPostJoinRollbackError(mismatchErr, acceptedProfileIdentity, memberRollbackErr, homeRollbackErr)
		}
		if err := setupTeamAddedAgentWorktree(worktreeAnchorDir, plans[i], teamHumanAddWorkDir); err != nil {
			return rollbackOnErr(err)
		}
	}
	noLibrary := true
	noProfile := true
	for _, plan := range plans {
		if plan.Profile != nil {
			noLibrary = false
			noProfile = false
			break
		}
	}
	if teamHumanAddStart && len(plans) == 1 {
		session := strings.TrimSpace(teamHumanAddSession)
		if session == "" {
			session = defaultTeamUpSessionName(repoRoot)
		}
		attach := teamHumanAddAttach && !teamHumanAddNoAttach
		if err := startTeamAddedAgent(cmd, plans[0], session, attach); err != nil {
			return err
		}
	}
	status := strings.TrimSpace(opts.OutputStatus)
	if status == "" {
		status = "added"
	}
	outputTeamID := createdTeamID
	if outputTeamID == "" && len(plans) > 0 {
		outputTeamID = strings.TrimSpace(plans[0].TeamID)
	}
	printOutput(teamHumanAddOutput{Status: status, AgentsRoot: agentsRoot, TeamID: outputTeamID, AuthorityTier: strings.TrimSpace(opts.OutputAuthorityTier), HomeOverride: explicitHome != "", LayoutOnly: teamHumanAddLayoutOnly, NoLibrary: noLibrary, NoProfile: noProfile, Agents: plans}, formatTeamHumanAdd)
	return nil
}

func startTeamAddedAgent(cmd *cobra.Command, plan teamHumanAddedAgent, session string, attach bool) error {
	runtimeKind, err := readTeamUpRuntimeKind(plan.HomeDir)
	if err != nil {
		return fmt.Errorf("%s: %w", plan.Name, err)
	}
	command, err := teamUpCommandForRuntime(runtimeKind)
	if err != nil {
		return fmt.Errorf("%s: %w", plan.Name, err)
	}
	agent := teamUpAgentPlan{Name: plan.Name, HomeDir: plan.HomeDir, RuntimeKind: runtimeKind, Command: command, Action: teamUpActionStart}
	proc, running, err := teamAddedAgentRunningProcess(plan.HomeDir)
	if err != nil {
		return err
	}
	if running {
		agent.Action = teamUpActionSkip
		agent.Reason = "process already has agent home as cwd"
		agent.RunningPID = proc.PID
		agent.RunningCmd = proc.Command
	}
	launchPlan := teamUpPlan{Session: teamUpTmuxName(firstNonEmptyLibraryValue(session, "aw-team")), Agents: []teamUpAgentPlan{agent}}
	if agent.Action == teamUpActionStart {
		if err := preflightTeamUpCommands(launchPlan); err != nil {
			return err
		}
	}
	started, err := executeTeamUpPlan(cmd, launchPlan, false, false, false)
	if err != nil {
		return err
	}
	if err := confirmStartedClaudeChannelPrompts(launchPlan.Session, started); err != nil {
		return err
	}
	if attach && teamUpSessionExists(launchPlan.Session) {
		return attachTeamUpSession(cmd, launchPlan.Session)
	}
	return nil
}

func teamAddedAgentRunningProcess(homeDir string) (teamUpRunningProcess, bool, error) {
	active, err := teamUpDetectActiveHomes(filepath.Dir(homeDir))
	if err != nil {
		return teamUpRunningProcess{}, false, err
	}
	proc, ok := active[canonicalTeamUpPath(homeDir)]
	return proc, ok, nil
}

func setupTeamAddedAgentWorktree(anchorDir string, plan teamHumanAddedAgent, workDir string) error {
	if strings.TrimSpace(plan.HomeDir) == "" {
		return nil
	}
	homeRepoRoot, homeInRepo, err := teamAddGitRepoRootForHome(anchorDir, plan.HomeDir)
	if err != nil {
		return err
	}
	workRepoRoot := ""
	if strings.TrimSpace(workDir) != "" {
		workRepoRoot, err = teamAddGitRepoRootForWorkDir(anchorDir, workDir)
		if err != nil {
			return err
		}
	} else if homeInRepo {
		workRepoRoot = homeRepoRoot
	} else {
		return nil
	}
	if homeInRepo {
		if err := ensureTeamAddHomeGitignored(homeRepoRoot, plan.HomeDir); err != nil {
			return err
		}
	}
	worktreeDir := filepath.Join(plan.HomeDir, "worktree")
	if err := ensureTeamAddGitWorktree(workRepoRoot, worktreeDir, plan.Name); err != nil {
		return err
	}
	worksOnMain, err := teamAddedAgentWorksOnMain(plan)
	if err != nil {
		return err
	}
	if worksOnMain {
		if err := ensureTeamAddWorkMainLink(plan.HomeDir, workRepoRoot); err != nil {
			return err
		}
	}
	return nil
}

func teamAddGitRepoRootForHome(anchorDir, homeDir string) (string, bool, error) {
	probeDir := anchorDir
	if parent := filepath.Dir(homeDir); strings.TrimSpace(parent) != "" {
		probeDir = parent
	}
	repoRoot, err := currentGitWorktreeRootFromDir(probeDir)
	if err != nil {
		return "", false, nil
	}
	canonicalRepoRoot := canonicalTeamUpPath(repoRoot)
	canonicalHome := canonicalTeamUpPath(homeDir)
	rel, err := filepath.Rel(canonicalRepoRoot, canonicalHome)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") || filepath.IsAbs(rel) {
		return "", false, nil
	}
	return canonicalRepoRoot, true, nil
}

func teamAddGitRepoRootForWorkDir(anchorDir, workDir string) (string, error) {
	resolved := strings.TrimSpace(workDir)
	if resolved == "" {
		return "", fmt.Errorf("--work-dir is required")
	}
	if !filepath.IsAbs(resolved) {
		resolved = filepath.Join(anchorDir, resolved)
	}
	repoRoot, err := currentGitWorktreeRootFromDir(resolved)
	if err != nil {
		return "", fmt.Errorf("--work-dir %s is not inside a git repo: %w", workDir, err)
	}
	return canonicalTeamUpPath(repoRoot), nil
}

func ensureTeamAddHomeGitignored(repoRoot, homeDir string) error {
	rel, err := filepath.Rel(canonicalTeamUpPath(repoRoot), canonicalTeamUpPath(homeDir))
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(filepath.Clean(rel))
	if rel == "." || strings.HasPrefix(rel, "../") {
		return nil
	}
	gitignore := filepath.Join(repoRoot, ".gitignore")
	pattern := "/" + strings.TrimPrefix(rel, "/") + "/"
	content, err := os.ReadFile(gitignore)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, line := range strings.Split(string(content), "\n") {
		if strings.TrimSpace(line) == pattern {
			return nil
		}
	}
	prefix := ""
	if len(content) > 0 && !strings.HasSuffix(string(content), "\n") {
		prefix = "\n"
	}
	return os.WriteFile(gitignore, append(content, []byte(prefix+pattern+"\n")...), 0o644)
}

func ensureTeamAddGitWorktree(repoRoot, worktreeDir, branch string) error {
	if info, err := os.Stat(worktreeDir); err == nil && info.IsDir() {
		if _, gitErr := os.Stat(filepath.Join(worktreeDir, ".git")); gitErr == nil {
			return nil
		}
		return fmt.Errorf("%s exists but is not a git worktree", worktreeDir)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(worktreeDir), 0o755); err != nil {
		return err
	}
	branch = strings.TrimSpace(branch)
	if branch == "" {
		return fmt.Errorf("agent branch name is required")
	}
	if exec.Command("git", "-C", repoRoot, "rev-parse", "--verify", "--quiet", "refs/heads/"+branch).Run() == nil {
		cmd := exec.Command("git", "-C", repoRoot, "worktree", "add", worktreeDir, branch)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("git worktree add %s %s: %w%s", worktreeDir, branch, err, formatCommandOutput(out))
		}
		return nil
	}
	cmd := exec.Command("git", "-C", repoRoot, "worktree", "add", worktreeDir, "-b", branch)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("git worktree add %s -b %s: %w%s", worktreeDir, branch, err, formatCommandOutput(out))
	}
	return nil
}

func teamAddedAgentWorksOnMain(plan teamHumanAddedAgent) (bool, error) {
	profilePath := filepath.Join(plan.HomeDir, ".aw", "profile", "profile.yaml")
	data, err := os.ReadFile(profilePath)
	if err == nil {
		var raw struct {
			WorksOnMain *bool `yaml:"works_on_main" json:"works_on_main"`
		}
		if err := yaml.Unmarshal(data, &raw); err != nil {
			return false, fmt.Errorf("parse %s: %w", profilePath, err)
		}
		if raw.WorksOnMain != nil {
			return *raw.WorksOnMain, nil
		}
	} else if err != nil && !os.IsNotExist(err) {
		return false, err
	}
	return teamAgentLikelyWorksOnMain(plan), nil
}

func teamAgentLikelyWorksOnMain(plan teamHumanAddedAgent) bool {
	labels := []string{plan.Name}
	if plan.Profile != nil {
		labels = append(labels, plan.Profile.ProfileRef)
	}
	for _, label := range labels {
		lower := strings.ToLower(strings.TrimSpace(label))
		for _, token := range []string{"coordinator", "reviewer", "proofreader", "deployer", "reliability", "maintainer"} {
			if strings.Contains(lower, token) {
				return true
			}
		}
	}
	return false
}

func ensureTeamAddWorkMainLink(homeDir, repoRoot string) error {
	link := filepath.Join(homeDir, "work-main")
	if info, err := os.Lstat(link); err == nil {
		if info.Mode()&os.ModeSymlink == 0 {
			return fmt.Errorf("%s exists and is not a symlink", link)
		}
		if err := os.Remove(link); err != nil {
			return err
		}
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(repoRoot, link)
}

type justCreatedTeamMemberRollbackTarget struct {
	TeamID        string
	Domain        string
	TeamName      string
	RegistryURL   string
	AwebURL       string
	CertificateID string
	MemberAddress string
}

func rollbackJustCreatedTeamMember(anchorDir string, accepted *acceptedTeamInvite) error {
	return rollbackJustCreatedTeamMemberWithExplicitHostedAuth(anchorDir, accepted, "")
}

func rollbackJustCreatedTeamMemberWithExplicitHostedAuth(anchorDir string, accepted *acceptedTeamInvite, explicitAPIKey string) error {
	target, err := justCreatedTeamMemberRollbackTargetFromAccepted(accepted)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), awid.APITimeout())
	defer cancel()
	if isAwebHostedNamespace(target.Domain) || strings.TrimSpace(explicitAPIKey) != "" {
		awebURL, apiKey, authErr := resolveHostedTeamRemoveAuthWithAwebURL(anchorDir, target.TeamID, target.AwebURL, explicitAPIKey)
		if authErr != nil {
			return authErr
		}
		_, err = postHostedTeamRemoveMember(ctx, awebURL, apiKey, target.TeamID, hostedTeamRemoveMemberRequest{CertificateID: target.CertificateID})
		if err != nil {
			return err
		}
		return nil
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	registryURL := strings.TrimSpace(target.RegistryURL)
	if registryURL != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return fmt.Errorf("invalid registry url %q: %w", registryURL, err)
		}
	} else {
		registryURL = strings.TrimSpace(registry.DefaultRegistryURL)
	}
	teamKey, err := awconfig.LoadTeamKey(target.Domain, target.TeamName)
	if err != nil {
		return fmt.Errorf("load team key for %s/%s: %w", target.Domain, target.TeamName, err)
	}
	if err := registry.RevokeCertificate(ctx, registryURL, target.Domain, target.TeamName, target.CertificateID, teamKey); err != nil {
		return fmt.Errorf("revoke certificate %s: %w", target.CertificateID, err)
	}
	return nil
}

func justCreatedTeamMemberRollbackTargetFromAccepted(accepted *acceptedTeamInvite) (justCreatedTeamMemberRollbackTarget, error) {
	if accepted == nil || accepted.Certificate == nil {
		return justCreatedTeamMemberRollbackTarget{}, fmt.Errorf("cannot roll back server-side team member: accepted certificate is missing")
	}
	target := justCreatedTeamMemberRollbackTarget{
		CertificateID: strings.TrimSpace(accepted.Certificate.CertificateID),
		MemberAddress: strings.TrimSpace(accepted.Certificate.MemberAddress),
		RegistryURL:   strings.TrimSpace(accepted.RegistryURL),
		AwebURL:       strings.TrimSpace(accepted.AwebURL),
	}
	if accepted.Output != nil {
		target.TeamID = strings.TrimSpace(accepted.Output.TeamID)
	}
	if target.TeamID == "" {
		target.TeamID = strings.TrimSpace(accepted.Certificate.Team)
	}
	target.Domain = awconfig.NormalizeDomain(accepted.Domain)
	target.TeamName = strings.TrimSpace(accepted.TeamName)
	if target.Domain == "" || target.TeamName == "" {
		if domain, teamName, err := awid.ParseTeamID(target.TeamID); err == nil {
			if target.Domain == "" {
				target.Domain = domain
			}
			if target.TeamName == "" {
				target.TeamName = teamName
			}
		}
	}
	if target.TeamID == "" && target.Domain != "" && target.TeamName != "" {
		target.TeamID = awid.BuildTeamID(target.Domain, target.TeamName)
	}
	if target.TeamID == "" {
		return justCreatedTeamMemberRollbackTarget{}, fmt.Errorf("cannot roll back server-side team member: team id is missing")
	}
	if target.Domain == "" || target.TeamName == "" {
		return justCreatedTeamMemberRollbackTarget{}, fmt.Errorf("cannot roll back server-side team member for %s: team domain/name is missing", target.TeamID)
	}
	if target.CertificateID == "" {
		return justCreatedTeamMemberRollbackTarget{}, fmt.Errorf("cannot roll back server-side team member for %s: certificate_id is missing", target.TeamID)
	}
	return target, nil
}

func addPostJoinRollbackError(cause error, accepted *acceptedTeamInvite, memberRollbackErr, homeRollbackErr error) error {
	if memberRollbackErr == nil && homeRollbackErr == nil {
		return cause
	}
	target, targetErr := justCreatedTeamMemberRollbackTargetFromAccepted(accepted)
	var b strings.Builder
	if memberRollbackErr != nil {
		b.WriteString("server-side member rollback failed")
		if targetErr == nil {
			fmt.Fprintf(&b, " for team_id %s certificate_id %s", target.TeamID, target.CertificateID)
			if target.MemberAddress != "" {
				fmt.Fprintf(&b, " member_address %s", target.MemberAddress)
			}
		}
		fmt.Fprintf(&b, ": %v", memberRollbackErr)
		if targetErr == nil {
			fmt.Fprintf(&b, "; dirty server-side member may remain; clean it from an owner/admin workspace with `aw id team remove-member --team %s --namespace %s --cert-id %s`", target.TeamName, target.Domain, target.CertificateID)
			if target.MemberAddress != "" {
				fmt.Fprintf(&b, " or `aw team remove-agent %s --team-id %s`", target.MemberAddress, target.TeamID)
			}
		} else {
			fmt.Fprintf(&b, "; rollback target details unavailable: %v", targetErr)
		}
	}
	if homeRollbackErr != nil {
		if b.Len() > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "local home rollback failed: %v", homeRollbackErr)
	}
	return fmt.Errorf("%w; %s", cause, b.String())
}

func parseTeamHumanAddSpec(raw string) (name, profileRef string, err error) {
	name = strings.TrimSpace(raw)
	if before, after, ok := strings.Cut(name, "@"); ok {
		name = strings.TrimSpace(before)
		profileRef = strings.TrimSpace(after)
		if profileRef == "" {
			return "", "", usageError("profile ref is required after @")
		}
	}
	if name == "" {
		return "", "", usageError("agent name is required")
	}
	if !isValidWorkspaceAlias(name) {
		return "", "", usageError("invalid agent name %q: must start with an alphanumeric and contain only alphanumerics, dashes, or underscores (max 64 chars)", name)
	}
	return name, profileRef, nil
}

type agentHomeRollback struct {
	home    string
	existed bool
	entries map[string]bool
}

func captureAgentHomeRollback(homeDir string) (*agentHomeRollback, error) {
	home := filepath.Clean(homeDir)
	info, err := os.Lstat(home)
	if os.IsNotExist(err) {
		return &agentHomeRollback{home: home, existed: false}, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return &agentHomeRollback{home: home, existed: true, entries: map[string]bool{".": true}}, nil
	}
	entries := map[string]bool{}
	if err := filepath.WalkDir(home, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(home, path)
		if err != nil {
			return err
		}
		entries[filepath.ToSlash(rel)] = true
		return nil
	}); err != nil {
		return nil, err
	}
	return &agentHomeRollback{home: home, existed: true, entries: entries}, nil
}

func (r *agentHomeRollback) Rollback() error {
	if r == nil || strings.TrimSpace(r.home) == "" {
		return nil
	}
	if !r.existed {
		return os.RemoveAll(r.home)
	}
	var created []string
	if err := filepath.WalkDir(r.home, func(path string, d os.DirEntry, err error) error {
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(r.home, path)
		if err != nil {
			return err
		}
		key := filepath.ToSlash(rel)
		if key != "." && !r.entries[key] {
			created = append(created, path)
		}
		return nil
	}); err != nil && !os.IsNotExist(err) {
		return err
	}
	sort.Slice(created, func(i, j int) bool { return len(created[i]) > len(created[j]) })
	for _, path := range created {
		if err := os.RemoveAll(path); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func preflightEmptyAgentHome(homeDir string) error {
	if err := pathpreflight.PreflightDir(homeDir, "agent home", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return err
	}
	if _, err := os.Lstat(filepath.Join(homeDir, ".aw")); err == nil {
		return usageError("agent home %s already has identity state", homeDir)
	} else if err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func preflightProfileAgentHome(homeDir string) error {
	return pathpreflight.PreflightDir(homeDir, "agent home", pathpreflight.AllowTempAmbientSymlinkPrefix())
}

func createAndAcceptTeamInviteForEmptyAgent(anchorDir, homeDir, alias string, global bool) (*acceptedTeamInvite, error) {
	team, domain, registryURL, awebURL, err := resolveTeamInviteTarget(anchorDir)
	if err != nil {
		// resolveTeamInviteTarget is shared with `aw id team invite`, whose error
		// mentions --team/--namespace. Those are not flags on `aw team add`: this
		// command mints against this workspace's active team.
		if errors.Is(err, errTeamInviteTargetHasNoActiveTeam) {
			return nil, usageError("aw team add mints against this workspace's active team, but none was found here; run `aw team create <name>` (or `aw init` with your team's AWEB_URL and AWEB_API_KEY) in this directory first, then re-run `aw team add`")
		}
		return nil, err
	}
	memberAddress := ""
	if global {
		identityExists, err := teamCreateHasIdentityMaterial(homeDir)
		if err != nil {
			return nil, err
		}
		if !identityExists {
			if err := bootstrapTeamCreateGlobalIdentity(homeDir, alias, domain, registryURL); err != nil {
				return nil, err
			}
		}
		if identity, _, err := awconfig.LoadWorktreeIdentityFromDir(homeDir); err == nil && identity != nil {
			memberAddress = strings.TrimSpace(identity.Address)
		}
	}
	localInvite := !global
	hasTeamKey, err := awconfig.TeamKeyExists(domain, team)
	if err != nil {
		return nil, err
	}
	var token string
	if hasTeamKey {
		_, token, err = createTeamInviteToken(domain, team, registryURL, awebURL, localInvite)
	} else if strings.TrimSpace(awebURL) != "" {
		_, token, err = createHostedTeamInviteToken(anchorDir, awid.BuildTeamID(domain, team), localInvite)
	} else {
		_, token, err = createTeamInviteToken(domain, team, registryURL, awebURL, localInvite)
	}
	if err != nil {
		return nil, err
	}
	accepted, err := acceptTeamInviteWithDetails(homeDir, token, teamAcceptInviteOptions{Name: alias, Scope: teamAcceptScopeFromGlobal(global), Address: memberAddress})
	if err != nil {
		return nil, err
	}
	// Agent provisioning writes the worktree binding immediately: the produced
	// agent is ready to run with no separate `aw init`.
	if err := recordAcceptedTeamMembership(homeDir, accepted.Output, accepted.Certificate, accepted.RegistryURL, accepted.AwebURL, recordMembershipOptions{SetActive: true, WriteWorkspaceBinding: true}); err != nil {
		return nil, err
	}
	return accepted, nil
}

func ensureAcceptedTeamWorkspaceBinding(homeDir string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, awebURL string) error {
	if output == nil || cert == nil {
		return fmt.Errorf("accepted team membership is required")
	}
	workspacePath := filepath.Join(homeDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if workspace == nil {
		workspace = &awconfig.WorktreeWorkspace{}
	}
	workspace.AwebURL = strings.TrimSpace(awebURL)
	workspace.WorkspacePath = homeDir
	workspace.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	upsertWorkspaceMembershipCache(workspace, awconfig.WorktreeMembership{
		TeamID:   strings.TrimSpace(output.TeamID),
		Alias:    strings.TrimSpace(output.Alias),
		CertPath: filepath.ToSlash(strings.TrimSpace(output.CertPath)),
		JoinedAt: strings.TrimSpace(cert.IssuedAt),
	})
	return awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace)
}

func formatTeamHumanAdd(v any) string {
	out := v.(teamHumanAddOutput)
	verb := "Added"
	if strings.TrimSpace(out.Status) == "extended" {
		verb = "Extended with"
	}
	var b strings.Builder
	profileCount := teamHumanProfileAgentCount(out.Agents)
	if profileCount == len(out.Agents) && profileCount > 0 {
		agentWord := "agent"
		if len(out.Agents) != 1 {
			agentWord = "agents"
		}
		profileText := "blueprint profiles"
		if profileCount == 1 {
			profileText = "blueprint profile " + teamHumanProfileLabel(out.Agents[0].Profile)
		}
		if out.HomeOverride {
			fmt.Fprintf(&b, "%s %d %s from %s with explicit home\n", verb, len(out.Agents), agentWord, profileText)
		} else {
			fmt.Fprintf(&b, "%s %d %s from %s under %s\n", verb, len(out.Agents), agentWord, profileText, out.AgentsRoot)
		}
	} else if profileCount > 0 {
		emptyCount := len(out.Agents) - profileCount
		if out.HomeOverride {
			fmt.Fprintf(&b, "%s %d agent(s) with explicit home (%d from blueprint profiles, %d empty-profile)\n", verb, len(out.Agents), profileCount, emptyCount)
		} else {
			fmt.Fprintf(&b, "%s %d agent(s) under %s (%d from blueprint profiles, %d empty-profile)\n", verb, len(out.Agents), out.AgentsRoot, profileCount, emptyCount)
		}
	} else if out.HomeOverride {
		fmt.Fprintf(&b, "%s %d empty-profile agent(s) with explicit home\n", verb, len(out.Agents))
	} else {
		fmt.Fprintf(&b, "%s %d empty-profile agent(s) under %s\n", verb, len(out.Agents), out.AgentsRoot)
	}
	for _, agent := range out.Agents {
		fmt.Fprintf(&b, "- %s: %s\n", agent.Name, agent.HomeDir)
	}
	if out.NoLibrary {
		b.WriteString("No Library profile was adopted; no profile home was materialized.\n")
	} else {
		b.WriteString("Library profile(s) adopted and materialized.\n")
	}
	return b.String()
}

func teamHumanProfileAgentCount(agents []teamHumanAddedAgent) int {
	count := 0
	for _, agent := range agents {
		if agent.Profile != nil || agent.ProfileMode == "library" {
			count++
		}
	}
	return count
}

func teamHumanProfileLabel(selector *libraryProfileSelector) string {
	if selector == nil {
		return "unknown"
	}
	label := strings.TrimSpace(selector.SourceBlueprintRef) + "/" + strings.TrimSpace(selector.ProfileRef)
	if strings.TrimSpace(selector.SourceBlueprintVersion) != "" {
		label += "@" + strings.TrimSpace(selector.SourceBlueprintVersion)
	}
	return label
}

func runTeamHumanRemoveAgent(cmd *cobra.Command, args []string) error {
	teamID := strings.TrimSpace(teamHumanRemoveTeamID)
	if teamID == "" {
		var err error
		teamID, err = activeTeamIDForHumanTeamCommand()
		if err != nil {
			return err
		}
	}
	domain, name, err := awid.ParseTeamID(teamID)
	if err != nil {
		return err
	}
	teamRemoveTeam = name
	teamRemoveNamespace = domain
	teamRemoveMember = strings.TrimSpace(args[0])
	teamRemoveCertID = ""
	teamRemoveRegistryURL = teamHumanRemoveRegistryURL
	teamRemoveAwebURL = teamHumanRemoveAwebURL
	teamRemoveAPIKey = teamHumanRemoveAPIKey
	return runTeamRemoveMember(cmd, nil)
}

func activeTeamIDForHumanTeamCommand() (string, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	if teamState, err := awconfig.LoadTeamState(workingDir); err == nil && teamState != nil && strings.TrimSpace(teamState.ActiveTeam) != "" {
		return strings.TrimSpace(teamState.ActiveTeam), nil
	}
	if sel, err := resolveSelectionForDir(workingDir); err == nil && strings.TrimSpace(sel.TeamID) != "" {
		return strings.TrimSpace(sel.TeamID), nil
	}
	return "", usageError("--team-id is required when no active team is selected in this workspace")
}

func applyHumanTeamIDToInvite(teamID string) error {
	teamInviteTeam = ""
	teamInviteNamespace = ""
	trimmed := strings.TrimSpace(teamID)
	if trimmed == "" {
		return nil
	}
	domain, name, err := awid.ParseTeamID(trimmed)
	if err != nil {
		return err
	}
	teamInviteTeam = name
	teamInviteNamespace = domain
	return nil
}
