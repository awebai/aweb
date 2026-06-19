package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
)

var (
	teamHumanCreateBYOT        bool
	teamHumanCreateName        string
	teamHumanCreateNamespace   string
	teamHumanCreateDisplayName string
	teamHumanCreateServiceURL  string
	teamHumanCreateRegistryURL string
	teamHumanCreateAlias       string
	teamHumanCreateProfiles    []string
	teamHumanInviteTeamID      string
	teamHumanAddLocal          bool
	teamHumanAddGlobal         bool
	teamHumanAddLayoutOnly     bool
	teamHumanRemoveTeamID      string
	teamHumanRemoveRegistryURL string
)

var teamHumanCmd = &cobra.Command{
	Use:   "team",
	Short: "Everyday teams: create, add, invite, join, list, switch, leave, remove-agent",
	Long: "Everyday team membership commands.\n\n" +
		"Use these commands for the normal hosted invite/join membership flow and for\n" +
		"checking or switching this identity's installed team memberships. Protocol/admin\n" +
		"controller operations remain under `aw id team`.",
}

var teamHumanCreateCmd = &cobra.Command{
	Use:   "create <name>",
	Short: "Create a local empty-profile team workspace",
	Long: "Create a local empty-profile team workspace.\n\n" +
		"This wraps aw init for the aw-local path. No --profile means no Library call\n" +
		"and no profile materialization. Library-bound --profile creation is deferred\n" +
		"behind the aw library plugin seam.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanCreate,
}

var teamHumanAddCmd = &cobra.Command{
	Use:   "add <name>[@<profile-ref>]...",
	Short: "Add empty-profile agents to this team's agents/instances layout",
	Long:  "Add one or more agents to agents/instances/<name>/. Bare names create empty-profile identity-only homes with no Library calls. @<profile-ref> is deferred behind the aw library plugin seam.",
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
	Short: "Remove an agent from a customer-controlled team",
	Long: "Remove an agent from a customer-controlled team.\n\n" +
		"This everyday verb maps to the BYOT/controller-backed certificate revocation\n" +
		"primitive. Hosted teams keep controller authority in cloud; use the hosted\n" +
		"dashboard removal flow there until hosted CLI removal is added.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanRemoveAgent,
}

func init() {
	teamHumanCmd.GroupID = groupIdentity

	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateBYOT, "byot", false, "Create a customer-controlled AWID team with local namespace controller authority")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateName, "name", "", "Team name")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateNamespace, "namespace", "", "Namespace domain for --byot")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateDisplayName, "display-name", "", "Team display name")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateServiceURL, "service", "", "Hosted service URL for dashboard guidance")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateRegistryURL, "registry", "", "Registry origin override for --byot")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateAlias, "alias", "", "Initial local workspace alias (defaults to <name>)")
	teamHumanCreateCmd.Flags().StringArrayVar(&teamHumanCreateProfiles, "profile", nil, "Library profile to adopt and materialize (deferred behind aw library seam)")
	teamHumanCmd.AddCommand(teamHumanCreateCmd)

	teamHumanAddCmd.Flags().BoolVar(&teamHumanAddLocal, "local", false, "Add a local team-scoped agent identity (default)")
	teamHumanAddCmd.Flags().BoolVar(&teamHumanAddGlobal, "global", false, "Add a global AWID identity/address-backed agent")
	teamHumanAddCmd.Flags().BoolVar(&teamHumanAddLayoutOnly, "layout-only", false, "Only create agents/instances/<name>; do not create identity state")
	teamHumanCmd.AddCommand(teamHumanAddCmd)

	teamHumanInviteCmd.Flags().StringVar(&teamHumanInviteTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to invite from (defaults to active team)")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteLocal, "local", false, "Create local workspace member invite (default)")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteGlobal, "global", false, "Create global member invite")
	teamHumanCmd.AddCommand(teamHumanInviteCmd)

	teamHumanJoinCmd.Flags().StringVar(&teamAcceptAlias, "alias", "", "Alias for the accepting agent (defaults to identity name)")
	teamHumanJoinCmd.Flags().StringVar(&teamAcceptAddress, "address", "", "Registered address to place in the global member certificate")
	teamHumanCmd.AddCommand(teamHumanJoinCmd)

	teamHumanCmd.AddCommand(teamHumanListCmd)
	teamHumanCmd.AddCommand(teamHumanSwitchCmd)
	teamHumanCmd.AddCommand(teamHumanLeaveCmd)
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to remove from (defaults to active team)")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveRegistryURL, "registry", "", "Registry origin override")
	teamHumanCmd.AddCommand(teamHumanRemoveAgentCmd)
	rootCmd.AddCommand(teamHumanCmd)
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
	NoLibrary    bool   `json:"no_library"`
	NoProfile    bool   `json:"no_profile"`
	IdentityOnly bool   `json:"identity_only"`
}

func runTeamHumanCreate(cmd *cobra.Command, args []string) error {
	teamName := strings.TrimSpace(args[0])
	if teamName == "" {
		return usageError("team name is required")
	}
	if len(teamHumanCreateProfiles) > 0 {
		return usageError("aw team create --profile requires aw library adoption; retry after the aw library plugin seam lands")
	}
	if teamHumanCreateBYOT {
		teamCreateName = teamHumanCreateName
		if strings.TrimSpace(teamCreateName) == "" {
			teamCreateName = teamName
		}
		teamCreateNamespace = teamHumanCreateNamespace
		teamCreateDisplayName = teamHumanCreateDisplayName
		teamCreateRegistryURL = teamHumanCreateRegistryURL
		return runTeamCreate(cmd, args)
	}
	if strings.TrimSpace(teamHumanCreateNamespace) != "" || strings.TrimSpace(teamHumanCreateRegistryURL) != "" {
		return usageError("aw team create does not use --namespace or --registry in the local empty-profile path")
	}
	wd, _ := os.Getwd()
	awebURL, err := resolveInitAwebURL()
	if err != nil {
		return err
	}
	registryURL, err := resolveInitAWIDRegistryURL()
	if err != nil {
		return err
	}
	alias := strings.TrimSpace(teamHumanCreateAlias)
	if alias == "" {
		alias = strings.ToLower(teamName)
	}
	if apiKey := resolveInitAPIKey(); apiKey != "" {
		result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
			WorkingDir:  wd,
			AwebURL:     awebURL,
			RegistryURL: registryURL,
			APIKey:      apiKey,
			Alias:       alias,
			HumanName:   resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:   resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		})
		if err != nil {
			return err
		}
		printOutput(teamHumanCreateOutputFromConnect(teamName, result), formatTeamHumanCreate)
		return nil
	}
	if !initShouldUseImplicitLocalFlow(registryURL) {
		return usageError("aw team create without AWEB_API_KEY requires a local awid registry; use aw init for other identity flows")
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
	printOutput(teamHumanCreateOutputFromConnect(teamName, result), formatTeamHumanCreate)
	return nil
}

func teamHumanCreateOutputFromConnect(teamName string, result connectOutput) teamHumanCreateOutput {
	return teamHumanCreateOutput{
		Status:       "created",
		TeamName:     strings.TrimSpace(teamName),
		ProfileMode:  "empty",
		TeamID:       strings.TrimSpace(result.TeamID),
		Alias:        strings.TrimSpace(result.Alias),
		WorkspaceID:  strings.TrimSpace(result.WorkspaceID),
		AwebURL:      strings.TrimSpace(result.AwebURL),
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
		fmt.Fprintf(&b, " as alias %s", out.Alias)
	}
	b.WriteString("\n")
	b.WriteString("No Library profile was adopted; no profile home was materialized.\n")
	return b.String()
}

type teamHumanAddOutput struct {
	Status     string                `json:"status"`
	AgentsRoot string                `json:"agents_root"`
	LayoutOnly bool                  `json:"layout_only"`
	NoLibrary  bool                  `json:"no_library"`
	NoProfile  bool                  `json:"no_profile"`
	Agents     []teamHumanAddedAgent `json:"agents"`
}

type teamHumanAddedAgent struct {
	Name        string `json:"name"`
	HomeDir     string `json:"home_dir"`
	ProfileMode string `json:"profile_mode"`
	Alias       string `json:"alias,omitempty"`
	TeamID      string `json:"team_id,omitempty"`
	CertPath    string `json:"cert_path,omitempty"`
}

func runTeamHumanAdd(cmd *cobra.Command, args []string) error {
	if teamHumanAddLocal && teamHumanAddGlobal {
		return usageError("--local and --global cannot be used together")
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	repoRoot := resolveRepoRoot(wd)
	agentsRoot := filepath.Join(repoRoot, "agents", "instances")
	plans := make([]teamHumanAddedAgent, 0, len(args))
	seen := map[string]bool{}
	for _, raw := range args {
		name, profileRef, err := parseTeamHumanAddSpec(raw)
		if err != nil {
			return err
		}
		if profileRef != "" {
			return usageError("aw team add %s@%s requires aw library adoption; retry after the aw library plugin seam lands", name, profileRef)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return usageError("duplicate agent name %q", name)
		}
		seen[key] = true
		plans = append(plans, teamHumanAddedAgent{Name: name, HomeDir: filepath.Join(agentsRoot, name), ProfileMode: "empty"})
	}
	for _, plan := range plans {
		if err := preflightEmptyAgentHome(plan.HomeDir); err != nil {
			return err
		}
	}
	for i := range plans {
		if err := os.MkdirAll(plans[i].HomeDir, 0o755); err != nil {
			return err
		}
		if teamHumanAddLayoutOnly {
			continue
		}
		accepted, err := createAndAcceptTeamInviteForEmptyAgent(wd, plans[i].HomeDir, plans[i].Name, teamHumanAddGlobal)
		if err != nil {
			return err
		}
		plans[i].Alias = accepted.Output.Alias
		plans[i].TeamID = accepted.Output.TeamID
		plans[i].CertPath = accepted.Output.CertPath
	}
	printOutput(teamHumanAddOutput{Status: "added", AgentsRoot: agentsRoot, LayoutOnly: teamHumanAddLayoutOnly, NoLibrary: true, NoProfile: true, Agents: plans}, formatTeamHumanAdd)
	return nil
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

func createAndAcceptTeamInviteForEmptyAgent(anchorDir, homeDir, alias string, global bool) (*acceptedTeamInvite, error) {
	team, domain, registryURL, awebURL, err := resolveTeamInviteTarget(anchorDir)
	if err != nil {
		return nil, err
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
	accepted, err := acceptTeamInviteWithDetails(homeDir, token, alias, "")
	if err != nil {
		return nil, err
	}
	if err := upsertAcceptedTeamMembershipState(homeDir, accepted.Output, accepted.Certificate, accepted.RegistryURL, accepted.AwebURL, true); err != nil {
		return nil, err
	}
	if err := ensureLocalIdentityEncryptionKeyForDir(homeDir); err != nil {
		return nil, err
	}
	return accepted, nil
}

func formatTeamHumanAdd(v any) string {
	out := v.(teamHumanAddOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Added %d empty-profile agent(s) under %s\n", len(out.Agents), out.AgentsRoot)
	for _, agent := range out.Agents {
		fmt.Fprintf(&b, "- %s: %s\n", agent.Name, agent.HomeDir)
	}
	b.WriteString("No Library profile was adopted; no profile home was materialized.\n")
	return b.String()
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
	teamRemoveRegistryURL = teamHumanRemoveRegistryURL
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
