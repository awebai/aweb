package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

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
	teamHumanCreateHome        string
	teamHumanCreateRuntime     string
	teamHumanCreateProfiles    []string
	teamHumanInviteTeamID      string
	teamHumanAddLocal          bool
	teamHumanAddGlobal         bool
	teamHumanAddLayoutOnly     bool
	teamHumanAddHome           string
	teamHumanAddRuntime        string
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
		"and no profile materialization. --profile BLUEPRINT_REF/PROFILE_REF[@BLUEPRINT_VERSION][=RUNTIME]\n" +
		"adopts from Library, binds the local identity, and materializes the home.\n" +
		"The materialization runtime is explicit CLI policy: --runtime, a =RUNTIME suffix, or default claude-code.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanCreate,
}

var teamHumanAddCmd = &cobra.Command{
	Use:   "add <name>[@<profile-ref>]...",
	Short: "Add empty-profile agents to this team's agents/instances layout",
	Long:  "Add one or more agents to agents/instances/<name>/. Bare names create empty-profile identity-only homes with no Library calls. NAME@BLUEPRINT_REF/PROFILE_REF[@BLUEPRINT_VERSION] adopts from Library, binds the new identity, and materializes the home. Use --runtime to choose the materialization runtime; omitted --runtime defaults to claude-code.",
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
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateHome, "home", "", "Agent home directory override for single-agent --profile create")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateRuntime, "runtime", "", "Materialization runtime for --profile homes (claude-code|codex|pi|local-shell; default claude-code)")
	teamHumanCreateCmd.Flags().StringArrayVar(&teamHumanCreateProfiles, "profile", nil, "Library profile selector BLUEPRINT_REF/PROFILE_REF[@BLUEPRINT_VERSION][=RUNTIME] to adopt and materialize")
	teamHumanCmd.AddCommand(teamHumanCreateCmd)

	teamHumanAddCmd.Flags().BoolVar(&teamHumanAddLocal, "local", false, "Add a local team-scoped agent identity (default)")
	teamHumanAddCmd.Flags().BoolVar(&teamHumanAddGlobal, "global", false, "Add a global AWID identity/address-backed agent")
	teamHumanAddCmd.Flags().BoolVar(&teamHumanAddLayoutOnly, "layout-only", false, "Only create agents/instances/<name>; do not create identity state")
	teamHumanAddCmd.Flags().StringVar(&teamHumanAddHome, "home", "", "Agent home directory override for a single added agent (default: agents/instances/<name>)")
	teamHumanAddCmd.Flags().StringVar(&teamHumanAddRuntime, "runtime", "", "Materialization runtime for profile-bound agents (claude-code|codex|pi|local-shell; default claude-code)")
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
	HomeDir      string `json:"home_dir,omitempty"`
	NoLibrary    bool   `json:"no_library"`
	NoProfile    bool   `json:"no_profile"`
	IdentityOnly bool   `json:"identity_only"`
}

func runTeamHumanCreate(cmd *cobra.Command, args []string) error {
	teamName := strings.TrimSpace(args[0])
	if teamName == "" {
		return usageError("team name is required")
	}
	profileSelectors := make([]libraryProfileSelector, 0, len(teamHumanCreateProfiles))
	for _, rawProfile := range teamHumanCreateProfiles {
		parsed, err := parseLibraryProfileSelector(rawProfile)
		if err != nil {
			return err
		}
		if err := rejectUnsupportedVersionedLibrarySelector(parsed); err != nil {
			return err
		}
		parsed, err = applyMaterializeRuntimePolicy(parsed, teamHumanCreateRuntime)
		if err != nil {
			return err
		}
		profileSelectors = append(profileSelectors, parsed)
	}
	var selector *libraryProfileSelector
	if len(profileSelectors) == 1 {
		selector = &profileSelectors[0]
	}
	rosterSpecs, err := teamHumanCreateRosterSpecs(profileSelectors)
	if err != nil {
		return err
	}
	wd, _ := os.Getwd()
	createHomeOverride := ""
	if strings.TrimSpace(teamHumanCreateHome) != "" {
		if len(profileSelectors) == 0 {
			return usageError("aw team create --home requires --profile")
		}
		if len(profileSelectors) > 1 {
			return usageError("aw team create --home can only be used with a single --profile")
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
	alias := strings.TrimSpace(teamHumanCreateAlias)
	if alias == "" {
		alias = strings.ToLower(teamName)
	}
	if teamHumanCreateBYOT {
		if len(profileSelectors) > 0 {
			return usageError("aw team create --byot --profile is not supported yet; create the BYOT team, then use aw team add NAME@BLUEPRINT_REF/PROFILE_REF")
		}
		name := strings.TrimSpace(teamHumanCreateName)
		if name == "" {
			name = teamName
		}
		domain := awconfig.NormalizeDomain(teamHumanCreateNamespace)
		if domain == "" {
			return usageError("aw team create --byot requires --namespace")
		}
		return runTeamHumanCreateModelA(wd, name, alias, domain, strings.TrimSpace(teamHumanCreateRegistryURL), strings.TrimSpace(teamHumanCreateDisplayName), nil)
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
			agentID := strings.TrimSpace(sel.Alias)
			if agentID == "" {
				agentID = strings.ToLower(teamName)
			}
			if _, _, err := applyLibraryProfileToHomeAndConfigure(wd, agentID, *selector, true); err != nil {
				return err
			}
			printOutput(teamHumanCreateOutput{Status: "created", TeamName: teamName, ProfileMode: "library", TeamID: sel.TeamID, Alias: sel.Alias, WorkspaceID: sel.WorkspaceID, AwebURL: sel.AwebURL, HomeDir: wd, NoLibrary: false, NoProfile: false, IdentityOnly: false}, formatTeamHumanCreate)
			return nil
		}
	}
	identityExists, err := teamCreateHasIdentityMaterial(wd)
	if err != nil {
		return err
	}
	if identityExists {
		if err := runTeamHumanCreateForExistingIdentity(wd, teamName, alias, selector); err != nil {
			return err
		}
		return runTeamHumanCreateRosterAdd(rosterSpecs)
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
		out := teamHumanCreateOutputFromConnect(teamName, result, wd)
		if selector != nil {
			if _, _, err := applyLibraryProfileToHomeAndConfigure(wd, result.Alias, *selector, true); err != nil {
				return err
			}
			out.ProfileMode = "library"
			out.NoLibrary = false
			out.NoProfile = false
			out.IdentityOnly = false
		}
		printOutput(out, formatTeamHumanCreate)
		return runTeamHumanCreateRosterAdd(rosterSpecs)
	}
	if !initShouldUseImplicitLocalFlow(registryURL) {
		if err := runTeamHumanCreateHostedInitBundle(wd, awebURL, registryURL, alias, selector); err != nil {
			return err
		}
		return runTeamHumanCreateRosterAdd(rosterSpecs)
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
	if selector != nil {
		if _, _, err := applyLibraryProfileToHomeAndConfigure(wd, result.Alias, *selector, true); err != nil {
			return err
		}
		out.ProfileMode = "library"
		out.NoLibrary = false
		out.NoProfile = false
		out.IdentityOnly = false
	}
	printOutput(out, formatTeamHumanCreate)
	return runTeamHumanCreateRosterAdd(rosterSpecs)
}

func teamHumanCreateRosterSpecs(selectors []libraryProfileSelector) ([]string, error) {
	if len(selectors) <= 1 {
		return nil, nil
	}
	specs := make([]string, 0, len(selectors))
	seen := map[string]bool{}
	for _, selector := range selectors {
		name := strings.TrimSpace(selector.ProfileRef)
		if !isValidWorkspaceAlias(name) {
			return nil, usageError("profile ref %q cannot be used as an agent name; use aw team add NAME@BLUEPRINT_REF/PROFILE_REF", selector.ProfileRef)
		}
		key := strings.ToLower(name)
		if seen[key] {
			return nil, usageError("duplicate roster agent name %q from --profile selectors", name)
		}
		seen[key] = true
		spec := fmt.Sprintf("%s@%s/%s", name, selector.SourceBlueprintRef, selector.ProfileRef)
		if strings.TrimSpace(selector.RuntimeKind) != "" {
			spec += "=" + strings.TrimSpace(selector.RuntimeKind)
		}
		specs = append(specs, spec)
	}
	return specs, nil
}

func runTeamHumanCreateRosterAdd(specs []string) error {
	if len(specs) == 0 {
		return nil
	}
	oldAddLocal := teamHumanAddLocal
	oldAddGlobal := teamHumanAddGlobal
	oldAddLayoutOnly := teamHumanAddLayoutOnly
	oldAddHome := teamHumanAddHome
	defer func() {
		teamHumanAddLocal = oldAddLocal
		teamHumanAddGlobal = oldAddGlobal
		teamHumanAddLayoutOnly = oldAddLayoutOnly
		teamHumanAddHome = oldAddHome
	}()
	teamHumanAddLocal = false
	teamHumanAddGlobal = false
	teamHumanAddLayoutOnly = false
	teamHumanAddHome = ""
	return runTeamHumanAdd(nil, specs)
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

func runTeamHumanCreateHostedInitBundle(wd, awebURL, registryURL, alias string, selector *libraryProfileSelector) error {
	canPrompt := initIsTTY() && !jsonFlag
	askPostCreateSetup := canPrompt && !initHasExplicitOnboardingArgs()
	result, err := guidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir:         wd,
		PromptIn:           os.Stdin,
		PromptOut:          os.Stderr,
		BaseURL:            awebURL,
		RegistryURL:        registryURL,
		ServerName:         serverFlag,
		BYOD:               false,
		Username:           strings.TrimSpace(initUsername),
		Domain:             strings.TrimSpace(initDomain),
		Alias:              alias,
		Name:               strings.TrimSpace(initName),
		HumanName:          resolveHumanNameValue(strings.TrimSpace(initHumanName)),
		AgentType:          resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		Role:               resolveRequestedRole(strings.TrimSpace(initRole)),
		Persistent:         initPersistent,
		InboundMode:        canonicalInitInboundModeForWire(initInboundMode),
		InjectAgentDocs:    !initDoNotTouchAgentsMD && !jsonFlag,
		DoNotTouchAgentsMD: initDoNotTouchAgentsMD,
		AskPostCreateSetup: askPostCreateSetup,
		NonInteractive:     !canPrompt,
	})
	if err != nil {
		return err
	}
	if selector != nil {
		sel, err := resolveSelectionForDir(wd)
		if err != nil {
			return err
		}
		agentID := strings.TrimSpace(sel.Alias)
		if agentID == "" {
			agentID = alias
		}
		if _, _, err := applyLibraryProfileToHomeAndConfigure(wd, agentID, *selector, true); err != nil {
			return err
		}
	}
	if !jsonFlag {
		initPrintGuidedOnboardingReady(result)
	}
	return nil
}

func runTeamHumanCreateForExistingIdentity(wd, teamName, alias string, selector *libraryProfileSelector) error {
	return runTeamHumanCreateModelA(wd, teamName, alias, "", "", strings.TrimSpace(teamHumanCreateDisplayName), selector)
}

func runTeamHumanCreateModelA(wd, teamName, alias, explicitDomain, explicitRegistryURL, displayName string, selector *libraryProfileSelector) error {
	if selector != nil {
		return usageError("aw team create --profile for an existing identity is not supported yet; use aw team add NAME@BLUEPRINT/PROFILE after creating the team")
	}
	identity, _, err := awconfig.LoadWorktreeIdentityFromDir(wd)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			if strings.TrimSpace(explicitDomain) != "" {
				return usageError("aw team create --byot requires a local member identity to enroll; use aw id team create for a controller-only team, or run aw init / aw id create first")
			}
			return usageError("current workspace has local signing state but no namespace address; run aw init for first-team setup or use --byot/--namespace for a domain you control")
		}
		return err
	}
	identityDomain, _, ok := awconfig.CutIdentityAddress(identity.Address)
	if !ok {
		return usageError("current identity has no namespace address; run aw init for first-team setup or use --byot/--namespace for a domain you control")
	}
	domain := awconfig.NormalizeDomain(explicitDomain)
	if domain == "" {
		domain = identityDomain
	}
	exists, err := awconfig.ControllerKeyExists(domain)
	if err != nil {
		return err
	}
	if !exists {
		return usageError("current identity is hosted-managed for namespace %s; creating another hosted team is not supported yet (tracked in default-aaas.3.15)", domain)
	}
	controllerKey, err := awconfig.LoadControllerKey(domain)
	if err != nil {
		return fmt.Errorf("load controller key for %s: %w", domain, err)
	}
	registryURL := strings.TrimSpace(explicitRegistryURL)
	if registryURL == "" {
		registryURL = strings.TrimSpace(identity.RegistryURL)
	}
	if registryURL == "" {
		registryURL, err = resolveInitAWIDRegistryURL()
		if err != nil {
			return err
		}
	}
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return err
	}
	if strings.TrimSpace(registryURL) != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return err
		}
	}
	memberKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(wd))
	if err != nil {
		return fmt.Errorf("load local signing key: %w", err)
	}
	memberDIDKey := awid.ComputeDIDKey(memberKey.Public().(ed25519.PublicKey))
	if strings.TrimSpace(identity.DID) != "" && strings.TrimSpace(identity.DID) != memberDIDKey {
		return fmt.Errorf("local signing key did %s does not match identity did %s", memberDIDKey, identity.DID)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := validateMemberAddressForCertificate(ctx, registry, strings.TrimSpace(registry.DefaultRegistryURL), strings.TrimSpace(identity.Address), strings.TrimSpace(identity.StableID), memberDIDKey, memberKey); err != nil {
		return err
	}
	bootstrap, err := bootstrapLocalTeamMemberWithLifetime(ctx, registry, strings.TrimSpace(registry.DefaultRegistryURL), domain, strings.ToLower(strings.TrimSpace(teamName)), strings.TrimSpace(displayName), controllerKey, memberKey, strings.TrimSpace(identity.StableID), strings.TrimSpace(identity.Address), alias, strings.TrimSpace(identity.Lifetime))
	if err != nil {
		return err
	}
	certPath, err := awconfig.SaveTeamCertificateForTeam(wd, bootstrap.TeamID, bootstrap.Certificate)
	if err != nil {
		return err
	}
	accepted := &teamAcceptInviteOutput{Status: "accepted", TeamID: bootstrap.TeamID, Alias: alias, CertPath: certPath}
	awebURL, err := resolveInitAwebURL()
	if err != nil {
		return err
	}
	if err := upsertAcceptedTeamMembershipState(wd, accepted, bootstrap.Certificate, strings.TrimSpace(registry.DefaultRegistryURL), awebURL, true); err != nil {
		return err
	}
	if err := ensureAcceptedTeamWorkspaceBinding(wd, accepted, bootstrap.Certificate, awebURL); err != nil {
		return err
	}
	printOutput(teamCreateOutput{Status: "created", TeamID: bootstrap.TeamID, TeamDIDKey: bootstrap.TeamDIDKey, TeamKeyPath: bootstrap.TeamKeyPath, RegistryURL: strings.TrimSpace(registry.DefaultRegistryURL)}, formatTeamCreate)
	return nil
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
		fmt.Fprintf(&b, " as alias %s", out.Alias)
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
	Status       string                `json:"status"`
	AgentsRoot   string                `json:"agents_root"`
	HomeOverride bool                  `json:"home_override,omitempty"`
	LayoutOnly   bool                  `json:"layout_only"`
	NoLibrary    bool                  `json:"no_library"`
	NoProfile    bool                  `json:"no_profile"`
	Agents       []teamHumanAddedAgent `json:"agents"`
}

type teamHumanAddedAgent struct {
	Name        string                  `json:"name"`
	HomeDir     string                  `json:"home_dir"`
	ProfileMode string                  `json:"profile_mode"`
	Profile     *libraryProfileSelector `json:"-"`
	Alias       string                  `json:"alias,omitempty"`
	TeamID      string                  `json:"team_id,omitempty"`
	CertPath    string                  `json:"cert_path,omitempty"`
}

func runTeamHumanAdd(cmd *cobra.Command, args []string) error {
	if teamHumanAddLocal && teamHumanAddGlobal {
		return usageError("--local and --global cannot be used together")
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
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
	agentsRoot := filepath.Join(repoRoot, "agents", "instances")
	plans := make([]teamHumanAddedAgent, 0, len(args))
	seen := map[string]bool{}
	for _, raw := range args {
		name, profileRef, err := parseTeamHumanAddSpec(raw)
		if err != nil {
			return err
		}
		var selector *libraryProfileSelector
		if profileRef != "" {
			if teamHumanAddLayoutOnly {
				return usageError("aw team add --layout-only cannot be used with profile selector %s@%s", name, profileRef)
			}
			parsed, err := parseLibraryProfileSelector(profileRef)
			if err != nil {
				return err
			}
			if err := rejectUnsupportedVersionedLibrarySelector(parsed); err != nil {
				return err
			}
			parsed, err = applyMaterializeRuntimePolicy(parsed, teamHumanAddRuntime)
			if err != nil {
				return err
			}
			selector = &parsed
		}
		key := strings.ToLower(name)
		if seen[key] {
			return usageError("duplicate agent name %q", name)
		}
		seen[key] = true
		profileMode := "empty"
		if selector != nil {
			profileMode = "library"
		}
		homeDir := filepath.Join(agentsRoot, name)
		if explicitHome != "" {
			homeDir = explicitHome
		}
		plans = append(plans, teamHumanAddedAgent{Name: name, HomeDir: homeDir, ProfileMode: profileMode, Profile: selector})
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
	for i := range plans {
		var rollback *agentHomeRollback
		if plans[i].Profile != nil {
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
		if plans[i].Profile != nil {
			if sel, err := resolveSelectionForDir(plans[i].HomeDir); err == nil && strings.TrimSpace(sel.TeamID) != "" {
				plans[i].Alias = strings.TrimSpace(sel.Alias)
				plans[i].TeamID = strings.TrimSpace(sel.TeamID)
			} else {
				accepted, err := createAndAcceptTeamInviteForEmptyAgent(wd, plans[i].HomeDir, plans[i].Name, teamHumanAddGlobal)
				if err != nil {
					if rollback != nil {
						_ = rollback.Rollback()
					}
					return err
				}
				createdProfileIdentity = true
				plans[i].Alias = accepted.Output.Alias
				plans[i].TeamID = accepted.Output.TeamID
				plans[i].CertPath = accepted.Output.CertPath
			}
		} else {
			accepted, err := createAndAcceptTeamInviteForEmptyAgent(wd, plans[i].HomeDir, plans[i].Name, teamHumanAddGlobal)
			if err != nil {
				return err
			}
			plans[i].Alias = accepted.Output.Alias
			plans[i].TeamID = accepted.Output.TeamID
			plans[i].CertPath = accepted.Output.CertPath
		}
		if plans[i].Profile != nil {
			agentID := strings.TrimSpace(plans[i].Alias)
			if agentID == "" {
				agentID = plans[i].Name
			}
			rollbackOnErr := func(err error) error {
				if createdProfileIdentity && rollback != nil {
					if rbErr := rollback.Rollback(); rbErr != nil {
						return fmt.Errorf("%w; rollback failed: %v", err, rbErr)
					}
				}
				return err
			}
			// Materialize the profile home, connect the member to the aweb service,
			// then run the coordination configure step. Connect sits between the two:
			// the configure step injects the team's active instructions, which the
			// aweb server serves only to a connected agent, and self-hosted create/add
			// install the awid certificate but not the aweb connection. Connecting only
			// after materialize succeeds avoids an orphaned aweb connection on a
			// materialize failure. (default-aabq.21)
			if _, _, err := applyLibraryProfileToHome(plans[i].HomeDir, agentID, *plans[i].Profile, true); err != nil {
				return rollbackOnErr(err)
			}
			if sel, selErr := resolveSelectionForDir(plans[i].HomeDir); selErr == nil && strings.TrimSpace(sel.AwebURL) != "" {
				if _, err := initCertificateConnectWithOptions(plans[i].HomeDir, strings.TrimSpace(sel.AwebURL), certificateConnectOptions{
					Role: strings.TrimSpace(plans[i].Profile.ProfileRef),
				}); err != nil {
					return rollbackOnErr(fmt.Errorf("connect agent to aweb service: %w", err))
				}
			}
			if err := configureMaterializedAgentHome(plans[i].HomeDir); err != nil {
				return rollbackOnErr(err)
			}
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
	printOutput(teamHumanAddOutput{Status: "added", AgentsRoot: agentsRoot, HomeOverride: explicitHome != "", LayoutOnly: teamHumanAddLayoutOnly, NoLibrary: noLibrary, NoProfile: noProfile, Agents: plans}, formatTeamHumanAdd)
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
	if err := ensureAcceptedTeamWorkspaceBinding(homeDir, accepted.Output, accepted.Certificate, accepted.AwebURL); err != nil {
		return nil, err
	}
	if err := ensureLocalIdentityEncryptionKeyForDir(homeDir); err != nil {
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
			fmt.Fprintf(&b, "Added %d %s from %s with explicit home\n", len(out.Agents), agentWord, profileText)
		} else {
			fmt.Fprintf(&b, "Added %d %s from %s under %s\n", len(out.Agents), agentWord, profileText, out.AgentsRoot)
		}
	} else if profileCount > 0 {
		emptyCount := len(out.Agents) - profileCount
		if out.HomeOverride {
			fmt.Fprintf(&b, "Added %d agent(s) with explicit home (%d from blueprint profiles, %d empty-profile)\n", len(out.Agents), profileCount, emptyCount)
		} else {
			fmt.Fprintf(&b, "Added %d agent(s) under %s (%d from blueprint profiles, %d empty-profile)\n", len(out.Agents), out.AgentsRoot, profileCount, emptyCount)
		}
	} else if out.HomeOverride {
		fmt.Fprintf(&b, "Added %d empty-profile agent(s) with explicit home\n", len(out.Agents))
	} else {
		fmt.Fprintf(&b, "Added %d empty-profile agent(s) under %s\n", len(out.Agents), out.AgentsRoot)
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
