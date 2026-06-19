package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	teamHumanCreateBYOT        bool
	teamHumanCreateName        string
	teamHumanCreateNamespace   string
	teamHumanCreateDisplayName string
	teamHumanCreateServiceURL  string
	teamHumanCreateRegistryURL string
	teamHumanCreateHosted      bool
	teamHumanCreateSelfHost    bool
	teamHumanCreateProfiles    []string
	teamHumanInviteTeamID      string
	teamHumanRemoveTeamID      string
	teamHumanRemoveRegistryURL string
)

var teamHumanCmd = &cobra.Command{
	Use:   "team",
	Short: "Everyday teams: create, invite, join, list, switch, leave, remove-agent",
	Long: "Everyday team membership commands.\n\n" +
		"Use these commands for the normal hosted invite/join membership flow and for\n" +
		"checking or switching this identity's installed team memberships. Protocol/admin\n" +
		"controller operations remain under `aw id team`.",
}

var teamHumanCreateCmd = &cobra.Command{
	Use:   "create [name]",
	Short: "Create a team or get the hosted create-team entrypoint",
	Long: "Create a team or get the hosted create-team entrypoint.\n\n" +
		"Hosted team creation is dashboard-first in this release because it depends on\n" +
		"the signed-in human account and organization. Customer-controlled BYOT teams\n" +
		"can be created from the CLI by passing --byot with --name and --namespace.",
	Args: cobra.MaximumNArgs(1),
	RunE: runTeamHumanCreate,
}

var teamHumanInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Invite an agent or workspace to the active team",
	Long: "Invite an agent or workspace to the active team.\n\n" +
		"This is the everyday add-agent entrypoint. It creates an invite token using\n" +
		"the current team's authority, then the joining workspace runs `aw team join <token>`.",
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
	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateHosted, "hosted", false, "Use hosted/API-key team creation or dashboard guidance")
	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateSelfHost, "self-host", false, "Create a local self-hosted team workspace with aw init primitives")
	teamHumanCreateCmd.Flags().StringArrayVar(&teamHumanCreateProfiles, "profile", nil, "Planned profile roster entry id@version:count (repeatable; optional, empty-profile by default)")
	teamHumanCmd.AddCommand(teamHumanCreateCmd)

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

type teamCreateProfileSelection struct {
	ProfileRef profileRef `json:"profile_ref"`
	Count      int        `json:"count"`
}

type profileRef struct {
	ID      string `json:"id"`
	Version string `json:"version"`
}

type teamCreateResult struct {
	Status              string                       `json:"status"`
	Mode                string                       `json:"mode"`
	TeamID              string                       `json:"team_id,omitempty"`
	Alias               string                       `json:"alias,omitempty"`
	AwebURL             string                       `json:"aweb_url,omitempty"`
	WorkspaceID         string                       `json:"workspace_id,omitempty"`
	Profiles            []teamCreateProfileSelection `json:"profiles"`
	EmptyProfileTeam    bool                         `json:"empty_profile_team"`
	LibraryRegistration string                       `json:"library_registration"`
}

type teamCreateLibraryRegistrationRequest struct {
	TeamID   string                       `json:"team_id"`
	Profiles []teamCreateProfileSelection `json:"profiles"`
}

var (
	teamHumanCreateAPIKeyInit = runAPIKeyBootstrapInit
	teamHumanCreateLocalInit  = func(req implicitLocalInitRequest) (connectOutput, error) { return initRunImplicitLocalFlow(req) }
	teamHumanRegisterLibrary  = func(req teamCreateLibraryRegistrationRequest) (string, error) {
		return "deferred_until_library_contract", nil
	}
)

func runTeamHumanCreate(cmd *cobra.Command, args []string) error {
	if teamHumanCreateBYOT {
		teamCreateName = teamHumanCreateName
		teamCreateNamespace = teamHumanCreateNamespace
		teamCreateDisplayName = teamHumanCreateDisplayName
		teamCreateRegistryURL = teamHumanCreateRegistryURL
		return runTeamCreate(cmd, args)
	}
	if teamHumanCreateHosted && teamHumanCreateSelfHost {
		return usageError("--hosted and --self-host are mutually exclusive")
	}
	if !teamHumanCreateHosted && !teamHumanCreateSelfHost {
		return usageError("one of --hosted or --self-host is required")
	}
	if strings.TrimSpace(teamHumanCreateNamespace) != "" || strings.TrimSpace(teamHumanCreateRegistryURL) != "" {
		return usageError("team create does not use --namespace or --registry unless --byot is set")
	}
	name := strings.TrimSpace(teamHumanCreateName)
	if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
		if name != "" && name != strings.TrimSpace(args[0]) {
			return usageError("team name specified both as argument and --name")
		}
		name = strings.TrimSpace(args[0])
	}
	profiles, err := parseTeamCreateProfiles(teamHumanCreateProfiles)
	if err != nil {
		return err
	}
	if teamHumanCreateHosted && resolveInitAPIKey() == "" {
		return printHostedTeamCreateDashboard(cmd)
	}
	if name == "" {
		return usageError("team name is required")
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	var result connectOutput
	mode := "new_local_team"
	if teamHumanCreateHosted {
		apiKey := resolveInitAPIKey()
		awebURL, err := resolveAPIKeyInitAwebURL()
		if err != nil {
			return err
		}
		registryURL, err := resolveInitAWIDRegistryURL()
		if err != nil {
			return err
		}
		mode = "existing_team_api_key"
		result, err = teamHumanCreateAPIKeyInit(apiKeyInitRequest{WorkingDir: wd, AwebURL: awebURL, RegistryURL: registryURL, APIKey: apiKey, Alias: resolveAliasValue(name), Name: strings.TrimSpace(initName), Role: resolveRequestedRole(strings.TrimSpace(initRole)), HumanName: resolveHumanNameValue(strings.TrimSpace(initHumanName)), AgentType: resolveAgentTypeValue(strings.TrimSpace(initAgentType)), Persistent: initPersistent, InboundMode: canonicalInitInboundModeForWire(initInboundMode)})
	} else {
		awebURL, err := resolveInitAwebURL()
		if err != nil {
			return err
		}
		registryURL, err := resolveInitAWIDRegistryURL()
		if err != nil {
			return err
		}
		result, err = teamHumanCreateLocalInit(implicitLocalInitRequest{WorkingDir: wd, AwebURL: awebURL, RegistryURL: registryURL, Alias: resolveAliasValue(name), Role: resolveRequestedRole(strings.TrimSpace(initRole)), HumanName: resolveHumanNameValue(strings.TrimSpace(initHumanName)), AgentType: resolveAgentTypeValue(strings.TrimSpace(initAgentType))})
	}
	if err != nil {
		return err
	}
	registration := "skipped_empty_profiles"
	if len(profiles) > 0 {
		registration, err = teamHumanRegisterLibrary(teamCreateLibraryRegistrationRequest{TeamID: result.TeamID, Profiles: profiles})
		if err != nil {
			return err
		}
	}
	out := teamCreateResult{Status: "created", Mode: mode, TeamID: result.TeamID, Alias: result.Alias, AwebURL: result.AwebURL, WorkspaceID: result.WorkspaceID, Profiles: profiles, EmptyProfileTeam: len(profiles) == 0, LibraryRegistration: registration}
	if jsonFlag {
		printOutput(out, func(v any) string { return "" })
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Created team workspace %s (%s)\n", out.TeamID, out.Mode)
	if out.EmptyProfileTeam {
		fmt.Fprintf(cmd.OutOrStdout(), "Profiles: empty (Library registration skipped)\n")
	} else {
		fmt.Fprintf(cmd.OutOrStdout(), "Profiles:\n")
		for _, profile := range out.Profiles {
			fmt.Fprintf(cmd.OutOrStdout(), "  - %s@%s x%d\n", profile.ProfileRef.ID, profile.ProfileRef.Version, profile.Count)
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Library registration: %s\n", out.LibraryRegistration)
	}
	return nil
}

func printHostedTeamCreateDashboard(cmd *cobra.Command) error {
	urls, err := resolveOnboardingServiceURLs(teamHumanCreateServiceURL)
	if err != nil {
		return err
	}
	serviceURL := strings.TrimSpace(urls.OnboardingURL)
	if serviceURL == "" {
		serviceURL = strings.TrimSpace(urls.AwebURL)
	}
	if serviceURL == "" {
		serviceURL = DefaultAwebURL
	}
	if jsonFlag {
		printOutput(map[string]any{"status": "dashboard_required", "mode": "hosted", "dashboard_url": serviceURL, "next_steps": []string{"Create the hosted team in the dashboard", "Run aw team invite from a team workspace or use the dashboard invite flow"}}, func(v any) string { return "" })
		return nil
	}
	fmt.Fprintf(cmd.OutOrStdout(), "Hosted team creation is dashboard-first unless AWEB_API_KEY is set.\n")
	fmt.Fprintf(cmd.OutOrStdout(), "Open: %s\n", serviceURL)
	return nil
}

func parseTeamCreateProfiles(values []string) ([]teamCreateProfileSelection, error) {
	out := make([]teamCreateProfileSelection, 0, len(values))
	for _, raw := range values {
		value := strings.TrimSpace(raw)
		if value == "" {
			continue
		}
		count := 1
		left := value
		if idx := strings.LastIndex(value, ":"); idx >= 0 {
			left = strings.TrimSpace(value[:idx])
			parsed, err := strconv.Atoi(strings.TrimSpace(value[idx+1:]))
			if err != nil || parsed < 0 {
				return nil, usageError("invalid --profile count in %q", raw)
			}
			count = parsed
		}
		parts := strings.Split(left, "@")
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return nil, usageError("--profile must use id@version:count")
		}
		if strings.ContainsAny(parts[0], `/\\`) || strings.Contains(parts[0], "://") || strings.Contains(parts[0], ":") {
			return nil, usageError("profile id must be a safe id segment")
		}
		out = append(out, teamCreateProfileSelection{ProfileRef: profileRef{ID: strings.TrimSpace(parts[0]), Version: strings.TrimSpace(parts[1])}, Count: count})
	}
	return out, nil
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
