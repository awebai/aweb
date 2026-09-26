package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize this directory as an aw workspace",
	Long: `Initialize the current directory using one of the supported
team-architecture flows:

- connect with an existing team certificate already present in .aw/
- create a hosted aweb.ai account when this directory is still clean
- use --byod to create an identity under a domain you control

By default, init creates or updates the clearly marked aweb section in
AGENTS.md or CLAUDE.md. Use --do-not-touch-agents-md to skip that file update.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// Root initialization runs first with hook traversal enabled.
	},
	RunE: runInit,
}

var (
	initURL                string
	initAwebURL            string
	initAWIDRegistry       string
	initBYOD               bool
	initUsername           string
	initDomain             string
	initAlias              string
	initName               string
	initInjectDocs         bool
	initSetupHooks         bool
	initSetupChannel       bool
	initDoNotTouchAgentsMD bool
	initHumanName          string
	initAgentType          string
	initWriteContext       bool
	initPrintExports       bool
	initRole               string
	initGlobal             bool
	initInboundMode        string
	initJoinFrom           string
	initJoinTeam           string
	initAdmissionTeamID    string
	initWorkspaceTeam      bool
	initWorkspaceKey       string
	initNewAccount         bool
	initNewTeam            bool
)

var (
	initIsTTY                      = isTTY
	initPrintGuidedOnboardingReady = printGuidedOnboardingReadyMessage
	initRunImplicitLocalFlow       = runImplicitLocalInit
)

type initResult struct {
	ServerName    string
	ExportBaseURL string
	Alias         string
	// APIKeyAuth is true when init succeeded via an API key bootstrap.
	// API keys are minted from an authenticated context (dashboard or
	// programmatic), so the actor already has an account; suggesting
	// `aw claim-human` is misleading. Other init paths leave this false
	// and the claim-human suggestion fires per shouldSuggestClaimHuman.
	APIKeyAuth bool
}

func init() {
	initCmd.Flags().StringVar(&initURL, "url", "", "Base URL for the aweb server used for init, bootstrap, and hosted onboarding flows")
	initCmd.Flags().StringVar(&initAwebURL, "aweb-url", "", "Base URL for the aweb server used by aw init (overrides AWEB_URL)")
	initCmd.Flags().StringVar(&initAWIDRegistry, "awid-registry", "", "Base URL for the awid registry used by aw init (overrides AWID_REGISTRY_URL)")
	initCmd.Flags().BoolVar(&initBYOD, "byod", false, "Use a domain you control instead of hosted aweb.ai onboarding")
	initCmd.Flags().StringVar(&initUsername, "username", "", "Hosted username to create")
	initCmd.Flags().StringVar(&initDomain, "domain", "", "BYOD domain to use with --byod")
	initCmd.Flags().StringVar(&initAlias, "local-name", "", "Deprecated alias for --name when creating a local workspace")
	markDeprecatedHiddenFlag(initCmd, "local-name", "name")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Deprecated alias for --name")
	markDeprecatedHiddenFlag(initCmd, "alias", "name")
	initCmd.Flags().StringVar(&initName, "name", "", "Identity/member name (global address name with --global, local routing name otherwise)")
	initCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	initCmd.Flags().BoolVar(&initDoNotTouchAgentsMD, "do-not-touch-agents-md", false, "Do not create or update AGENTS.md or CLAUDE.md during init")
	initCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	initCmd.Flags().BoolVar(&initSetupChannel, "setup-channel", false, "Set up Claude Code aweb-channel plugin for real-time coordination")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Ensure .aw/context exists in the current directory")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	addWorkspaceRoleFlags(initCmd, &initRole, "Workspace role name (must match a role in the active team roles bundle)")
	initCmd.Flags().BoolVar(&initGlobal, "global", false, "Create an addressed self-custodial global identity instead of the default local workspace")
	initCmd.Flags().BoolVar(&initGlobal, "persistent", false, "Deprecated alias for --global")
	markDeprecatedHiddenFlag(initCmd, "persistent", "global")
	initCmd.Flags().StringVar(&initInboundMode, "inbound-mode", "", "Inbound delivery mode for a global identity (open|team-and-contacts). Only valid with --global.")
	initCmd.Flags().StringVar(&initJoinFrom, "join-from", "", "Add an agent to a team by minting one invite from this existing workspace or identity home")
	initCmd.Flags().StringVar(&initJoinTeam, "join-team", "", "Team ID to use with --join-from when the source has more than one membership")
	initCmd.Flags().StringVar(&initAdmissionTeamID, "admission-team-id", "", "Add an agent through host human admission for this explicit team ID")
	initCmd.Flags().BoolVar(&initWorkspaceTeam, "workspace-team", false, "Ensure a workspace's default team using explicit --identity-home and --workspace-key")
	initCmd.Flags().StringVar(&initWorkspaceKey, "workspace-key", "", "OATS canonical format-1 workspace key for --workspace-team")
	initCmd.Flags().BoolVar(&initNewAccount, "new-account", false, "Explicitly create a new hosted aweb.ai account")
	initCmd.Flags().BoolVar(&initNewTeam, "new-team", false, "Explicitly create a new self-hosted/BYOD team")

	rootCmd.AddCommand(initCmd)
}

func addWorkspaceRoleFlags(cmd *cobra.Command, target *string, description string) {
	cmd.Flags().StringVar(target, "role-name", "", description)
	cmd.Flags().StringVar(target, "role", "", "Compatibility alias for --role-name")
}

func validateInitOutcomeFlags() error {
	outcomes := initOutcomeFlagNames()
	if len(outcomes) > 1 {
		return usageError("init outcome flags are mutually exclusive: %s", strings.Join(outcomes, ", "))
	}
	if strings.TrimSpace(initJoinTeam) != "" && strings.TrimSpace(initJoinFrom) == "" {
		return usageError("--join-team requires --join-from")
	}
	if strings.TrimSpace(activeIdentityHome.Root) != "" && activeIdentityHome.External() && !initWorkspaceTeam {
		return usageError("aw init with --identity-home is only supported for --workspace-team; refusing to use an external identity home for account, team, or add-agent init")
	}
	return nil
}

func initOutcomeFlagNames() []string {
	var outcomes []string
	if strings.TrimSpace(initJoinFrom) != "" {
		outcomes = append(outcomes, "--join-from")
	}
	if strings.TrimSpace(initAdmissionTeamID) != "" {
		outcomes = append(outcomes, "--admission-team-id")
	}
	if initWorkspaceTeam {
		outcomes = append(outcomes, "--workspace-team")
	}
	if initNewAccount {
		outcomes = append(outcomes, "--new-account")
	}
	if initNewTeam {
		outcomes = append(outcomes, "--new-team")
	}
	return outcomes
}

func missingInitOutcomeError(action, flag string) error {
	guidance := initWorkspaceDiscoveryGuidance()
	if guidance != "" {
		return usageError("explicit init outcome required to %s; rerun with %s, or choose --join-from, --admission-team-id, or --workspace-team\n\n%s", action, flag, guidance)
	}
	return usageError("explicit init outcome required to %s; rerun with %s, or choose --join-from, --admission-team-id, or --workspace-team", action, flag)
}

func requireOrPromptInitOutcome(canPrompt bool, action, flag string) error {
	if !canPrompt {
		return missingInitOutcomeError(action, flag)
	}
	printInitWorkspaceDiscoveryChoices(os.Stderr)
	promptIn := bufferedPromptReader(os.Stdin)
	choice, err := promptRequiredStringWithIO("Choose aw init outcome (number, join-from, admission-team-id, workspace-team, new-account, new-team)", "", promptIn, os.Stderr)
	if err != nil {
		return err
	}
	if handled, err := applyInitDiscoveryChoice(strings.TrimSpace(choice)); handled || err != nil {
		if err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "Confirmed: this will join team %s from %s.\n", initJoinTeam, initJoinFrom)
		return nil
	}
	switch strings.TrimSpace(choice) {
	case "new-account", "--new-account":
		if flag != "--new-account" {
			return usageError("chosen outcome --new-account does not match this init path; rerun with --new-account or choose %s", flag)
		}
		fmt.Fprintln(os.Stderr, "Confirmed: this will create a NEW ACCOUNT with its own team.")
		initNewAccount = true
		return nil
	case "new-team", "--new-team":
		if flag != "--new-team" {
			return usageError("chosen outcome --new-team does not match this init path; rerun with --new-team or choose %s", flag)
		}
		fmt.Fprintln(os.Stderr, "Confirmed: this will create a new team for this workspace.")
		initNewTeam = true
		return nil
	case "join-from", "--join-from":
		source, err := promptRequiredStringWithIO("Join from workspace or identity home", "", promptIn, os.Stderr)
		if err != nil {
			return err
		}
		initJoinFrom = strings.TrimSpace(source)
		team, err := promptStringWithIO("Team ID for join (blank is allowed only when the source has one membership)", strings.TrimSpace(initJoinTeam), promptIn, os.Stderr)
		if err != nil {
			return err
		}
		initJoinTeam = strings.TrimSpace(team)
		teamLabel := initJoinTeam
		if teamLabel == "" {
			teamLabel = "the source's only team"
		}
		fmt.Fprintf(os.Stderr, "Confirmed: this will join %s from %s.\n", teamLabel, initJoinFrom)
		return nil
	case "admission-team-id", "--admission-team-id":
		teamID, err := promptRequiredStringWithIO("Admission team ID", "", promptIn, os.Stderr)
		if err != nil {
			return err
		}
		initAdmissionTeamID = strings.TrimSpace(teamID)
		fmt.Fprintf(os.Stderr, "Confirmed: this will request hosted admission for team %s.\n", initAdmissionTeamID)
		return nil
	case "workspace-team", "--workspace-team":
		identityHomeRoot, err := promptRequiredStringWithIO("Identity home root for workspace's default team", strings.TrimSpace(activeIdentityHome.Root), promptIn, os.Stderr)
		if err != nil {
			return err
		}
		identityHomeRoot, err = filepathAbs(identityHomeRoot)
		if err != nil {
			return err
		}
		workspaceKey, err := promptRequiredStringWithIO("Workspace's default team key", strings.TrimSpace(initWorkspaceKey), promptIn, os.Stderr)
		if err != nil {
			return err
		}
		initWorkspaceTeam = true
		initWorkspaceKey = strings.TrimSpace(workspaceKey)
		activeIdentityHome = awconfig.IdentityHome{Root: identityHomeRoot, Source: awconfig.IdentityHomeFlag}
		fmt.Fprintf(os.Stderr, "Confirmed: this will ensure a workspace's default team in explicit identity home %s.\n", identityHomeRoot)
		return nil
	default:
		return usageError("unknown init outcome %q; choose join-from, admission-team-id, workspace-team, new-account, or new-team", choice)
	}
}

func applyInitDiscoveryChoice(choice string) (bool, error) {
	if choice == "" {
		return false, nil
	}
	entries, err := awconfig.LoadMachineWorkspaceIndex()
	if err != nil {
		return false, nil
	}
	for i, entry := range entries {
		if choice == fmt.Sprintf("%d", i+1) {
			if entry.Availability != awconfig.MachineWorkspaceAvailable {
				detail := strings.TrimSpace(entry.AvailabilityError)
				if detail != "" {
					return true, usageError("workspace discovery entry %d is unavailable: %s", i+1, detail)
				}
				return true, usageError("workspace discovery entry %d is unavailable", i+1)
			}
			initJoinFrom = strings.TrimSpace(entry.Path)
			initJoinTeam = strings.TrimSpace(entry.TeamID)
			return initJoinFrom != "" && initJoinTeam != "", nil
		}
	}
	if strings.Contains(choice, string(os.PathSeparator)) || strings.HasPrefix(choice, ".") {
		initJoinFrom = strings.TrimSpace(choice)
		return true, nil
	}
	return false, nil
}

func initWorkspaceDiscoveryGuidance() string {
	entries, err := awconfig.LoadMachineWorkspaceIndex()
	if err != nil {
		return fmt.Sprintf("Warning: could not read workspace discovery index at ~/.config/aw/workspaces.yaml: %v", err)
	}
	if len(entries) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Existing workspace discovery index (~/.config/aw/workspaces.yaml; discovery only, not authority):\n")
	for i, entry := range entries {
		availability := string(entry.Availability)
		if availability == "" {
			availability = string(awconfig.MachineWorkspaceUnavailable)
		}
		detail := ""
		if strings.TrimSpace(entry.AvailabilityError) != "" {
			detail = ": " + strings.TrimSpace(entry.AvailabilityError)
		}
		fmt.Fprintf(&b, "  %d) %s team=%s alias=%s server=%s [%s%s]\n", i+1, entry.Path, entry.TeamID, entry.Alias, entry.ServerURL, availability, detail)
		if entry.Availability == awconfig.MachineWorkspaceAvailable {
			fmt.Fprintf(&b, "     join with: aw init --join-from %q --join-team %q\n", entry.Path, entry.TeamID)
		}
	}
	return strings.TrimRight(b.String(), "\n")
}

func printInitWorkspaceDiscoveryChoices(out io.Writer) {
	guidance := initWorkspaceDiscoveryGuidance()
	if guidance == "" {
		return
	}
	fmt.Fprintln(out, guidance)
}

func runPromptedExplicitInitOutcome(cmd *cobra.Command) (bool, error) {
	if initWorkspaceTeam {
		return true, runInitWorkspaceTeam(cmd)
	}
	if strings.TrimSpace(initJoinFrom) != "" {
		return true, runInitJoinFrom(cmd)
	}
	if strings.TrimSpace(initAdmissionTeamID) != "" {
		return true, runInitAdmissionTeamID(cmd)
	}
	return false, nil
}

func runInitWorkspaceTeam(cmd *cobra.Command) error {
	if strings.TrimSpace(activeIdentityHome.Root) == "" || !activeIdentityHome.External() {
		return usageError("--identity-home is required with --workspace-team")
	}
	if strings.TrimSpace(initWorkspaceKey) == "" {
		return usageError("--workspace-key is required with --workspace-team")
	}
	previousKey, previousLabel := teamEnsureWorkspaceKey, teamEnsureLabel
	teamEnsureWorkspaceKey = strings.TrimSpace(initWorkspaceKey)
	teamEnsureLabel = strings.TrimSpace(initName)
	defer func() {
		teamEnsureWorkspaceKey = previousKey
		teamEnsureLabel = previousLabel
	}()
	return runTeamEnsure(cmd.Context(), cmd)
}

func runInitJoinFrom(cmd *cobra.Command) error {
	wd, _ := os.Getwd()
	if err := ensureConnectTargetClean(wd); err != nil {
		return err
	}
	sourceWorkingDir, sourceIdentityHome, teamID, err := resolveInitJoinSource(strings.TrimSpace(initJoinFrom), strings.TrimSpace(initJoinTeam))
	if err != nil {
		return err
	}
	invite, err := createWorkspaceTeamInviteForTeamAt(sourceWorkingDir, sourceIdentityHome, teamID)
	if err != nil {
		return fmt.Errorf("%w; alternatively use --admission-team-id %s with host authorization", err, teamID)
	}
	return acceptInitInviteAndConnect(cmd, wd, invite.Token, invite.AwebURL)
}

func runInitAdmissionTeamID(cmd *cobra.Command) error {
	wd, _ := os.Getwd()
	if err := ensureConnectTargetClean(wd); err != nil {
		return err
	}
	if err := ensureTeamAdmissionAuthForInit(cmd); err != nil {
		return err
	}
	resp, err := issueTeamAdmissionInvite(cmd.Context(), strings.TrimSpace(initAdmissionTeamID), newRegistryReadRequestID(), resolveAliasValue(resolveInitLocalName()))
	if err != nil {
		return err
	}
	return acceptInitInviteAndConnect(cmd, wd, resp.Token, resp.ServerURL)
}

func ensureTeamAdmissionAuthForInit(cmd *cobra.Command) error {
	_, ok, err := loadCLIAuthConfigForScope(cliAuthScopeTeamAdmission)
	if err != nil {
		return err
	}
	if ok {
		return nil
	}
	if initIsTTY() && !jsonFlag {
		allow, err := promptYesNoWithIO("No cli.team_admission login was found. Start bounded device login now?", true, os.Stdin, os.Stderr)
		if err != nil {
			return err
		}
		if !allow {
			return usageError("authorization-required: run `aw auth login --scope %s` before this command", cliAuthScopeTeamAdmission)
		}
	}
	previousScope := cliAuthScopeFlag
	cliAuthScopeFlag = cliAuthScopeTeamAdmission
	defer func() { cliAuthScopeFlag = previousScope }()
	parent := cmd.Context()
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithTimeout(parent, cliAuthLoginTimeout)
	defer cancel()
	loginCmd := cmd
	if jsonFlag {
		loginCmd = &cobra.Command{Use: cmd.Use}
		loginCmd.SetOut(os.Stderr)
		loginCmd.SetErr(cmd.ErrOrStderr())
	}
	return runAuthLogin(ctx, loginCmd)
}

func initInviteIdentityScope() string {
	return teamAcceptScopeFromGlobal(initGlobal)
}

func acceptInitInviteAndConnect(cmd *cobra.Command, workingDir, token, preferredAwebURL string) error {
	alias := resolveAliasValue(resolveInitLocalName())
	accepted, err := acceptAndStoreTeamInvite(workingDir, token, teamAcceptInviteOptions{
		Name:    alias,
		Scope:   initInviteIdentityScope(),
		AwebURL: strings.TrimSpace(preferredAwebURL),
	}, teamInviteStoreOptions{IdentityHome: currentEncryptionKeyIdentityHome(), SetActive: true})
	if err != nil {
		return err
	}
	awebURL := firstNonEmptyString(strings.TrimSpace(preferredAwebURL), strings.TrimSpace(accepted.AwebURL), strings.TrimSpace(accepted.Output.AwebURL))
	if awebURL == "" {
		return usageError("accepted invite did not include an aweb URL; rerun aw init with --aweb-url")
	}
	result, err := initCertificateConnectWithOptions(workingDir, awebURL, certificateConnectOptions{
		Role:      resolveRequestedRole(strings.TrimSpace(initRole)),
		HumanName: resolveHumanNameValue(strings.TrimSpace(initHumanName)),
		AgentType: resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
	})
	if err != nil {
		return err
	}
	printOutput(result, formatConnect)
	return nil
}

func resolveInitJoinSource(rawSource, explicitTeam string) (workingDir, identityHome, teamID string, err error) {
	source := strings.TrimSpace(rawSource)
	if source == "" {
		return "", "", "", usageError("--join-from is required")
	}
	clean, err := filepathAbs(source)
	if err != nil {
		return "", "", "", err
	}
	if info, statErr := os.Stat(filepath.Join(clean, ".aw")); statErr == nil && info.IsDir() {
		workingDir = clean
	} else {
		identityHome = clean
		workingDir = clean
	}
	teamID = strings.TrimSpace(explicitTeam)
	if teamID != "" {
		return workingDir, identityHome, teamID, nil
	}
	var state *awconfig.TeamState
	if identityHome != "" {
		state, err = awconfig.LoadTeamStateFromIdentityHome(identityHome)
	} else {
		state, err = awconfig.LoadTeamState(workingDir)
	}
	if err != nil {
		return "", "", "", fmt.Errorf("load --join-from team memberships: %w", err)
	}
	if len(state.Memberships) != 1 {
		ids := make([]string, 0, len(state.Memberships))
		for _, membership := range state.Memberships {
			ids = append(ids, membership.TeamID)
		}
		return "", "", "", usageError("--join-team is required when --join-from has %d team memberships (%s)", len(state.Memberships), strings.Join(ids, ", "))
	}
	return workingDir, identityHome, state.Memberships[0].TeamID, nil
}

func filepathAbs(path string) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func runInit(cmd *cobra.Command, args []string) error {
	if initSetupChannel && initSetupHooks {
		return fmt.Errorf("--setup-channel and --setup-hooks are mutually exclusive: the channel supersedes the notify hook")
	}
	if initInjectDocs && initDoNotTouchAgentsMD {
		return fmt.Errorf("--inject-docs and --do-not-touch-agents-md are mutually exclusive")
	}
	if err := validateInitInboundMode(); err != nil {
		return err
	}
	if err := validateInitOutcomeFlags(); err != nil {
		return err
	}
	if initWorkspaceTeam {
		return runInitWorkspaceTeam(cmd)
	}
	if strings.TrimSpace(initJoinFrom) != "" {
		return runInitJoinFrom(cmd)
	}
	if strings.TrimSpace(initAdmissionTeamID) != "" {
		return runInitAdmissionTeamID(cmd)
	}

	// When only --inject-docs, --setup-hooks, or --setup-channel are requested,
	// operate on the existing workspace without running the full init flow.
	if (initInjectDocs || initSetupHooks || initSetupChannel) && !initNeedsFullInitForAddonOnly() {
		wd, _ := os.Getwd()
		repoRoot := resolveRepoRoot(wd)
		if initInjectDocs {
			printInjectDocsResult(InjectAgentDocs(repoRoot))
		}
		if initSetupChannel {
			channelResult := SetupChannelMCP(repoRoot, initIsTTY())
			printChannelMCPResult(channelResult)
		}
		if initSetupHooks {
			hookResult := SetupClaudeHooks(repoRoot, initIsTTY())
			printClaudeHooksResult(hookResult)
		}
		return nil
	}

	if apiKey := resolveInitAPIKey(); apiKey != "" {
		wd, _ := os.Getwd()
		awebURL, err := resolveAPIKeyInitAwebURL()
		if err != nil {
			return err
		}
		registryURL, err := resolveInitAWIDRegistryURL()
		if err != nil {
			return err
		}
		identityHome, err := identityHomeForDir(wd)
		if err != nil {
			return err
		}
		result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
			WorkingDir:   wd,
			IdentityHome: identityHome.Root,
			AwebURL:      awebURL,
			RegistryURL:  registryURL,
			APIKey:       apiKey,
			Name:         resolveInitGlobalName(initGlobal),
			Alias:        resolveAliasValue(resolveInitLocalName()),
			Role:         resolveRequestedRole(strings.TrimSpace(initRole)),
			HumanName:    resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:    resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
			Global:       initGlobal,
			InboundMode:  canonicalInitInboundModeForWire(initInboundMode),
		})
		if err != nil {
			return err
		}
		printOutput(result, formatConnect)
		didInjectDocs := runDefaultInitDocsInjection(wd)
		if !jsonFlag {
			printPostInitActions(&initResult{
				ServerName:    hostFromBaseURL(result.AwebURL),
				ExportBaseURL: result.AwebURL,
				Alias:         strings.TrimSpace(result.Alias),
				APIKeyAuth:    true,
			}, wd, didInjectDocs)
		}
		return nil
	}

	// Certificate-based init: when a team certificate exists and a server URL is provided.
	{
		wd, _ := os.Getwd()
		if hasCertificateForInit(wd) {
			awebURL, err := resolveExplicitInitAwebURL()
			if err != nil {
				return err
			}
			serviceURLs, err := resolveOnboardingServiceURLs(awebURL)
			if err != nil {
				return err
			}
			result, err := initCertificateConnectWithOptions(wd, serviceURLs.AwebURL, certificateConnectOptions{
				Role: resolveRequestedRole(strings.TrimSpace(initRole)),
			})
			if err != nil {
				return err
			}
			printOutput(result, formatConnect)
			didInjectDocs := runDefaultInitDocsInjection(wd)
			if !jsonFlag {
				printPostInitActions(&initResult{
					ServerName:    hostFromBaseURL(serviceURLs.AwebURL),
					ExportBaseURL: serviceURLs.AwebURL,
					Alias:         strings.TrimSpace(result.Alias),
				}, wd, didInjectDocs)
			}
			return nil
		}
	}

	wd, _ := os.Getwd()
	workspaceMissing, err := initWorkspaceMissing(wd)
	if err != nil {
		return err
	}
	if workspaceMissing {
		canPrompt := initIsTTY() && !jsonFlag
		awebURL, err := resolveInitAwebURL()
		if err != nil {
			return err
		}
		registryURL, err := resolveInitAWIDRegistryURL()
		if err != nil {
			return err
		}
		if initShouldUseImplicitLocalFlow(registryURL) {
			if !initNewTeam {
				if err := requireOrPromptInitOutcome(canPrompt, "create a new self-hosted team", "--new-team"); err != nil {
					return err
				}
				if handled, err := runPromptedExplicitInitOutcome(cmd); handled || err != nil {
					return err
				}
			}
			result, err := initRunImplicitLocalFlow(implicitLocalInitRequest{
				WorkingDir:  wd,
				AwebURL:     awebURL,
				RegistryURL: registryURL,
				Alias:       resolveAliasValue(resolveInitLocalName()),
				Role:        resolveRequestedRole(strings.TrimSpace(initRole)),
				HumanName:   resolveHumanNameValue(strings.TrimSpace(initHumanName)),
				AgentType:   resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
			})
			if err != nil {
				if isRegistryUnavailableError(err) {
					return fmt.Errorf("local awid registry %s is not reachable; start the local stack (for example docker compose up) and retry: %w", registryURL, err)
				}
				return err
			}
			printOutput(result, formatConnect)
			didInjectDocs := runDefaultInitDocsInjection(wd)
			if !jsonFlag {
				printPostInitActions(&initResult{
					ServerName:    hostFromBaseURL(awebURL),
					ExportBaseURL: awebURL,
					Alias:         strings.TrimSpace(result.Alias),
				}, wd, didInjectDocs)
			}
			return nil
		}
		if initBYOD {
			if !initNewTeam {
				if err := requireOrPromptInitOutcome(canPrompt, "create a new BYOD team", "--new-team"); err != nil {
					return err
				}
				if handled, err := runPromptedExplicitInitOutcome(cmd); handled || err != nil {
					return err
				}
			}
		} else if !initNewAccount {
			if err := requireOrPromptInitOutcome(canPrompt, "create a new hosted account", "--new-account"); err != nil {
				return err
			}
			if handled, err := runPromptedExplicitInitOutcome(cmd); handled || err != nil {
				return err
			}
		}
		askPostCreateSetup := canPrompt && !initHasExplicitOnboardingArgs()
		result, err := guidedOnboardingWizard(guidedOnboardingRequest{
			WorkingDir:  wd,
			PromptIn:    os.Stdin,
			PromptOut:   os.Stderr,
			BaseURL:     awebURL,
			RegistryURL: registryURL,
			ServerName:  serverFlag,
			BYOD:        initBYOD,
			Username:    strings.TrimSpace(initUsername),
			Domain:      strings.TrimSpace(initDomain),
			Alias: func() string {
				if initGlobal {
					return strings.TrimSpace(initAlias)
				}
				return resolveAliasValue(resolveInitLocalName())
			}(),
			Name:               resolveInitGlobalName(initGlobal),
			HumanName:          resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:          resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
			Role:               resolveRequestedRole(strings.TrimSpace(initRole)),
			Global:             initGlobal,
			InboundMode:        canonicalInitInboundModeForWire(initInboundMode),
			InjectAgentDocs:    !initDoNotTouchAgentsMD && !jsonFlag,
			DoNotTouchAgentsMD: initDoNotTouchAgentsMD,
			AskPostCreateSetup: askPostCreateSetup,
			NonInteractive:     !canPrompt,
		})
		if err != nil {
			return err
		}
		if !jsonFlag {
			initPrintGuidedOnboardingReady(result)
		}
		return nil
	}
	return usageError("this directory already has a workspace; use a fresh directory")
}

func initHasExplicitOnboardingArgs() bool {
	values := []string{
		initUsername,
		initDomain,
		initAlias,
		initName,
	}
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return true
		}
	}
	return initBYOD || initGlobal
}

func resolveInitAwebURL() (string, error) {
	return normalizeAwebBaseURL(awebURLOrDefault(resolveInitAwebURLOverride()))
}

func resolveExplicitInitAwebURL() (string, error) {
	value := resolveInitAwebURLOverride()
	if value == "" {
		workingDir, err := os.Getwd()
		if err != nil {
			return "", err
		}
		discovered, ok, err := resolveDefaultCertificateInitAwebURL(workingDir)
		if err != nil {
			return "", err
		}
		if ok {
			return discovered, nil
		}
		return "", usageError("--aweb-url, --url, or AWEB_URL is required when using certificate auth (team certificate found under .aw/team-certs/)")
	}
	return normalizeAwebBaseURL(value)
}

func resolveDefaultCertificateInitAwebURL(workingDir string) (string, bool, error) {
	cert, _, err := loadCertificateForConnect(workingDir)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	teamDomain, _, err := awid.ParseTeamID(strings.TrimSpace(cert.Team))
	if err != nil {
		return "", false, fmt.Errorf("current team certificate has invalid team_id %q: %w", cert.Team, err)
	}
	if workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir); err == nil && workspace != nil {
		if awebURL := strings.TrimSpace(workspace.AwebURL); awebURL != "" {
			if workspace.Membership(strings.TrimSpace(cert.Team)) != nil || len(workspace.Memberships) == 0 {
				normalized, err := normalizeAwebBaseURL(awebURL)
				if err != nil {
					return "", false, fmt.Errorf("invalid aweb_url for team %s: %w", cert.Team, err)
				}
				return normalized, true, nil
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	if teamState, err := awconfig.LoadTeamState(workingDir); err == nil && teamState != nil {
		if membership := teamState.Membership(strings.TrimSpace(cert.Team)); membership != nil {
			if awebURL := strings.TrimSpace(membership.AwebURL); awebURL != "" {
				normalized, err := normalizeAwebBaseURL(awebURL)
				if err != nil {
					return "", false, fmt.Errorf("invalid aweb_url for team %s: %w", cert.Team, err)
				}
				return normalized, true, nil
			}
		}
	} else if err != nil && !os.IsNotExist(err) {
		return "", false, err
	}
	registryURL, err := resolveWorkspaceTeamRegistryURL(workingDir, "", teamDomain)
	if err != nil {
		if os.IsNotExist(err) {
			return "", false, nil
		}
		return "", false, err
	}
	if strings.TrimSpace(registryURL) != awid.DefaultAWIDRegistryURL {
		return "", false, nil
	}
	awebURL, err := cleanBaseURL(awebURLOrDefault("") + "/api")
	if err != nil {
		return "", false, err
	}
	return awebURL, true, nil
}

func resolveInitAwebURLOverride() string {
	value := strings.TrimSpace(initAwebURL)
	if value == "" {
		value = strings.TrimSpace(initURL)
	}
	if value == "" {
		value = strings.TrimSpace(os.Getenv("AWEB_URL"))
	}
	return value
}

func awebURLOrDefault(raw string) string {
	if value := strings.TrimSpace(raw); value != "" {
		return value
	}
	return DefaultAwebURL
}

func resolveInitAWIDRegistryURL() (string, error) {
	value := strings.TrimSpace(initAWIDRegistry)
	if value == "" {
		value = strings.TrimSpace(os.Getenv("AWID_REGISTRY_URL"))
	}
	if value == "" {
		value = awid.DefaultAWIDRegistryURL
	}
	if strings.EqualFold(value, "local") {
		return "", usageError("AWID_REGISTRY_URL=local is not supported by `aw init`; use an explicit localhost URL such as http://localhost:8010")
	}
	return cleanBaseURL(value)
}

func initBaseURLIsLocalhost(raw string) bool {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return false
	}
	host := strings.TrimSpace(u.Hostname())
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func initRegistryIsLocalhost(raw string) bool {
	return initBaseURLIsLocalhost(raw)
}

func initShouldUseImplicitLocalFlow(registryURL string) bool {
	if !initRegistryIsLocalhost(registryURL) {
		return false
	}
	// The implicit local flow is the compatibility path for a local aweb+awid
	// stack. Explicit onboarding inputs mean the user is asking for hosted/BYOD
	// semantics even if the test or dev stack happens to be on localhost.
	return !initBYOD &&
		strings.TrimSpace(initUsername) == "" &&
		strings.TrimSpace(initDomain) == "" &&
		!initGlobal
}

// initNeedsFullInitForAddonOnly returns true when an add-on request must
// escalate to full init because it changes identity/team state or has no
// existing workspace to operate on.
func initNeedsFullInitForAddonOnly() bool {
	if initBYOD || initUsername != "" || initDomain != "" || initAlias != "" || initName != "" || initRole != "" || initGlobal {
		return true
	}
	wd, _ := os.Getwd()
	missing, _ := initWorkspaceMissing(wd)
	return missing
}

func initWorkspaceMissing(workingDir string) (bool, error) {
	_, _, err := awconfig.LoadWorktreeWorkspaceFromDir(workingDir)
	if err == nil {
		return false, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("invalid local workspace binding: %w", err)
	}
	return true, nil
}

func printGuidedOnboardingReadyMessage(result *guidedOnboardingResult) {
	if result == nil {
		return
	}
	fmt.Println()
	fmt.Println("Workspace ready.")
	fmt.Println()
	fmt.Println("Tell your agent: please read https://aweb.ai/docs/cli-tutorial.md")
	fmt.Println()
	printChannelLaunchInstructions(os.Stdout)
}

func printChannelLaunchInstructions(out io.Writer) {
	fmt.Fprintln(out, "To use the channel directly inside Claude Code (real-time coordination),")
	fmt.Fprintln(out, "install the plugin once:")
	fmt.Fprintln(out, "  claude plugin marketplace add awebai/claude-plugins")
	fmt.Fprintln(out, "  claude plugin install aweb-channel@awebai-marketplace")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Then start Claude Code with this exact line:")
	fmt.Fprintln(out, "  claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace")
	fmt.Fprintln(out)
	for _, line := range channelLaunchWhyLines {
		fmt.Fprintln(out, line)
	}
	fmt.Fprintln(out)
	for _, line := range channelPiPathLines {
		fmt.Fprintln(out, line)
	}
}

// channelLaunchWhyLines explains why both flags are on the launch line. Channel
// messages are delivered to the session only in bypass-permissions mode today.
var channelLaunchWhyLines = []string{
	"Both flags are needed: channel messages are delivered to the session only in",
	"bypass-permissions mode today. In Claude Code's default auto mode (and plan",
	"mode) the notification arrives and is silently not surfaced, so without",
	"--dangerously-skip-permissions there are no wake-ups. Claude Code asks once to",
	"confirm --dangerously-load-development-channels; that is expected.",
}

// channelPiPathLines name Pi as the other maintained wake-up path.
var channelPiPathLines = []string{
	"Pi is the other maintained wake-up path:",
	"  pi install npm:@awebai/pi@latest",
	"Then start pi in the workspace. Mail and chat wake the session, with the",
	"sender's verification shown.",
}

func resolveHumanName() string {
	return resolveHumanNameValue(strings.TrimSpace(initHumanName))
}

func resolveHumanNameValue(value string) string {
	if v := strings.TrimSpace(value); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_HUMAN")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_HUMAN_NAME")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		return v
	}
	return "developer"
}

func resolveAgentType() string {
	return resolveAgentTypeValue(strings.TrimSpace(initAgentType))
}

func resolveAgentTypeValue(value string) string {
	if v := strings.TrimSpace(value); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_AGENT_TYPE")); v != "" {
		return v
	}
	return "agent"
}

func resolveInitLocalName() string {
	if value := strings.TrimSpace(initAlias); value != "" {
		return value
	}
	return strings.TrimSpace(initName)
}

func resolveInitGlobalName(global bool) string {
	if !global {
		return ""
	}
	return strings.TrimSpace(initName)
}

func resolveAliasValue(explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
}

// validateInitInboundMode enforces the aapl.7 contract on the
// --inbound-mode flag. The user-facing flag values use the
// hyphen-spelling CLI convention (open, team-and-contacts); the
// underscored canonical form (team_and_contacts) is the wire-level value
// translated by canonicalInitInboundModeForWire before the API call.
//
// Per Juan c2d25276: --inbound-mode is a real top-level flag of
// `aw init --global` and every supported global creation path
// (API-key bootstrap, guided hosted onboarding, BYOD) must forward
// the value into the create call. This validator only enforces the
// flag-shape contract; threading through the paths is the runner's
// responsibility.
//
// Two guards:
//
//  1. The flag is only meaningful for a global identity (--global);
//     local workspaces have no inbound delivery mode.
//  2. Only the two-value set {open, team-and-contacts} is canonical.
//     The stale contacts-only spelling is accepted as a compatibility
//     alias and normalized to team-and-contacts. The withdrawn value
//     "contacts_or_teammates" (or the hyphenated variant) must fail at
//     parse time so users copying stale commands see a clear error.
func validateInitInboundMode() error {
	value := strings.TrimSpace(initInboundMode)
	if value == "" {
		return nil
	}
	if !initGlobal {
		return fmt.Errorf("--inbound-mode is only valid with --global; local workspaces do not have an inbound delivery mode")
	}
	if initBYOD {
		// BYOD creates the team certificate locally; there is no
		// hosted creation endpoint at this stage to carry the
		// inbound_mode value. Fail fast instead of silently
		// dropping the user's choice (Juan c2d25276: "fail only
		// where the path genuinely cannot create/configure a
		// global identity"). The user can set the mode after the
		// BYOD identity is up via the dashboard's inbound-mode
		// surface or the hosted REST API
		// (`aw inbound-mode <mode>`).
		return fmt.Errorf("--inbound-mode is not supported on --byod global creation today (no server-side creation endpoint to carry the value); run `aw init --byod --global` first, then set the inbound mode from the dashboard or with `aw inbound-mode <open|team-and-contacts>`")
	}
	switch value {
	case "open":
		initInboundMode = "open"
		return nil
	case "team-and-contacts", "contacts-only":
		initInboundMode = "team-and-contacts"
		return nil
	}
	return fmt.Errorf("--inbound-mode must be one of {open, team-and-contacts}; got %q", value)
}

// canonicalInitInboundModeForWire translates the user-facing
// flag value into the canonical wire form expected by the API:
// "team-and-contacts" → "team_and_contacts". Returns "" when no value was set.
func canonicalInitInboundModeForWire(flag string) string {
	switch strings.TrimSpace(flag) {
	case "":
		return ""
	case "open":
		return "open"
	case "team-and-contacts", "contacts-only":
		return "team_and_contacts"
	}
	// Should be unreachable after validateInitInboundMode; defensive only.
	return strings.TrimSpace(flag)
}

func resolveRequestedRole(explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_ROLE_NAME")); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("AWEB_ROLE"))
}

func runDefaultInitDocsInjection(workingDir string) bool {
	if jsonFlag || initDoNotTouchAgentsMD || initInjectDocs {
		return false
	}
	repoRoot := resolveRepoRoot(workingDir)
	printInjectDocsResult(InjectAgentDocs(repoRoot))
	return true
}

func printPostInitActions(result *initResult, workingDir string, didDefaultInjectDocs bool) {
	if initPrintExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + result.ExportBaseURL)
		if strings.TrimSpace(result.Alias) != "" {
			fmt.Println("export AWEB_ALIAS=" + result.Alias)
		}
	}
	repoRoot := resolveRepoRoot(workingDir)
	if initInjectDocs {
		printInjectDocsResult(InjectAgentDocs(repoRoot))
	}
	if initSetupChannel {
		channelResult := SetupChannelMCP(repoRoot, isTTY())
		printChannelMCPResult(channelResult)
	}
	if initSetupHooks {
		hookResult := SetupClaudeHooks(repoRoot, isTTY())
		printClaudeHooksResult(hookResult)
	}
	if !jsonFlag {
		printInitNextSteps(result, workingDir, initInjectDocs || didDefaultInjectDocs, initSetupHooks, initSetupChannel)
	}
}

func printInitNextSteps(result *initResult, workingDir string, didInjectDocs, didSetupHooks, didSetupChannel bool) {
	lines := initNextStepLines(result, workingDir, didInjectDocs, didSetupHooks, didSetupChannel)
	if len(lines) == 0 {
		return
	}
	fmt.Println()
	fmt.Println("Next steps:")
	for _, line := range lines {
		fmt.Println(line)
	}
}

func initNextStepLines(result *initResult, workingDir string, didInjectDocs, didSetupHooks, didSetupChannel bool) []string {
	var lines []string

	if !didSetupChannel {
		lines = append(lines, formatInitNextStep("aw init --setup-channel", "Set up Claude Code channel for real-time coordination"))
	}
	if !didInjectDocs {
		lines = append(lines, formatInitNextStep("aw init --inject-docs", "Add coordination instructions to CLAUDE.md / AGENTS.md"))
	}
	if shouldSuggestClaimHuman(result) {
		lines = append(lines, formatInitNextStep("aw claim-human --email you@example.com", "Attach your human account for dashboard access"))
	}

	lines = append(lines, "")
	lines = append(lines, secondAgentNextStepLines...)
	lines = append(lines, "")
	lines = append(lines, "  Install the channel plugin once (real-time coordination in Claude Code):")
	lines = append(lines, "    claude plugin marketplace add awebai/claude-plugins")
	lines = append(lines, "    claude plugin install aweb-channel@awebai-marketplace")
	lines = append(lines, "")
	lines = append(lines, "  Then start Claude Code with this exact line:")
	lines = append(lines, "    claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace")
	lines = append(lines, "")
	for _, line := range channelLaunchWhyLines {
		lines = append(lines, "  "+line)
	}
	lines = append(lines, "")
	for _, line := range channelPiPathLines {
		lines = append(lines, "  "+line)
	}
	lines = append(lines, "")
	lines = append(lines, "  Tell your agent: please read https://aweb.ai/docs/cli-tutorial.md")
	return lines
}

// secondAgentNextStepLines tell the user how to put another agent in the team
// this init just joined. Running aw init again in another directory creates a
// separate account and team, whose agents cannot message this one.
var secondAgentNextStepLines = []string{
	"  Add another agent to THIS team (running aw init again elsewhere creates a",
	"  separate team whose agents cannot message this one):",
	"    aw team invite                        run here; prints a one-use token",
	"    aw team join <token> --name <name>    run in the other agent's directory",
	"    aw workspace add-worktree <role>      or, for a git worktree of this repo",
}

func formatInitNextStep(command, description string) string {
	return fmt.Sprintf("  %-36s %s", command, description)
}

func shouldSuggestClaimHuman(result *initResult) bool {
	if result == nil {
		return false
	}
	// API-key bootstrap implies the actor already has an account: API keys
	// are minted from authenticated contexts (dashboard or programmatic).
	// Suggesting claim-human in that case is misleading.
	if result.APIKeyAuth {
		return false
	}
	values := []string{result.ServerName, result.ExportBaseURL}
	for _, value := range values {
		lower := strings.ToLower(strings.TrimSpace(value))
		if lower == "" {
			continue
		}
		if strings.Contains(lower, "app.aweb.ai") || strings.Contains(lower, "aweb.ai") {
			return true
		}
	}
	return false
}

func normalizeAwebBaseURL(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func hostFromBaseURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}
