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
	Annotations: map[string]string{identityCreationTargetAnnotation: "true"},
	Use:         "init",
	Short:       "Initialize this directory as an aw workspace",
	Long: `Initialize the current directory using one of the supported
team-architecture flows:

- connect with an existing team certificate already present in .aw/
- add an agent to the existing team selected by AWEB_API_KEY
- create a hosted aweb.ai account when this directory is still clean
- use --byod to create an identity under a domain you control

By default, init creates or updates the clearly marked aweb section in
AGENTS.md or CLAUDE.md. Use --do-not-touch-agents-md to skip that file update.

A supplied AWEB_API_KEY, including a workspace key returned by CLI signup,
joins the team selected by the service. An aw team invite can also join it.
Creating a new account/team in a fresh directory creates a separate team.
Use aw team invite / aw team join to add a member to that team.

The channel plugin or host wake broker is the preferred notification path.
--setup-hooks explicitly enables a Claude Code chat-only polling fallback:
notices arrive after tool calls, with no mail or idle wake-up support.
After confirming channel/broker delivery, use --remove-notify-hook on its own
for backed-up removal of exact aw notify PostToolUse entries from the current
directory's and, inside a git repo, the repository root's .claude/settings.json.
Init and upgrades never remove them implicitly.

Use --join-from to create a child in a fresh directory from a selected native
creator workspace.`,
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
	initRemoveNotifyHook   bool
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
	initInvite             string
	initParent             string
	initJoinTeam           string
	initAdmissionTeamID    string
	initWorkspaceTeam      bool
	initWorkspaceKey       string
	initExpectedAccountID  string
	initNewAccount         bool
	initNewTeam            bool
	initTeam               string
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

	// ServerAssignedName records that API-key init omitted a requested name.
	ServerAssignedName bool

	// Path is the way init set this workspace up, which decides its next steps.
	Path initPath
}

// initPath is the way aw init set a workspace up.
type initPath string

const (
	initPathUnspecified initPath = ""
	// initPathNewTeam created a new account, team or namespace.
	initPathNewTeam initPath = "new_team"
	initPathAPIKey  initPath = "api_key"
	initPathJoined  initPath = "joined"
	// initPathReconnect connected an identity that already existed.
	initPathReconnect initPath = "reconnect"
)

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
	initCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Enable Claude Code chat-only polling after tool calls (explicit fallback; no mail or idle wake-ups)")
	initCmd.Flags().BoolVar(&initRemoveNotifyHook, "remove-notify-hook", false, "Remove only the exact aw notify PostToolUse hook from current directory and repository root settings, with backups (standalone local action)")
	initCmd.Flags().BoolVar(&initSetupChannel, "setup-channel", false, "Set up Claude Code aweb-channel plugin for real-time coordination")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (agents: explicit only; humans: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime label (default: AWEB_AGENT_TYPE or agent; human kind is verified by the server)")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Ensure .aw/context exists in the current directory")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	addWorkspaceRoleFlags(initCmd, &initRole, "Workspace role name (must match a role in the active team roles bundle)")
	initCmd.Flags().BoolVar(&initGlobal, "global", false, "Create an addressed self-custodial global identity instead of the default local workspace")
	initCmd.Flags().BoolVar(&initGlobal, "persistent", false, "Deprecated alias for --global")
	markDeprecatedHiddenFlag(initCmd, "persistent", "global")
	initCmd.Flags().StringVar(&initInboundMode, "inbound-mode", "", "Inbound delivery mode for a global identity (open|team-and-contacts|contacts-only). Only valid with --global.")
	initCmd.Flags().StringVar(&initInvite, "invite", "", "Join this invite with an independently selected creator")
	initCmd.Flags().String("token-file", "", "Read the join invitation from this private file instead of --invite")
	initCmd.Flags().Bool("token-stdin", false, "Read one join invitation from stdin through EOF (max 65536 bytes)")
	initCmd.Flags().StringVar(&initParent, "parent", "", "Same-machine creator home for a fresh child")
	initCmd.Flags().StringVar(&initJoinFrom, "join-from", "", "Add an agent to a team by minting one invite from this existing workspace or identity home")
	initCmd.Flags().StringVar(&initJoinTeam, "join-team", "", "Team ID to use with --join-from when the source has more than one membership")
	initCmd.Flags().StringVar(&initAdmissionTeamID, "admission-team-id", "", "Add an agent through host human admission for this explicit team ID")
	initCmd.Flags().String("org", "", "Organization slug or ID for --workspace-team")
	initCmd.Flags().BoolVar(&initWorkspaceTeam, "workspace-team", false, "Ensure a workspace's default team using explicit --identity-home and --workspace-key")
	initCmd.Flags().StringVar(&initWorkspaceKey, "workspace-key", "", "OATS canonical format-1 workspace key for --workspace-team")
	initCmd.Flags().StringVar(&initExpectedAccountID, "expect-account", "", "Expected hosted account ID for workspace-team or admission init")
	initCmd.Flags().BoolVar(&initNewAccount, "new-account", false, "Explicitly create a new hosted aweb.ai account")
	initCmd.Flags().BoolVar(&initNewTeam, "new-team", false, "Explicitly create a new self-hosted/BYOD team")
	initCmd.Flags().StringVar(&initTeam, "team", "", "Name of the team --new-team creates on a local (localhost) awid registry (default: default)")

	rootCmd.AddCommand(initCmd)
}

func addWorkspaceRoleFlags(cmd *cobra.Command, target *string, description string) {
	cmd.Flags().StringVar(target, "role-name", "", description)
	cmd.Flags().StringVar(target, "role", "", "Compatibility alias for --role-name")
}

func validateInitOutcomeFlags(input initInviteInput) error {
	if initParent != "" && initInvite == "" && !input.selected() {
		return usageError("--parent requires --invite; --join-from already selects its creator")
	}
	outcomes := initOutcomeFlagNames(input)
	if len(outcomes) > 1 {
		return usageError("init outcome flags are mutually exclusive: %s", strings.Join(outcomes, ", "))
	}
	if strings.TrimSpace(initJoinTeam) != "" && strings.TrimSpace(initJoinFrom) == "" {
		return usageError("--join-team requires --join-from")
	}
	if activeIdentityHome.Source == awconfig.IdentityHomeEnvVar && initWorkspaceTeam {
		return usageError("workspace-team creation requires an explicit --identity-home target; refusing to extend inherited identity home %s", activeIdentityHome.Root)
	}
	if strings.TrimSpace(initJoinFrom) != "" && activeIdentityHome.External() {
		if activeIdentityHome.Source != awconfig.IdentityHomeFlag {
			return usageError("join-from creation requires an explicit fresh --identity-home target; refusing to change inherited identity home %s", activeIdentityHome.Root)
		}
		return nil
	}
	if strings.TrimSpace(activeIdentityHome.Root) != "" && activeIdentityHome.External() && !initWorkspaceTeam {
		return usageError("aw init with --identity-home is only supported for --workspace-team or explicit fresh --join-from; refusing to use an external identity home for account, team, or add-agent init")
	}
	return nil
}

func initOutcomeFlagNames(input initInviteInput) []string {
	var outcomes []string
	if strings.TrimSpace(initInvite) != "" || input.selected() {
		outcomes = append(outcomes, "--invite")
	}
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

type initDispatchResult uint8

const (
	initDispatchDeferred initDispatchResult = iota
	initDispatchComplete
)

func dispatchExplicitInitOutcome(cmd *cobra.Command, input initInviteInput) (initDispatchResult, error) {
	if strings.TrimSpace(initInvite) != "" || input.selected() {
		return initDispatchComplete, runInitIndependentInvite(cmd, input)
	}
	if initWorkspaceTeam {
		return initDispatchComplete, runInitWorkspaceTeam(cmd)
	}
	if strings.TrimSpace(initJoinFrom) != "" {
		return initDispatchComplete, runInitJoinFrom(cmd)
	}
	if strings.TrimSpace(initAdmissionTeamID) != "" {
		return initDispatchComplete, runInitAdmissionTeamID(cmd)
	}
	return initDispatchDeferred, nil
}

type initIdentityInput struct {
	ContextFile workspaceContextPolicy
	Role        string
	HumanName   string
	AgentType   string
}

// initConnectIdentity normalizes requested display/runtime hints. A runtime
// label never establishes human kind (docs/identity.md); therefore both fresh
// creation and reconnect keep only an explicitly supplied human display name.
func initConnectIdentity(input initIdentityInput) certificateConnectOptions {
	return certificateConnectOptions{
		ContextFile: input.ContextFile,
		Role:        resolveRequestedRole(strings.TrimSpace(input.Role)),
		HumanName:   strings.TrimSpace(input.HumanName),
		AgentType:   resolveAgentTypeValue(strings.TrimSpace(input.AgentType)),
	}
}

func runInitWorkspaceTeam(cmd *cobra.Command) error {
	if strings.TrimSpace(activeIdentityHome.Root) == "" || !activeIdentityHome.External() {
		return usageError("--identity-home is required with --workspace-team")
	}
	if strings.TrimSpace(initWorkspaceKey) == "" {
		return usageError("--workspace-key is required with --workspace-team")
	}
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	org, err := workspaceTeamOrgFromCommand(cmd)
	if err != nil {
		return err
	}
	out, err := ensureWorkspaceTeam(cmd.Context(), workspaceTeamEnsureInput{
		WorkingDir: workingDir, Home: activeIdentityHome, Org: org,
		WorkspaceKey: strings.TrimSpace(initWorkspaceKey), Label: strings.TrimSpace(initName), ExpectedAccountID: strings.TrimSpace(initExpectedAccountID),
	})
	if err != nil {
		return err
	}
	return writeWorkspaceTeamEnsureOutput(cmd, out)
}

func runInitIndependentInvite(cmd *cobra.Command, input initInviteInput) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := ensureInitInviteTarget(wd); err != nil {
		return err
	}
	token, err := initInviteToken(cmd, input)
	if err != nil {
		return err
	}
	raw, origin, err := decodeJoinToken(token)
	if err != nil {
		return err
	}
	return acceptInitInviteAndConnect(cmd, initInviteConnection{WorkingDir: wd, Token: raw, PreferredAwebURL: origin, ParentHome: initParent})
}

func runInitJoinFrom(cmd *cobra.Command) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if home.External() && home.Source != awconfig.IdentityHomeFlag {
		return usageError("join-from creation requires an explicit fresh --identity-home target; refusing to change inherited identity home %s", home.Root)
	}
	return runRecoverableJoinFrom(cmd, wd, strings.TrimSpace(initJoinFrom), strings.TrimSpace(initJoinTeam))
}

func runInitAdmissionTeamID(cmd *cobra.Command) error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	if err := ensureInitInviteTarget(wd); err != nil {
		return err
	}
	if strings.TrimSpace(initExpectedAccountID) == "" {
		return usageError("--expect-account is required for --admission-team-id; run `aw auth status --scope %s --json` and choose the intended account", cliAuthScopeTeamAdmission)
	}
	if err := ensureTeamAdmissionAuthForInit(cmd); err != nil {
		return err
	}
	previousExpected := teamAdmissionInviteExpectedAccountID
	teamAdmissionInviteExpectedAccountID = strings.TrimSpace(initExpectedAccountID)
	defer func() { teamAdmissionInviteExpectedAccountID = previousExpected }()
	// Cloud's admission-invite route takes a UUID request_id for retry-safe issuance.
	requestID, err := newInvitationID()
	if err != nil {
		return err
	}
	alias := resolveAliasValue(resolveInitLocalName())
	resp, err := issueTeamAdmissionInviteForCreation(cmd.Context(), strings.TrimSpace(initAdmissionTeamID), requestID, alias, &awid.IDCreationIntent{Name: alias, IdentityScope: initInviteIdentityScope()})
	if err != nil {
		return err
	}
	return acceptInitInviteAndConnect(cmd, initInviteConnection{WorkingDir: wd, Token: resp.Token, PreferredAwebURL: resp.ServerURL})
}

// Admission init uses an existing cli.team_admission login and never starts
// one: a device login it chose a host for could authorize the wrong host.
func ensureTeamAdmissionAuthForInit(cmd *cobra.Command) error {
	cfg, ok, err := loadCLIAuthConfigForScope(cliAuthScopeTeamAdmission)
	if err != nil {
		return err
	}
	named := firstNonEmptyString(resolveInitAwebURLOverride(), strings.TrimSpace(serverFlag))
	if ok && named == "" {
		return nil
	}
	issuer, err := normalizeCLIAuthIssuer(awebURLOrDefault(named))
	if err != nil {
		return err
	}
	login := fmt.Sprintf("run `aw auth login --scope %s --server-name %s` first", cliAuthScopeTeamAdmission, issuer)
	if !ok {
		return usageError("authorization-required: no %s login for %s; %s", cliAuthScopeTeamAdmission, issuer, login)
	}
	stored, err := normalizeCLIAuthIssuer(cfg.Issuer)
	if err != nil {
		return err
	}
	if stored != issuer {
		return usageError("authorization-required: the stored %s login is for %s, not %s; %s", cliAuthScopeTeamAdmission, stored, issuer, login)
	}
	return nil
}

func initInviteIdentityScope() string {
	return string(inviteMemberScopeFromFlags(inviteMemberScopeFlags{Global: initGlobal}))
}

// Local init creates a key; global init reuses the selected identity and key.
// Neither is permission to replace an existing workspace binding.
func ensureInitInviteTarget(workingDir string) error {
	if !initGlobal {
		return ensureConnectTargetClean(workingDir)
	}
	if err := validateGlobalInitTarget(workingDir); err != nil {
		return err
	}
	return ensureAwebRuntimeGitIgnored(workingDir)
}

func validateGlobalInitTarget(workingDir string) error {
	if _, _, err := resolveGlobalIdentityForTeamAccept(workingDir, ""); err != nil {
		return err
	}
	path := awconfig.WorktreeWorkspacePath(workingDir)
	if _, err := os.Stat(path); err == nil {
		return usageError("refusing to overwrite existing %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

type initInviteConnection struct {
	ParentFromSource bool
	WorkingDir       string
	IdentityHome     string
	Token            string
	PreferredAwebURL string
	ParentHome       string
}

func acceptInitInviteAndConnect(cmd *cobra.Command, request initInviteConnection) error {
	workingDir := request.WorkingDir
	home, err := awconfig.ResolveIdentityHome(workingDir, firstNonEmptyString(request.IdentityHome, identityHomeFlag))
	if err != nil {
		return err
	}
	alias := resolveAliasValue(resolveInitLocalName())
	accepted, err := acceptAndStoreTeamInvite(teamInviteStoreRequest{
		Acceptance: teamInviteAcceptanceRequest{
			WorkingDir: workingDir,
			Token:      request.Token,
			Options: teamAcceptInviteOptions{
				IdentityHome:     externalIdentityHomeRoot(home),
				ParentHome:       request.ParentHome,
				ParentFromSource: request.ParentFromSource,
				Name:             alias,
				Scope:            initInviteIdentityScope(),
				AwebURL:          strings.TrimSpace(request.PreferredAwebURL),
				RegistryURL:      strings.TrimSpace(initAWIDRegistry),
			},
		},
		Store: teamInviteStoreOptions{IdentityHome: resolvedEncryptionKeyIdentityHome(home), Activation: membershipMakeActive},
	})
	if err != nil {
		return err
	}
	awebURL := acceptedInviteServiceURL(teamInviteConnectionTarget{Token: request.Token, PreferredURL: request.PreferredAwebURL, Accepted: accepted})
	if awebURL == "" {
		return usageError("accepted invite did not include an aweb URL; rerun aw init with --aweb-url")
	}
	return connectInitAcceptedInvite(cmd, workingDir, awebURL, home)
}

func connectInitAcceptedInvite(cmd *cobra.Command, workingDir, awebURL string, home awconfig.IdentityHome) error {
	identity := initConnectIdentity(initIdentityInput{ContextFile: requestedInitContextPolicy(), Role: initRole, HumanName: initHumanName, AgentType: initAgentType})
	result, err := initCertificateConnectWithOptions(workingDir, awebURL, certificateConnectOptions{
		IdentityHome: home.Root,
		ContextFile:  identity.ContextFile,
		Role:         identity.Role,
		HumanName:    identity.HumanName,
		AgentType:    identity.AgentType,
	})
	if err != nil {
		return err
	}
	resultInit := &initResult{
		ServerName:    hostFromBaseURL(awebURL),
		ExportBaseURL: awebURL,
		Alias:         strings.TrimSpace(result.Alias),
		Path:          initPathJoined,
	}
	return printInitOutcome(result, resultInit, workingDir, initDefaultSetup(resultInit, workingDir))
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
	identity := initConnectIdentity(initIdentityInput{ContextFile: requestedInitContextPolicy(), Role: initRole, HumanName: initHumanName, AgentType: initAgentType})
	if activeHuman != nil {
		return runHumanConnect(cmd)
	}
	if cmd.Flags().Changed("org") && !initWorkspaceTeam {
		return usageError("--org requires --workspace-team")
	}
	if strings.TrimSpace(initTeam) != "" {
		applies, err := initTeamFlagApplies()
		if err != nil {
			return err
		}
		if !applies {
			return initTeamFlagUsageError()
		}
	}
	if initRemoveNotifyHook {
		if len(args) != 0 {
			return usageError("--remove-notify-hook takes no positional arguments")
		}
		return runRemoveClaudeNotifyHook(cmd)
	}
	if initSetupChannel && initSetupHooks {
		return fmt.Errorf("--setup-channel and --setup-hooks are mutually exclusive: the channel supersedes the notify hook")
	}
	if initInjectDocs && initDoNotTouchAgentsMD {
		return fmt.Errorf("--inject-docs and --do-not-touch-agents-md are mutually exclusive")
	}
	if err := validateInitInboundMode(); err != nil {
		return err
	}
	input, err := readInitInviteInput(cmd)
	if err != nil {
		return err
	}
	if err := validateInitOutcomeFlags(input); err != nil {
		return err
	}
	creationDir, err := os.Getwd()
	if err != nil {
		return err
	}
	if resumed, err := resumeSignupFromInit(initSignupResumeInput{Command: cmd, WorkingDir: creationDir, Invite: input, Identity: identity}); resumed == initDispatchComplete || err != nil {
		return err
	}
	if dispatched, err := dispatchExplicitInitOutcome(cmd, input); dispatched == initDispatchComplete || err != nil {
		return err
	}

	// When only --inject-docs, --setup-hooks, or --setup-channel are requested,
	// operate on the existing workspace without running the full init flow.
	if initInjectDocs || initSetupHooks || initSetupChannel {
		needsFullInit, err := initNeedsFullInitForAddonOnly()
		if err != nil {
			return err
		}
		if !needsFullInit {
			return runInitAddons()
		}
	}

	apiKey := resolveInitAPIKey()
	if apiKey != "" {
		recovery, err := loadAPIKeyInitRecoveryForKey(apiKeyInitAuthorityPreflight{WorkingDir: creationDir, APIKey: apiKey})
		if err != nil {
			return err
		}
		return runInitFromAPIKey(cmd, initAPIKeySelection{WorkingDir: creationDir, APIKey: apiKey, Recovery: recovery})
	}

	if connected, err := runInitFromExistingCertificate(cmd); connected == initDispatchComplete || err != nil {
		return err
	}

	wd := creationDir
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
		if initNewTeam && !initBYOD && strings.TrimSpace(initUsername) == "" && strings.TrimSpace(initDomain) == "" && !initGlobal && !initRegistryIsLocalhost(registryURL) {
			return localNamespaceOnRemoteRegistry(registryURL)
		}
		if strings.TrimSpace(initTeam) != "" && !initShouldUseImplicitLocalFlow(registryURL) {
			return initTeamFlagUsageError()
		}
		if initShouldUseImplicitLocalFlow(registryURL) {
			if !initNewTeam {
				if err := requireOrPromptInitOutcome(canPrompt, "create a new self-hosted team", "--new-team"); err != nil {
					return err
				}
				if dispatched, err := dispatchExplicitInitOutcome(cmd, input); dispatched == initDispatchComplete || err != nil {
					return err
				}
			}
			result, err := initRunImplicitLocalFlow(implicitLocalInitRequest{
				ContextFile: identity.ContextFile, WorkingDir: wd,
				AwebURL:     awebURL,
				RegistryURL: registryURL,
				Alias:       resolveAliasValue(resolveInitLocalName()),
				TeamName:    strings.TrimSpace(initTeam),
				Role:        identity.Role,
				HumanName:   identity.HumanName,
				AgentType:   identity.AgentType,
			})
			if err != nil {
				if isRegistryUnavailableError(err) {
					return fmt.Errorf("local awid registry %s is not reachable; start the local stack (for example docker compose up) and retry: %w", registryURL, err)
				}
				return err
			}
			resultInit := &initResult{
				ServerName:    hostFromBaseURL(awebURL),
				ExportBaseURL: awebURL,
				Alias:         strings.TrimSpace(result.Alias),
				Path:          initPathNewTeam,
			}
			return printInitOutcome(result, resultInit, wd, initDefaultSetup(resultInit, wd))
		}
		if initBYOD {
			if !initNewTeam {
				if err := requireOrPromptInitOutcome(canPrompt, "create a new BYOD team", "--new-team"); err != nil {
					return err
				}
				if dispatched, err := dispatchExplicitInitOutcome(cmd, input); dispatched == initDispatchComplete || err != nil {
					return err
				}
			}
		} else if !initNewAccount {
			if err := requireOrPromptInitOutcome(canPrompt, "create a new hosted account", "--new-account"); err != nil {
				return err
			}
			if dispatched, err := dispatchExplicitInitOutcome(cmd, input); dispatched == initDispatchComplete || err != nil {
				return err
			}
		}
		askPostCreateSetup := canPrompt && !initHasExplicitOnboardingArgs()
		result, err := guidedOnboardingWizard(guidedOnboardingRequest{
			ContextFile: identity.ContextFile, WorkingDir: wd,
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
			Name:               resolveInitGlobalName(identityScopeFromFlags(identityScopeFlags{Global: initGlobal})),
			HumanName:          identity.HumanName,
			AgentType:          identity.AgentType,
			Role:               identity.Role,
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

func runInitAddons() error {
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
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

type initAPIKeySelection struct {
	WorkingDir string
	APIKey     string
	Recovery   *apiKeyPartialInitState
}

func runInitFromAPIKey(cmd *cobra.Command, selected initAPIKeySelection) error {
	identity := initConnectIdentity(initIdentityInput{ContextFile: requestedInitContextPolicy(), Role: initRole, HumanName: initHumanName, AgentType: initAgentType})
	// A roster request can omit agent_type. Preserve that exact wire choice
	// on native recovery unless the operator explicitly supplies a value.
	if selected.Recovery != nil && firstNonEmpty(initAgentType, os.Getenv("AWEB_AGENT_TYPE")) == "" {
		identity.AgentType = selected.Recovery.AgentType
	}
	wd, apiKey := selected.WorkingDir, selected.APIKey
	awebURL, err := resolveAPIKeyInitAwebURL()
	if err != nil {
		return err
	}
	registryURL, err := resolveConfiguredInitAWIDRegistryURL()
	if err != nil {
		return err
	}
	identityHome, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if identityHome.External() {
		identityHome = awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(wd)}
		oldHome := activeIdentityHome
		activeIdentityHome = identityHome
		defer func() { activeIdentityHome = oldHome }()
	}
	requestedAlias := resolveAliasValue(resolveInitLocalName())
	result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
		ContextFile:  identity.ContextFile,
		WorkingDir:   wd,
		IdentityHome: identityHome.Root,
		AwebURL:      awebURL,
		RegistryURL:  registryURL,
		APIKey:       apiKey,
		Name:         resolveInitGlobalName(identityScopeFromFlags(identityScopeFlags{Global: initGlobal})),
		Alias:        requestedAlias,
		Role:         identity.Role,
		HumanName:    identity.HumanName,
		AgentType:    identity.AgentType,
		Global:       initGlobal,
		InboundMode:  canonicalInitInboundModeForWire(initInboundMode),
	})
	if err != nil {
		return err
	}
	resultInit := &initResult{
		ServerName:         hostFromBaseURL(result.AwebURL),
		ExportBaseURL:      result.AwebURL,
		Alias:              strings.TrimSpace(result.Alias),
		APIKeyAuth:         true,
		ServerAssignedName: !initGlobal && requestedAlias == "",
		Path:               initPathAPIKey,
	}
	return printInitOutcome(result, resultInit, wd, initDefaultSetup(resultInit, wd))
}

func runInitFromExistingCertificate(cmd *cobra.Command) (initDispatchResult, error) {
	identity := initConnectIdentity(initIdentityInput{ContextFile: requestedInitContextPolicy(), Role: initRole, HumanName: initHumanName, AgentType: initAgentType})
	wd, err := os.Getwd()
	if err != nil {
		return initDispatchComplete, err
	}
	hasCertificate, err := hasCertificateForInit(wd)
	if err != nil {
		return initDispatchComplete, err
	}
	if hasCertificate {
		firstConnect, err := initWorkspaceMissing(wd)
		if err != nil {
			return initDispatchComplete, err
		}
		path := initPathReconnect
		if firstConnect {
			path = initPathJoined
		}
		awebURL, err := resolveExplicitInitAwebURL()
		if err != nil {
			return initDispatchComplete, err
		}
		serviceURLs, err := resolveOnboardingServiceURLs(awebURL)
		if err != nil {
			return initDispatchComplete, err
		}
		result, err := initCertificateConnectWithOptions(wd, serviceURLs.AwebURL, certificateConnectOptions{
			ContextFile: identity.ContextFile,
			Role:        identity.Role,
			HumanName:   identity.HumanName,
			AgentType:   identity.AgentType,
		})
		if err != nil {
			return initDispatchComplete, err
		}
		resultInit := &initResult{
			ServerName:    hostFromBaseURL(serviceURLs.AwebURL),
			ExportBaseURL: serviceURLs.AwebURL,
			Alias:         strings.TrimSpace(result.Alias),
			Path:          path,
		}
		return initDispatchComplete, printInitOutcome(result, resultInit, wd, initDefaultSetup(resultInit, wd))
	}
	return initDispatchDeferred, nil
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
	registryURL, err := resolveWorkspaceTeamRegistryURL(context.Background(), registryAuthorityRequest{
		WorkingDir: workingDir, Domain: teamDomain, TeamID: cert.Team,
	})
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
	return selectedAwebServiceURL(serviceURLSelection{AwebURL: initAwebURL, URL: initURL})
}

func awebURLOrDefault(raw string) string {
	if value := strings.TrimSpace(raw); value != "" {
		return value
	}
	return DefaultAwebURL
}

func resolveInitAWIDRegistryURL() (string, error) {
	value, err := resolveConfiguredInitAWIDRegistryURL()
	if err != nil || value != "" {
		return value, err
	}
	return awid.DefaultAWIDRegistryURL, nil
}

func resolveConfiguredInitAWIDRegistryURL() (string, error) {
	value, err := resolveRegistryURLSetting(registryURLSettingInput{ExplicitURL: initAWIDRegistry})
	if errors.Is(err, errLocalRegistryURL) {
		return "", usageError("AWID_REGISTRY_URL=local is not supported by `aw init`; use an explicit localhost URL such as http://localhost:8010")
	}
	if err != nil || value == "" {
		return value, err
	}
	return awid.CanonicalRegistryServerOrigin(value)
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
	// A local registry selects local team creation only when the command has
	// no explicit hosted/BYOD onboarding inputs.
	return !initBYOD &&
		strings.TrimSpace(initUsername) == "" &&
		strings.TrimSpace(initDomain) == "" &&
		!initGlobal
}

// initNeedsFullInitForAddonOnly returns true when an add-on request must
// escalate to full init because it changes identity/team state or has no
// existing workspace to operate on.
func initNeedsFullInitForAddonOnly() (bool, error) {
	if initBYOD || initUsername != "" || initDomain != "" || initAlias != "" || initName != "" || initRole != "" || initGlobal {
		return true, nil
	}
	wd, err := os.Getwd()
	if err != nil {
		return false, err
	}
	return initWorkspaceMissing(wd)
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
	fmt.Fprintln(commandStdout)
	fmt.Fprintln(commandStdout, "Workspace ready.")
}

// channelLaunchWhyLines distinguishes channel loading from permission mode.
var channelLaunchWhyLines = []string{
	"Channel delivery works in any permission mode, including auto and plan.",
	"Choose the permission mode that suits your workflow. Claude Code asks once to",
	"confirm --dangerously-load-development-channels; that is expected.",
}

// channelPiPathLines name Pi as the other maintained wake-up path.
var channelPiPathLines = []string{
	"Pi is the other maintained wake-up path:",
	"  pi install npm:@awebai/pi@latest",
	"Then start pi in the workspace. Mail and chat wake the session, with the",
	"sender's verification shown.",
}

func resolveAgentType() string {
	return resolveAgentTypeValue(strings.TrimSpace(initAgentType))
}

// Runtime hints never establish identity kind. The server verifies human kind.
func resolveAgentTypeValue(value string) string {
	v := strings.TrimSpace(value)
	if v == "" {
		v = strings.TrimSpace(os.Getenv("AWEB_AGENT_TYPE"))
	}
	if v == "" || v == "human" {
		return "agent"
	}
	return v
}

func resolveInitLocalName() string {
	if value := strings.TrimSpace(initAlias); value != "" {
		return value
	}
	return strings.TrimSpace(initName)
}

func resolveInitGlobalName(scope awid.IdentityScope) string {
	if scope != awid.IdentityScopeGlobal {
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

// validateInitInboundMode validates the global-only flag with the shared
// CLI-to-wire parser. Creation paths forward the chosen canonical mode.
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
		return fmt.Errorf("--inbound-mode is not supported on --byod global creation today (no server-side creation endpoint to carry the value); run `aw init --byod --global` first, then set the inbound mode from the dashboard or with `aw inbound-mode <open|team-and-contacts|contacts-only>`")
	}
	mode, err := normalizeInboundModeCLIValue(value)
	if err != nil {
		return err
	}
	initInboundMode = strings.ReplaceAll(mode, "_", "-")
	return nil
}

// canonicalInitInboundModeForWire returns the validated mode's wire spelling.
// Empty means the caller did not request a mode; defaults remain caller-owned.
func canonicalInitInboundModeForWire(flag string) string {
	if strings.TrimSpace(flag) == "" {
		return ""
	}
	mode, err := normalizeInboundModeCLIValue(flag)
	if err != nil {
		return strings.TrimSpace(flag)
	}
	return mode
}

// runDefaultInitDocsInjection writes the default aweb docs and returns what
// it did, or nil when init does not write them by default.
func runDefaultInitDocsInjection(workingDir string) *injectDocsResult {
	if jsonFlag || initDoNotTouchAgentsMD || initInjectDocs {
		return nil
	}
	result := InjectAgentDocs(resolveRepoRoot(workingDir))
	printInjectDocsResult(result)
	return result
}

func printPostInitActions(result *initResult, workingDir string) initSetupDone {
	var done initSetupDone
	if !jsonFlag && result.ServerAssignedName && strings.TrimSpace(result.Alias) != "" {
		fmt.Fprintf(commandStdout, "\nYour agent is named %s.\n", strings.TrimSpace(result.Alias))
	}
	if initPrintExports {
		fmt.Fprintln(commandStdout, "")
		fmt.Fprintln(commandStdout, "# Copy/paste to configure your shell:")
		fmt.Fprintln(commandStdout, "export AWEB_URL="+result.ExportBaseURL)
		if strings.TrimSpace(result.Alias) != "" {
			fmt.Fprintln(commandStdout, "export AWEB_ALIAS="+result.Alias)
		}
	}
	repoRoot := resolveRepoRoot(workingDir)
	if initInjectDocs {
		docs := InjectAgentDocs(repoRoot)
		printInjectDocsResult(docs)
		done.DocsInjected = docsInjected(docs)
	}
	if initSetupChannel {
		channelResult := SetupChannelMCP(repoRoot, isTTY())
		printChannelMCPResult(channelResult)
		done.ChannelSetUp = channelReady(channelResult)
		done.ChannelGuidancePrinted = channelResult != nil
	}
	if initSetupHooks {
		hookResult := SetupClaudeHooks(repoRoot, isTTY())
		printClaudeHooksResult(hookResult)
	}
	return done
}

// initNextStep is one thing to do after aw init: the exact command and why.
type initNextStep struct {
	Command string `json:"command"`
	Why     string `json:"why"`
}

const initGuideURL = "https://aweb.ai/docs/cli-tutorial.md"

// initSetupDone is what init's setup after connecting actually did.
type initSetupDone struct {
	DocsInjected bool
	ChannelSetUp bool
	// ChannelGuidancePrinted is set when channel setup already printed how to
	// start Claude Code with the channel and the Pi alternative.
	ChannelGuidancePrinted bool
}

// docsInjected reports whether docs injection wrote its instructions.
func docsInjected(result *injectDocsResult) bool {
	return result != nil && len(result.Errors) == 0
}

// channelReady reports whether channel setup installed the Claude Code
// plugin or found it already present.
func channelReady(result *claudeHooksResult) bool {
	return result != nil && result.Error == nil && !result.Skipped && (result.Created || result.Updated || result.AlreadyExists)
}

// printInitOutcome prints the connection, runs init's setup and then its
// next steps, so text output ends with the steps and the guide. --json
// prints one document.
func printInitOutcome(out connectOutput, result *initResult, workingDir string, setup func() (initSetupDone, error)) error {
	outputFailure := func(err error) error {
		if err == nil {
			return nil
		}
		return fmt.Errorf("write init result: %w. Check the output destination and inspect the connected identity before retrying init.", err)
	}
	if jsonFlag {
		done, err := setup()
		if err != nil {
			return err
		}
		out.NextSteps = initNextStepsAfter(result, workingDir, done)
		out.Guide = initGuideURL
		return outputFailure(printOutput(out, formatConnect))
	}
	outputErr := printOutput(out, formatConnect)
	done, err := setup()
	if err != nil {
		return errors.Join(err, outputFailure(outputErr))
	}
	if outputErr == nil {
		_, outputErr = fmt.Fprint(commandStdout, formatInitNextSteps(initNextStepsAfter(result, workingDir, done), !done.ChannelGuidancePrinted))
	}
	return outputFailure(outputErr)
}

// initDefaultSetup injects the default docs and runs the requested post-init
// actions.
func initDefaultSetup(result *initResult, workingDir string) func() (initSetupDone, error) {
	return func() (initSetupDone, error) {
		done := initSetupDone{DocsInjected: docsInjected(runDefaultInitDocsInjection(workingDir))}
		if !jsonFlag {
			post := printPostInitActions(result, workingDir)
			done.DocsInjected = done.DocsInjected || post.DocsInjected
			done.ChannelSetUp = post.ChannelSetUp
			done.ChannelGuidancePrinted = post.ChannelGuidancePrinted
		}
		return done, nil
	}
}

// initNextStepsAfter is the one list of next steps for the path init took,
// after what its setup actually did. Text and --json both print it.
func initNextStepsAfter(result *initResult, workingDir string, done initSetupDone) []initNextStep {
	path := initPathUnspecified
	if result != nil {
		path = result.Path
		if result.APIKeyAuth && (path == initPathUnspecified || path == initPathNewTeam) {
			path = initPathAPIKey
		}
	}
	steps := []initNextStep{{"aw workspace status", "Check that this agent reaches the server, and see who is on your team"}}
	if path == initPathNewTeam && shouldSuggestClaimHuman(result) {
		steps = append(steps,
			initNextStep{"aw mail send --to-address aweb.ai/aida --subject hello --body \"Hi Aida, I just joined aweb.\"", "Say hi to Aida, aweb's own agent: a first message to a public address"},
			initNextStep{"aw claim-human --email <your-email>", "Attach your person to this account; until then .aw/signing.key is its only recovery"},
		)
	}
	switch path {
	case initPathAPIKey:
		steps = append(steps, initNextStep{"aw team invite", "Add another agent to this team (or create one from the dashboard): run the join command it prints in that agent's folder"})
		steps = appendWorktreeStep(steps, workingDir)
	case initPathJoined:
		steps = append(steps, initNextStep{"aw mail send --to <teammate> --subject hello --body \"Hello\"", "Send your first message to a teammate"})
	case initPathNewTeam:
		joinFromWhy := "Run in another agent's folder on this machine to add it to this team"
		if initResultIsHosted(result) {
			joinFromWhy = "Run in another agent's folder to add it to THIS team; aw init there without --join-from creates a separate account and team instead"
		}
		steps = append(steps,
			initNextStep{"aw init --join-from " + formatShellCommand([]string{workingDir}) + " --name <name>", joinFromWhy},
			initNextStep{"aw team invite", "Or, for an agent on another machine: run the join command it prints in that agent's folder"},
		)
		steps = appendWorktreeStep(steps, workingDir)
	}
	if !done.ChannelSetUp {
		steps = append(steps, initNextStep{"aw init --setup-channel", "Install the aweb channel plugin for Claude Code, so messages wake this agent"})
	}
	if !done.ChannelGuidancePrinted {
		steps = append(steps, initNextStep{"claude --dangerously-load-development-channels " + claudeChannelSpec, "Start Claude Code with the channel loaded"})
	}
	if !done.DocsInjected {
		steps = append(steps, initNextStep{"aw init --inject-docs", "Add aweb instructions to CLAUDE.md / AGENTS.md"})
	}
	return steps
}

// appendWorktreeStep offers another worktree as another agent, inside a git
// worktree only.
func appendWorktreeStep(steps []initNextStep, workingDir string) []initNextStep {
	if _, err := currentGitWorktreeRootFromDir(workingDir); err != nil {
		return steps
	}
	return append(steps, initNextStep{"aw workspace add-worktree <role>", "Or add a git worktree of this repo as another agent"})
}

// formatInitNextSteps renders the next steps block for text output, with the
// channel guidance unless setup already printed it.
func formatInitNextSteps(steps []initNextStep, withChannelGuidance bool) string {
	if len(steps) == 0 {
		return ""
	}
	var sb strings.Builder
	sb.WriteString("\nNext steps:\n")
	for _, line := range initStepLines(steps, withChannelGuidance) {
		sb.WriteString(line + "\n")
	}
	return sb.String()
}

func initStepLines(steps []initNextStep, withChannelGuidance bool) []string {
	var lines []string
	for _, step := range steps {
		lines = append(lines, "  "+step.Command, "      "+step.Why)
	}
	lines = append(lines, "")
	if withChannelGuidance {
		for _, line := range channelLaunchWhyLines {
			lines = append(lines, "  "+line)
		}
		lines = append(lines, "")
		for _, line := range channelPiPathLines {
			lines = append(lines, "  "+line)
		}
		lines = append(lines, "")
	}
	lines = append(lines, "  Tell your agent: please read "+initGuideURL)
	return lines
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
	return initResultIsHosted(result)
}

// initResultIsHosted reports whether init connected to hosted aweb.ai.
func initResultIsHosted(result *initResult) bool {
	if result == nil {
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

func hostFromBaseURL(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return ""
	}
	return strings.ToLower(strings.TrimSpace(u.Hostname()))
}
