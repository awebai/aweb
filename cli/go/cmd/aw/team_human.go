package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var (
	teamHumanCreateBYOT            bool
	teamHumanCreateName            string
	teamHumanCreateNamespace       string
	teamHumanCreateDisplayName     string
	teamHumanCreateServiceURL      string
	teamHumanCreateRegistryURL     string
	teamHumanCreateAlias           string
	teamHumanCreateUsername        string
	teamHumanCreateFirstLocal      bool
	teamHumanCreateFirstGlobal     bool
	teamHumanInviteTeamID          string
	teamHumanRemoveTeamID          string
	teamHumanAgentStatusTeamID     string
	teamHumanRemoveRegistryURL     string
	teamHumanRemoveAwebURL         string
	teamHumanRemoveAPIKey          string
	teamHumanRemoveResumeOperation string
	teamHumanRemoveAbortOperation  string
	teamHumanRemoveListPending     bool
	teamHumanJoinNoConnect         bool
	teamHumanJoinHarness           string
	teamHumanJoinSetupOnly         bool
)

var teamHumanCmd = &cobra.Command{
	Use:   "team",
	Short: "Everyday team membership: invite, join, list, switch, and leave",
	Long: "Everyday team membership commands.\n\n" +
		"Use these commands to invite a member, join or leave a team, and inspect or\n" +
		"switch this identity's installed memberships. Team creation and owner/admin\n" +
		"repair operations live under `aw team admin`.",
}

const (
	teamGroupMembership      = "membership"
	teamGroupAdministration  = "administration"
	teamAdminGroupOperations = "team-administration"
)

var teamAdminCmd = &cobra.Command{
	Use:   "admin",
	Short: "Team creation and team administration",
	Long: "Team creation and team administration.\n\n" +
		"Use this surface to create a team, or to perform owner/admin inspection and\n" +
		"repair. These operations are separate from the everyday invite, join, list,\n" +
		"switch, and leave journey.",
}

// registerTeamAdminCommand makes the explicit admin path canonical while retaining
// the old aw team <command> path as a hidden compatibility alias. A shallow Cobra
// command copy is intentional: both paths share the exact flag set and handler, so
// compatibility cannot drift into a second implementation.
func registerTeamAdminCommand(cmd *cobra.Command, groupID string) {
	compatibilityAlias := *cmd
	compatibilityAlias.Hidden = true
	compatibilityAlias.GroupID = ""

	addTeamAdminCommand(cmd, groupID)
	teamHumanCmd.AddCommand(&compatibilityAlias)
}

// addTeamAdminCommand registers cmd only under aw team admin.
func addTeamAdminCommand(cmd *cobra.Command, groupID string) {
	cmd.GroupID = groupID
	teamAdminCmd.AddCommand(cmd)
}

var teamHumanCreateCmd = &cobra.Command{
	Annotations: map[string]string{hostHumanOrgAnnotation: "true"},
	Use:         "create <name>",
	Short:       "Create a team workspace",
	Long: "Create a team workspace with its first agent identity.\n\n" +
		"This wraps aw init for the aw-local path.\n\n" +
		"With --org, create a hosted team using human CLI authorization and return an invite.\n" +
		"This explicit mode creates no local identity or profile; accept the invite separately.\n\n" +
		"In a fresh directory, a supplied AWEB_API_KEY uses the service's workspace bootstrap.",
	Args: cobra.ExactArgs(1),
	RunE: runTeamHumanCreate,
}

var teamHumanInviteCmd = &cobra.Command{
	Use:   "invite",
	Short: "Invite an agent or workspace to the active team",
	Long: "Invite an agent or workspace to the active team.\n\n" +
		"This creates an invite token using the current team's authority for a separate\n" +
		"workspace or machine, then the joining workspace runs `aw team join <token>`.",
	Args: cobra.NoArgs,
	RunE: runTeamHumanInvite,
}

var teamHumanJoinCmd = &cobra.Command{
	Annotations: map[string]string{identityCreationTargetAnnotation: "true"},
	Use:         "join [invite-token | --token-file <path> | --token-stdin]",
	Short:       "Join a team from an invite token",
	Long: "Join a team from an invite token.\n\n" +
		"Run this in a clean target directory. It refuses to overwrite an existing\n" +
		".aw identity/key. Join installs the identity and membership, then connects this\n" +
		"workspace to the aweb service carried by the invite. Use --no-connect only when\n" +
		"you intentionally want identity state without a workspace binding.\n\n" +
		"Use --harness claude|codex|pi to install team docs; Claude and Pi also prepare delivery.\n" +
		"Codex reads mail when asked; for delivery as it arrives, run it under OATS.\n" +
		"This does not launch a session or verify message delivery. After a setup failure,\n" +
		"retry here with --setup-only --harness <harness>, without the invite token.",
	Args: validateTeamJoinArgs,
	RunE: runTeamHumanJoin,
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
	Use:   "remove-agent [member-address]",
	Short: "Retire an agent: release its claims, then revoke its certificate",
	Long: "Retire an agent from a team across the stores that hold its state.\n\n" +
		"It first deletes the agent's workspace record, which releases the task claims\n" +
		"held under it, and only then revokes its certificate. That order matters: an\n" +
		"agent can release its own claims until its certificate is revoked, and the\n" +
		"legacy hosted remove-member path can delete the same workspace record without\n" +
		"releasing anything. The prepared hosted-local path preserves the same order.\n\n" +
		"If the claims cannot be released the command stops before revoking and says\n" +
		"which store changed and which did not, rather than leaving an agent with no\n" +
		"credential and claims nobody can clear. To revoke access immediately and\n" +
		"accept that outcome, use `aw id team remove-member`.\n\n" +
		"Customer-controlled teams revoke with the local team controller key. Hosted\n" +
		"local members first prepare an immutable workspace/agent/certificate operation,\n" +
		"persist non-secret recovery state, release exact coordination state, and commit\n" +
		"cloud-mediated revocation. Use --resume-operation after a partial failure,\n" +
		"--list-pending when local recovery state is lost, or --abort-operation only\n" +
		"before release. Addressed/global hosted members retain the exact-certificate path.\n\n" +
		"STATUS VALUES. These are a contract; branch on them rather than on the prose.\n" +
		"Each says what its evidence supports, and the second column is the part that\n" +
		"matters, because the defect this command was built to remove was a status word\n" +
		"asserting more than the service had established.\n\n" +
		"  status (whole retirement)\n" +
		"    retired           every store reached the state retirement wants, and each\n" +
		"                      one established it. Exit 0.\n" +
		"    reported_retired  every store reached that state, but the certificate part\n" +
		"                      rests on a service reporting a no-op. It does NOT mean no\n" +
		"                      certificate exists. Exit 0. Confirm with agent-status.\n" +
		"    incomplete        a store did not reach that state; the per-store results\n" +
		"                      say which. Exit non-zero.\n\n" +
		"  certificate_result\n" +
		"    revoked                     this call revoked a certificate.\n" +
		"    already_revoked             the registry stated the certificate exists and\n" +
		"                                was already revoked. Only a registry says this;\n" +
		"                                it is never inferred from an absence.\n" +
		"    reported_nothing_to_revoke  the service reported it had nothing to revoke.\n" +
		"                                This says NOTHING about whether a certificate\n" +
		"                                exists: the hosted service answers from its own\n" +
		"                                membership records and may never consult the\n" +
		"                                registry, so a member holding a live certificate\n" +
		"                                with no hosted record is reported this way.\n\n" +
		"  per-store result: changed, unchanged, blocked, failed, not_attempted.\n" +
		"    changed and unchanged are terminal; the other three are not.\n\n" +
		"  claims_released is null when the server did not report a count, which is what\n" +
		"    a server older than that field does. Null is not zero.\n\n" +
		"Exit status answers one question only: did the request reach the service and get\n" +
		"an answer. It never carries a claim about certificate state. So on a\n" +
		"customer-controlled team, retiring a name that no longer resolves is an error\n" +
		"rather than a no-op, because that answer is indistinguishable from a request\n" +
		"that never arrived - while a registry saying already-revoked is success.",
	Args: validateTeamRemoveAgentArgs,
	RunE: runTeamHumanRemoveAgent,
}

func init() {
	teamHumanCmd.GroupID = groupIdentity
	teamHumanCmd.AddGroup(
		&cobra.Group{ID: teamGroupMembership, Title: "Everyday Membership"},
		&cobra.Group{ID: teamGroupAdministration, Title: "Advanced"},
	)
	teamAdminCmd.GroupID = teamGroupAdministration
	teamAdminCmd.AddGroup(
		&cobra.Group{ID: teamAdminGroupOperations, Title: "Team Administration"},
	)

	teamHumanCreateCmd.Flags().String("org", "", "Hosted organization slug or ID (requires aw auth login)")
	teamHumanCreateCmd.Flags().String("request-id", "", "Hosted create UUID (reuse to replay)")
	teamHumanCreateCmd.Flags().Bool("show-token", false, "Print the hosted invite token in text output")
	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateBYOT, "byot", false, "Create a customer-controlled AWID team with local namespace controller authority")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateName, "name", "", "Team name")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateNamespace, "namespace", "", "Namespace domain for --byot")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateDisplayName, "display-name", "", "Team display name")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateServiceURL, "service", "", "Hosted service URL for dashboard guidance")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateRegistryURL, "registry", "", "Registry origin override for --byot")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateAlias, "first-agent-name", "", "Initial workspace member name (defaults to <name>)")
	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateFirstLocal, "first-agent-local", false, "Enroll the first agent as a local team-scoped identity (default)")
	teamHumanCreateCmd.Flags().BoolVar(&teamHumanCreateFirstGlobal, "first-agent-global", false, "Enroll the first agent as a global identity, reusing an existing global identity or creating one when founding with hosted/namespace authority")
	teamHumanCreateCmd.Flags().StringVar(&teamHumanCreateUsername, "username", "", "Hosted username to create when founding through managed aweb onboarding")
	registerTeamAdminCommand(teamHumanCreateCmd, teamAdminGroupOperations)

	teamHumanInviteCmd.Flags().String("for-human", "", "Admit agents whose verified nearest human is this did:aw person")
	teamHumanInviteCmd.Flags().StringVar(&teamHumanInviteTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to invite from (defaults to active team)")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteMemberLocal, "member-local", false, "Create local workspace member invite (default)")
	teamHumanInviteCmd.Flags().BoolVar(&teamInviteMemberGlobal, "member-global", false, "Create global member invite")
	teamHumanInviteCmd.GroupID = teamGroupMembership
	teamHumanCmd.AddCommand(teamHumanInviteCmd)

	teamHumanJoinCmd.Flags().String("parent", "", "Same-machine creator home for a fresh child, independent of the invite")
	teamHumanJoinCmd.Flags().StringVar(&teamAcceptAlias, "name", "", "Member name for the accepting agent (defaults to identity name)")
	teamHumanJoinCmd.Flags().BoolVar(&teamAcceptLocal, "local", false, "Join with a local workspace identity (default)")
	teamHumanJoinCmd.Flags().BoolVar(&teamAcceptGlobal, "global", false, "Join by reusing the existing global identity in this workspace")
	teamHumanJoinCmd.Flags().BoolVar(&teamAcceptNoAddress, "no-address", false, "For --global, join with did:aw continuity but no member address")
	teamHumanJoinCmd.Flags().StringVar(&teamAcceptAddress, "address", "", "Advanced: existing owned address to place in the global member certificate")
	teamHumanJoinCmd.Flags().StringVar(&teamHumanJoinHarness, "harness", "", "Install team docs; prepare delivery for claude/pi (omitted: no harness changes)")
	teamHumanJoinCmd.Flags().BoolVar(&teamHumanJoinSetupOnly, "setup-only", false, "Retry harness setup for the connected identity without accepting an invite")
	teamHumanJoinCmd.Flags().BoolVar(&teamHumanJoinNoConnect, "no-connect", false, "Install identity and membership without connecting this workspace")
	teamHumanJoinCmd.Flags().String("token-file", "", "Read the invite token from this file instead of an argument")
	teamHumanJoinCmd.Flags().Bool("token-stdin", false, "Read the invite token from stdin instead of an argument")
	teamHumanJoinCmd.GroupID = teamGroupMembership
	teamHumanCmd.AddCommand(teamHumanJoinCmd)

	teamHumanListCmd.GroupID = teamGroupMembership
	teamHumanSwitchCmd.GroupID = teamGroupMembership
	teamHumanLeaveCmd.GroupID = teamGroupMembership
	teamHumanCmd.AddCommand(teamHumanListCmd)
	teamHumanCmd.AddCommand(teamHumanSwitchCmd)
	teamHumanCmd.AddCommand(teamHumanLeaveCmd)
	teamHumanAgentStatusCmd.Flags().StringVar(&teamHumanAgentStatusTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to read from (defaults to active team)")
	addTeamAdminCommand(teamHumanAgentStatusCmd, teamAdminGroupOperations)

	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveTeamID, "team-id", "", "Canonical team id (<name>:<namespace>) to remove from (defaults to active team)")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveRegistryURL, "registry", "", "Registry origin override")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveAwebURL, "aweb-url", "", "Hosted aweb API URL override for cloud-mediated removal")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveAPIKey, "api-key", "", "Team API key for hosted removal (overrides AWEB_API_KEY; workspace-bound API keys are rejected by hosted aweb)")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveResumeOperation, "resume-operation", "", "Resume exact hosted removal operation ID; no member address is accepted")
	teamHumanRemoveAgentCmd.Flags().StringVar(&teamHumanRemoveAbortOperation, "abort-operation", "", "Abort exact hosted removal operation ID before coordination release")
	teamHumanRemoveAgentCmd.Flags().BoolVar(&teamHumanRemoveListPending, "list-pending", false, "List owner/admin hosted removal operations requiring recovery")
	addTeamAdminCommand(teamHumanRemoveAgentCmd, teamAdminGroupOperations)
	teamHumanCmd.AddCommand(teamAdminCmd)
	rootCmd.AddCommand(teamHumanCmd)
}

type teamHumanCreateOutput struct {
	Status      string `json:"status"`
	TeamName    string `json:"team_name"`
	TeamID      string `json:"team_id,omitempty"`
	Alias       string `json:"alias,omitempty"`
	WorkspaceID string `json:"workspace_id,omitempty"`
	AwebURL     string `json:"aweb_url,omitempty"`
	RegistryURL string `json:"registry_url,omitempty"`
	HomeDir     string `json:"home_dir,omitempty"`
}

type teamHumanCreateFoundingResult struct {
	HumanOutput  *teamHumanCreateOutput
	TeamOutput   *teamCreateOutput
	GuidedResult *guidedOnboardingResult
}

func runTeamHumanCreate(cmd *cobra.Command, args []string) error {
	if cmd != nil && cmd.Flags().Changed("org") {
		return runOrgTeamCreate(cmd, args[0])
	}
	teamName := strings.TrimSpace(args[0])
	if teamName == "" {
		return usageError("team name is required")
	}
	wd, _ := os.Getwd()
	home, err := identityHomeForDir(wd)
	if err != nil {
		return err
	}
	if home.External() {
		return usageError("team admin create creates a first-agent identity; refusing to change selected identity home %s; use id team create for a sibling team", home.Root)
	}
	firstAgentScope, err := resolveTeamHumanCreateFirstAgentScope()
	if err != nil {
		return err
	}
	alias := strings.TrimSpace(teamHumanCreateAlias)
	if alias == "" {
		alias = strings.ToLower(teamName)
	}
	if teamHumanCreateBYOT {
		name := strings.TrimSpace(teamHumanCreateName)
		if name == "" {
			name = teamName
		}
		domain := awconfig.NormalizeDomain(teamHumanCreateNamespace)
		if domain == "" {
			return usageError("aw team admin create --byot requires --namespace")
		}
		if firstAgentScope == awid.IdentityModeGlobal {
			identityExists, err := teamCreateHasIdentityMaterial(wd)
			if err != nil {
				return err
			}
			if !identityExists {
				if err := bootstrapTeamCreateGlobalIdentity(globalIdentityBootstrap{WorkingDir: wd, Name: alias, Domain: domain, RegistryURL: strings.TrimSpace(teamHumanCreateRegistryURL)}); err != nil {
					return err
				}
			}
		}
		teamOut, err := foundTeamWithNamespaceControllerAuthority(namespaceTeamFounding{WorkingDir: wd, Name: name, CreatorAlias: alias, Domain: domain, RegistryURL: strings.TrimSpace(teamHumanCreateRegistryURL), DisplayName: strings.TrimSpace(teamHumanCreateDisplayName), CreatorScope: awid.IdentityScope(firstAgentScope)})
		if err != nil {
			return err
		}
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{TeamOutput: teamOut})
	}
	if strings.TrimSpace(teamHumanCreateNamespace) != "" || strings.TrimSpace(teamHumanCreateRegistryURL) != "" {
		return usageError("aw team admin create does not use --namespace or --registry without --byot")
	}
	identityExists, err := teamCreateHasIdentityMaterial(wd)
	if err != nil {
		return err
	}
	if identityExists {
		teamOut, err := foundTeamWithNamespaceControllerAuthority(namespaceTeamFounding{WorkingDir: wd, Name: teamName, CreatorAlias: alias, DisplayName: strings.TrimSpace(teamHumanCreateDisplayName), CreatorScope: awid.IdentityScope(firstAgentScope)})
		if err != nil {
			return err
		}
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{TeamOutput: teamOut})
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
		identityHome, err := identityHomeForDir(wd)
		if err != nil {
			return err
		}
		selectedRegistryURL, err := resolveConfiguredInitAWIDRegistryURL()
		if err != nil {
			return err
		}
		result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
			WorkingDir:   wd,
			IdentityHome: identityHome.Root,
			AwebURL:      apiKeyAwebURL,
			RegistryURL:  selectedRegistryURL,
			APIKey:       apiKey,
			Name:         apiName,
			Alias:        apiAlias,
			Global:       firstAgentGlobal,
			HumanName:    resolveHumanNameValue(initHumanName, resolveAgentType()),
			AgentType:    resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		})
		if err != nil {
			return err
		}
		out := teamHumanCreateOutputFromConnect(teamName, result, wd)
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HumanOutput: &out})
	}
	if !initShouldUseImplicitLocalFlow(registryURL) {
		guidedResult, err := runTeamHumanCreateHostedInitBundle(hostedTeamCreation{WorkingDir: wd, AwebURL: awebURL, RegistryURL: registryURL, Username: strings.TrimSpace(teamHumanCreateUsername), Alias: alias, Scope: awid.IdentityScope(firstAgentScope)})
		if err != nil {
			return err
		}
		return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{GuidedResult: guidedResult})
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
		HumanName:   resolveHumanNameValue(initHumanName, resolveAgentType()),
		AgentType:   resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
	})
	if err != nil {
		if isRegistryUnavailableError(err) {
			return fmt.Errorf("local awid registry %s is not reachable; start the local stack and retry: %w", registryURL, err)
		}
		return err
	}
	out := teamHumanCreateOutputFromConnect(teamName, result, wd)
	return finishTeamHumanCreateFounding(teamHumanCreateFoundingResult{HumanOutput: &out})
}

func finishTeamHumanCreateFounding(result teamHumanCreateFoundingResult) error {
	if result.HumanOutput != nil {
		if err := printOutput(*result.HumanOutput, formatTeamHumanCreate); err != nil {
			return err
		}
	}
	if result.TeamOutput != nil {
		if err := printOutput(*result.TeamOutput, formatTeamCreate); err != nil {
			return err
		}
	}
	if result.GuidedResult != nil && !jsonFlag {
		initPrintGuidedOnboardingReady(result.GuidedResult)
	}
	return nil
}

type globalIdentityBootstrap struct {
	WorkingDir  string
	Name        string
	Domain      string
	RegistryURL string
}

// bootstrapTeamCreateGlobalIdentity prepares the member's own durable identity;
// namespace authority authorizes its address, not its later creator attribution
// (docs/identity.md#1-claim-address).
func bootstrapTeamCreateGlobalIdentity(input globalIdentityBootstrap) error {
	domain := awconfig.NormalizeDomain(input.Domain)
	alias := input.Name
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
	_, err = executeIDCreate(input.WorkingDir, idCreateOptions{
		Name:        alias,
		Domain:      domain,
		RegistryURL: input.RegistryURL,
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

type hostedTeamCreation struct {
	WorkingDir  string
	AwebURL     string
	RegistryURL string
	Username    string
	Alias       string
	Scope       awid.IdentityScope
}

func runTeamHumanCreateHostedInitBundle(input hostedTeamCreation) (*guidedOnboardingResult, error) {
	canPrompt := initIsTTY() && !jsonFlag
	askPostCreateSetup := canPrompt && !initHasExplicitOnboardingArgs()
	firstAgentGlobal := input.Scope == awid.IdentityScopeGlobal
	requestAlias := input.Alias
	requestName := ""
	if firstAgentGlobal {
		requestAlias = ""
		requestName = input.Alias
	}
	req := guidedOnboardingRequest{
		WorkingDir:         input.WorkingDir,
		PromptIn:           os.Stdin,
		PromptOut:          os.Stderr,
		BaseURL:            input.AwebURL,
		RegistryURL:        input.RegistryURL,
		ServerName:         serverFlag,
		BYOD:               false,
		Username:           strings.TrimSpace(firstNonEmptyString(input.Username, initUsername)),
		Domain:             strings.TrimSpace(initDomain),
		Alias:              requestAlias,
		Name:               requestName,
		HumanName:          resolveHumanNameValue(initHumanName, resolveAgentType()),
		AgentType:          resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		Role:               resolveRequestedRole(strings.TrimSpace(initRole)),
		Global:             firstAgentGlobal,
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

type namespaceTeamFounding struct {
	WorkingDir   string
	Name         string
	CreatorAlias string
	Domain       string
	RegistryURL  string
	DisplayName  string
	CreatorScope awid.IdentityScope
}

// foundTeamWithNamespaceControllerAuthority uses namespace authority to found
// the team and controller authority to admit its creator as a member
// (docs/identity.md#2-create-team). Identity ancestry is independent.
func foundTeamWithNamespaceControllerAuthority(input namespaceTeamFounding) (*teamCreateOutput, error) {
	domain := awconfig.NormalizeDomain(input.Domain)
	identity, _, identityErr := awconfig.LoadWorktreeIdentityFromDir(input.WorkingDir)
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
	registry, err := newConfiguredRegistryClient(nil)
	if err != nil {
		return nil, err
	}
	ctx, cancel := commandAPIContext(nil)
	defer cancel()
	registryURL, err := resolveTeamCommandRegistry(ctx, registry, input.WorkingDir, domain, awid.BuildTeamID(domain, input.Name), input.RegistryURL)
	if err != nil {
		return nil, err
	}
	firstAgentAddress := ""
	if input.CreatorScope == awid.IdentityScopeGlobal && identityErr == nil && identity != nil {
		firstAgentAddress = strings.TrimSpace(identity.Address)
	}
	plan, err := resolveTeamMemberEnrollment(ctx, teamMemberEnrollmentResolveOptions{
		WorkingDir:        input.WorkingDir,
		TeamDomain:        domain,
		Name:              input.CreatorAlias,
		Address:           firstAgentAddress,
		Scope:             string(input.CreatorScope),
		RegistryURL:       registryURL,
		Registry:          registry,
		AllowLocalMint:    true,
		AllowDefaultClaim: false,
	})
	if err != nil {
		return nil, err
	}
	bootstrap, err := bootstrapTeamMembership(ctx, teamMembershipBootstrap{
		Registry: registry, RegistryURL: registryURL, Domain: domain,
		TeamName: input.Name, DisplayName: input.DisplayName, ControllerKey: controllerKey,
		Member: awid.TeamCertificateFields{
			MemberDIDKey: plan.MemberDIDKey, MemberDIDAW: plan.MemberDIDAW, MemberAddress: plan.MemberAddress,
			Alias: plan.Name, IdentityScope: plan.Scope,
		},
		NameFlag: "--first-agent-name",
	})
	if err != nil {
		return nil, err
	}
	certPath, err := awconfig.SaveTeamCertificateForTeam(input.WorkingDir, bootstrap.TeamID, bootstrap.Certificate)
	if err != nil {
		return nil, err
	}
	accepted := &teamAcceptInviteOutput{Status: "accepted", TeamID: bootstrap.TeamID, Alias: input.CreatorAlias, CertPath: certPath}
	awebURL, err := resolveInitAwebURL()
	if err != nil {
		return nil, err
	}
	// The creator self-enrolls as the team's first member and produces a
	// ready-to-run identity, so the worktree binding is written now.
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: input.WorkingDir, Output: accepted, Certificate: bootstrap.Certificate, RegistryURL: registryURL, RegistryOperatorOrigin: operatorRegistryOrigin(registryURL, ""), AwebURL: awebURL, IdentityHome: currentEncryptionKeyIdentityHome(), Activation: membershipMakeActive, Binding: membershipWriteWorkspaceBinding}); err != nil {
		return nil, err
	}
	return &teamCreateOutput{Status: "created", TeamID: bootstrap.TeamID, TeamDIDKey: bootstrap.TeamDIDKey, TeamKeyPath: bootstrap.TeamKeyPath, RegistryURL: registryURL}, nil
}

func teamHumanCreateOutputFromConnect(teamName string, result connectOutput, homeDir string) teamHumanCreateOutput {
	return teamHumanCreateOutput{
		Status:      "created",
		TeamName:    strings.TrimSpace(teamName),
		TeamID:      strings.TrimSpace(result.TeamID),
		Alias:       strings.TrimSpace(result.Alias),
		WorkspaceID: strings.TrimSpace(result.WorkspaceID),
		AwebURL:     strings.TrimSpace(result.AwebURL),
		HomeDir:     strings.TrimSpace(homeDir),
	}
}

func formatTeamHumanCreate(v any) string {
	out := v.(teamHumanCreateOutput)
	var b strings.Builder
	fmt.Fprintf(&b, "Created team %s", out.TeamName)
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
	teamRemoveCertID = ""
	teamRemoveRegistryURL = teamHumanRemoveRegistryURL
	teamRemoveAwebURL = teamHumanRemoveAwebURL
	teamRemoveAPIKey = teamHumanRemoveAPIKey

	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	client, _, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return err
	}
	// Member removal spans registry and coordination cascades; retain its explicit one-minute workflow budget.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if teamHumanRemoveListPending || strings.TrimSpace(teamHumanRemoveResumeOperation) != "" || strings.TrimSpace(teamHumanRemoveAbortOperation) != "" {
		if !isAwebHostedNamespace(domain) {
			return usageError("hosted removal recovery flags require an aweb-hosted team")
		}
		awebURL, apiKey, authErr := resolveHostedTeamRemoveAuth(workingDir, teamID)
		if authErr != nil {
			return authErr
		}
		switch {
		case teamHumanRemoveListPending:
			operations, listErr := listHostedRemovals(ctx, awebURL, apiKey, teamID)
			if listErr != nil {
				return listErr
			}
			if err := printOutput(operations, formatHostedRemovalList); err != nil {
				return err
			}
			return nil
		case strings.TrimSpace(teamHumanRemoveAbortOperation) != "":
			operationID := strings.TrimSpace(teamHumanRemoveAbortOperation)
			before, getErr := getHostedRemoval(ctx, awebURL, apiKey, teamID, operationID)
			if getErr != nil {
				return getErr
			}
			if err := validateHostedRemovalOperation(before, teamID, "", "", ""); err != nil || before.OperationID != operationID {
				if err != nil {
					return err
				}
				return fmt.Errorf("hosted removal get returned a different operation")
			}
			aborted, abortErr := abortHostedRemoval(ctx, awebURL, apiKey, teamID, operationID)
			if abortErr != nil {
				return abortErr
			}
			if err := validateHostedRemovalOperation(aborted, teamID, before.WorkspaceID, before.AgentID, before.CertificateID); err != nil {
				return err
			}
			if aborted.Status != "aborted" && aborted.Status != "committed" {
				return fmt.Errorf("hosted removal abort returned unexpected status %q", aborted.Status)
			}
			if err := clearHostedRemovalRecovery(workingDir, operationID); err != nil {
				return fmt.Errorf("hosted removal %s reached %s but local recovery cleanup failed: %w", operationID, aborted.Status, err)
			}
			if err := printOutput(aborted, formatHostedRemovalOperation); err != nil {
				return err
			}
			return nil
		default:
			operation, resumeErr := resumeHostedRemoval(ctx, client, workingDir, teamID, strings.TrimSpace(teamHumanRemoveResumeOperation))
			if resumeErr != nil {
				return resumeErr
			}
			if err := printOutput(operation, formatHostedRemovalOperation); err != nil {
				return err
			}
			return nil
		}
	}

	teamRemoveMember = strings.TrimSpace(args[0])
	memberDomain, alias, err := parseAddress(teamRemoveMember)
	if err != nil {
		return err
	}

	// Hosted local members use immutable W/A prepare before any coordination
	// write. Addressed/global and customer-controlled members retain their
	// existing exact-certificate paths.
	if isAwebHostedNamespace(domain) {
		workspace, resolveErr := resolveExactRetirementWorkspace(ctx, client, alias)
		if resolveErr != nil {
			return resolveErr
		}
		scope := ""
		if workspace.AgentIdentityScope != nil {
			scope = strings.TrimSpace(*workspace.AgentIdentityScope)
		}
		if scope == "" {
			return fmt.Errorf("hosted removal workspace did not report identity scope; refusing before coordination release")
		}
		if scope == "local" {
			if !strings.EqualFold(awconfig.NormalizeDomain(memberDomain), awconfig.NormalizeDomain(domain)) {
				return fmt.Errorf("local hosted member %s must be named in team namespace %s", alias, domain)
			}
			out, hostedErr := runHostedLocalRemoval(ctx, client, workingDir, teamID, teamRemoveMember, *workspace)
			if out.TeamID != "" {
				if err := printOutput(out, formatTeamRemoveAgent); err != nil {
					return err
				}
			}
			if hostedErr != nil || !retirementSucceeded(out.Status) {
				if hostedErr != nil {
					return &cliError{code: 1, msg: hostedErr.Error()}
				}
				return &cliError{code: 1, msg: fmt.Sprintf("%s is not fully retired; see the per-store results above", teamRemoveMember)}
			}
			return nil
		}
		if scope != "global" {
			return fmt.Errorf("hosted removal workspace has unsupported identity scope %q", scope)
		}
	}

	var verified *verifiedMember
	revoke := func(ctx context.Context) (certificateStoreResult, error) {
		return revokeHostedTeamCertificate(ctx, teamID, teamRemoveMember, "")
	}
	if !isAwebHostedNamespace(domain) {
		registry, err := newConfiguredRegistryClient(nil)
		if err != nil {
			return err
		}
		registryURL, err := resolveTeamCommandRegistry(ctx, registry, workingDir, domain, teamID, teamHumanRemoveRegistryURL)
		if err != nil {
			return err
		}
		signers, signersErr := teamReadSigners(workingDir, domain, name)
		if signersErr != nil {
			return signersErr
		}
		verified, err = verifyRetirementTarget(
			ctx, client, registry, registryURL, domain, name, teamRemoveMember, alias,
			signers,
		)
		if err != nil {
			return err
		}
		revoke = func(ctx context.Context) (certificateStoreResult, error) {
			return revokeVerifiedTeamCertificate(ctx, registry, registryURL, domain, name, teamID, verified)
		}
	}

	out := retireTeamAgent(ctx, client, teamID, teamRemoveMember, alias, verified != nil, revoke)
	if err := printOutput(out, formatTeamRemoveAgent); err != nil {
		return err
	}
	if !retirementSucceeded(out.Status) {
		return &cliError{code: 1, msg: fmt.Sprintf("%s is not fully retired; see the per-store results above", teamRemoveMember)}
	}
	return nil
}

func revokeVerifiedTeamCertificate(ctx context.Context, registry *awid.RegistryClient, registryURL, domain, team, teamID string, verified *verifiedMember) (certificateStoreResult, error) {
	teamKey, err := awconfig.LoadTeamKey(domain, team)
	if err != nil {
		return certificateStoreResult{}, fmt.Errorf("load team key for %s: %w", teamID, err)
	}
	// No lookup here. The member was resolved and verified once, before anything
	// was written, and its certificate id was carried forward - see verifiedMember.
	if verified == nil {
		return certificateStoreResult{}, fmt.Errorf("refusing to revoke on %s without an established member", teamID)
	}
	result, err := revokeRegistryTeamCertificate(
		ctx, registry, registryURL, domain, team, verified.CertificateID, teamKey,
	)
	if err != nil {
		return certificateStoreResult{}, err
	}
	// Report the address the registry returned for the certificate that was
	// revoked, not the string that was typed.
	result.MemberAddress = verified.MemberAddress
	return result, nil
}

func activeTeamIDForHumanTeamCommand() (string, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return "", err
	}
	if awconfig.IsGrantHome(home.Root) {
		grant, err := awconfig.LoadGrantHome(home.Root)
		if err != nil {
			return "", err
		}
		return grant.TeamID, nil
	}
	if teamState, err := loadSelectedTeamState(workingDir, home); err == nil && teamState != nil && strings.TrimSpace(teamState.ActiveTeam) != "" {
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
