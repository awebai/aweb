package main

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize this directory in an existing project",
	Long: `Initialize the current directory as another agent workspace inside an
existing aweb project.

Use this when you already have a project-scoped API key. Human users
normally start with aw run <provider>; aw init is the explicit
existing-project bootstrap primitive.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat for init — no credentials yet.
	},
	RunE: runInit,
}

var (
	initCloudURL       string
	initHosted         bool
	initHostedUsername string
	initHostedAWIDURL  string
	initProjectSlug    string
	initNamespaceSlug  string
	initAlias          string
	initName           string
	initReachability   string
	initInjectDocs     bool
	initSetupHooks     bool
	initSetupChannel   bool
	initHumanName      string
	initAgentType      string
	initWriteContext   bool
	initPrintExports   bool
	initRole           string
	initPermanent      bool
)

var (
	initResolveBaseURLForCollection  = resolveBaseURLForInit
	initFetchSuggestionForCollection = fetchInitSuggestion
	initIsTTY                        = isTTY
	initPrintGuidedOnboardingReady   = printGuidedOnboardingReadyMessage
)

// initFlow identifies which clean-slate workspace/identity creation path to use.
type initFlow int

const (
	// flowHeadless creates a project plus its first workspace identity.
	flowHeadless initFlow = iota

	// flowProjectKey initializes a workspace inside an existing project using
	// project authority.
	flowProjectKey

	// flowInvite accepts a spawn invite into another workspace.
	flowInvite
)

type initOptions struct {
	Flow                      initFlow
	WorkingDir                string
	PromptIn                  io.Reader
	PromptOut                 io.Writer
	BaseURL                   string
	ServerName                string
	ProjectSlug               string
	NamespaceSlug             string
	IdentityAlias             string
	IdentityName              string
	AddressReachability       string
	HumanName                 string
	AgentType                 string
	WriteContext              bool
	AuthToken                 string // Bearer token for the selected flow
	InviteToken               string
	WorkspaceRole             string
	PromptAliasAfterBootstrap bool
	PromptRoleAfterBootstrap  bool
	Lifetime                  string // "ephemeral" (default) or "persistent"
}

type initCollectionInput struct {
	WorkingDir       string
	Interactive      bool
	JSONOutput       bool
	PromptIn         io.Reader
	PromptOut        io.Writer
	CloudURL         string
	ServerName       string
	ProjectSlug      string
	NamespaceSlug    string
	Alias            string
	Name             string
	Reachability     string
	HumanName        string
	AgentType        string
	WriteContext     bool
	Role             string
	Permanent        bool
	PromptRole       bool
	PromptName       bool
	DeferAliasPrompt bool
	DeferRolePrompt  bool
	AuthToken        string
	InviteToken      string
}

type initResult struct {
	Response        *awid.BootstrapIdentityResponse
	ServerName      string
	Role            string
	AttachResult    *contextAttachResult
	SigningKeyPath  string
	ExportBaseURL   string
	ExportNamespace string
	JoinedViaInvite bool
}

func init() {
	initCmd.Flags().StringVar(&initCloudURL, "cloud-url", "", "Base URL for aweb-cloud. The CLI discovers the aweb and awid URLs from this via GET /api/v1/discovery.")
	initCmd.Flags().BoolVar(&initHosted, "hosted", false, "Create a hosted aweb.ai identity in this directory")
	initCmd.Flags().StringVar(&initHostedUsername, "username", "", "Hosted username to create with --hosted")
	initCmd.Flags().StringVar(&initHostedAWIDURL, "awid-url", "", "Override the awid registry URL for hosted init automation")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initName, "name", "", "Permanent identity name (required with --permanent unless .aw/identity.yaml already exists)")
	initCmd.Flags().StringVar(&initReachability, "reachability", "", "Permanent address reachability (private|org-visible|contacts-only|public)")
	initCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	initCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	initCmd.Flags().BoolVar(&initSetupChannel, "setup-channel", false, "Set up Claude Code channel MCP server for real-time coordination")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Ensure .aw/context exists in the current directory")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	addWorkspaceRoleFlags(initCmd, &initRole, "Workspace role name (must match a role in the active project roles bundle)")
	initCmd.Flags().BoolVar(&initPermanent, "permanent", false, "Create a durable self-custodial identity instead of the default ephemeral identity")

	rootCmd.AddCommand(initCmd)
}

func addWorkspaceRoleFlags(cmd *cobra.Command, target *string, description string) {
	cmd.Flags().StringVar(target, "role-name", "", description)
	cmd.Flags().StringVar(target, "role", "", "Compatibility alias for --role-name")
}

func runInit(cmd *cobra.Command, args []string) error {
	if initSetupChannel && initSetupHooks {
		return fmt.Errorf("--setup-channel and --setup-hooks are mutually exclusive: the channel supersedes the notify hook")
	}

	// When only --inject-docs, --setup-hooks, or --setup-channel are requested,
	// operate on the existing workspace without running the full init flow.
	if (initInjectDocs || initSetupHooks || initSetupChannel) && !initNeedsFullInit() {
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

	// Certificate-based init: when a team certificate exists and a cloud URL is provided.
	{
		wd, _ := os.Getwd()
		if hasCertificateForInit(wd) {
			cloudURL := strings.TrimSpace(initCloudURL)
			if cloudURL == "" {
				cloudURL = strings.TrimSpace(os.Getenv("AWEB_URL"))
			}
			if cloudURL == "" {
				return usageError("--cloud-url or AWEB_URL is required when using certificate auth (team certificate found at .aw/team-cert.pem)")
			}
			serviceURLs, err := resolveOnboardingServiceURLs(cloudURL)
			if err != nil {
				return err
			}
			result, err := initCertificateConnectWithOptions(wd, serviceURLs.AwebURL, certificateConnectOptions{
				Role:     resolveRequestedRole(strings.TrimSpace(initRole)),
				CloudURL: serviceURLs.CloudURL,
				AwidURL:  serviceURLs.AwidURL,
			})
			if err != nil {
				return err
			}
			printOutput(result, formatConnect)
			return nil
		}
	}

	if hostedInitRequested() {
		return runHostedInit(cmd)
	}

	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) == "" {
		wd, _ := os.Getwd()
		workspaceMissing, err := initWorkspaceMissing(wd)
		if err != nil {
			return err
		}
		if workspaceMissing {
			if !initIsTTY() {
				return usageError("current directory is not initialized for aw; rerun `aw init` in a TTY for guided onboarding or get a team certificate first with `aw id team accept-invite`")
			}
			result, err := guidedOnboardingWizard(guidedOnboardingRequest{
				WorkingDir: wd,
				PromptIn:   os.Stdin,
				PromptOut:  os.Stderr,
				CloudURL:   initCloudURL,
				ServerName: serverFlag,
				Alias: func() string {
					if initPermanent {
						return strings.TrimSpace(initAlias)
					}
					return resolveAliasValue(strings.TrimSpace(initAlias))
				}(),
				Name:               strings.TrimSpace(initName),
				Reachability:       strings.TrimSpace(initReachability),
				HumanName:          resolveHumanNameValue(strings.TrimSpace(initHumanName)),
				AgentType:          resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
				Role:               resolveRequestedRole(strings.TrimSpace(initRole)),
				AskPostCreateSetup: true,
			})
			if err != nil {
				return err
			}
			if !jsonFlag {
				initPrintGuidedOnboardingReady(result)
			}
			return nil
		}
		return usageError("this directory already has a workspace; set AWEB_API_KEY to reinitialize it or use a fresh directory")
	}

	opts, err := collectInitOptionsForFlow(flowProjectKey)
	if err != nil {
		return err
	}
	result, err := executeInit(opts)
	if err != nil {
		return err
	}

	if jsonFlag {
		printJSON(result.Response)
	} else {
		printInitSummary(result.Response, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, opts.WorkingDir, "Initialized workspace")
	}
	printPostInitActions(result, opts.WorkingDir)
	return nil
}

func hostedInitRequested() bool {
	return initHosted || strings.TrimSpace(initHostedUsername) != "" || strings.TrimSpace(initHostedAWIDURL) != ""
}

// initNeedsFullInit returns true if the user passed flags that require the
// full init flow, or if no local workspace binding exists yet (first-time init).
func initNeedsFullInit() bool {
	if initCloudURL != "" || initAlias != "" || initName != "" || initReachability != "" || initRole != "" || initPermanent {
		return true
	}
	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) != "" {
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
	if result == nil || strings.TrimSpace(result.InitialPrompt) == "" {
		return
	}
	fmt.Println()
	fmt.Println("Workspace ready.")
	fmt.Println("Start your agent here with:")
	fmt.Println("  aw run claude")
	fmt.Println("  aw run codex")
	fmt.Println("Ask it to read the agent guide at https://aweb.ai/agent-guide.txt")
}

func collectInitOptionsForFlow(flow initFlow) (initOptions, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return initOptions{}, err
	}
	return collectInitOptionsWithInput(flow, initCollectionInput{
		WorkingDir:    workingDir,
		Interactive:   isTTY(),
		JSONOutput:    jsonFlag,
		PromptIn:      os.Stdin,
		PromptOut:     os.Stderr,
		CloudURL:      initCloudURL,
		ServerName:    serverFlag,
		ProjectSlug:   resolveProjectSlug(),
		NamespaceSlug: resolveExplicitNamespaceSlug(),
		Alias: func() string {
			if initPermanent {
				return strings.TrimSpace(initAlias)
			}
			return resolveAliasValue(strings.TrimSpace(initAlias))
		}(),
		Name:         strings.TrimSpace(initName),
		Reachability: strings.TrimSpace(initReachability),
		HumanName:    resolveHumanNameValue(strings.TrimSpace(initHumanName)),
		AgentType:    resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
		WriteContext: initWriteContext,
		Role:         resolveRequestedRole(strings.TrimSpace(initRole)),
		Permanent:    initPermanent,
		AuthToken:    strings.TrimSpace(os.Getenv("AWEB_API_KEY")),
	})
}

func collectInviteInitOptionsWithInput(token string, input initCollectionInput) (initOptions, error) {
	token = strings.TrimSpace(token)
	if !strings.HasPrefix(token, "aw_inv_") {
		return initOptions{}, usageError("invalid invite token (expected aw_inv_...)")
	}
	input.InviteToken = token
	return collectInitOptionsWithInput(flowInvite, input)
}

func validateInitIdentityFlags() error {
	return validateInitIdentityOptions(initPermanent, strings.TrimSpace(initAlias), strings.TrimSpace(initName), strings.TrimSpace(initReachability))
}

func validateInitIdentityOptions(permanent bool, alias, name, reachabilityRaw string) error {
	reachability := normalizeAddressReachability(strings.TrimSpace(reachabilityRaw))
	if strings.TrimSpace(reachabilityRaw) != "" && reachability == "" {
		return usageError("invalid --reachability (use private|org-visible|contacts-only|public)")
	}
	if permanent {
		if alias != "" {
			return usageError("--alias cannot be used with --permanent; use --name")
		}
		if name == "" {
			return usageError("--name is required with --permanent")
		}
		return nil
	}
	if name != "" {
		return usageError("--name can only be used with --permanent")
	}
	if reachability != "" {
		return usageError("--reachability can only be used with --permanent")
	}
	return nil
}

func normalizeAddressReachability(raw string) string {
	switch strings.TrimSpace(strings.ToLower(raw)) {
	case "":
		return ""
	case "private":
		return "private"
	case "org-visible":
		return "org-visible"
	case "contacts-only":
		return "contacts-only"
	case "public":
		return "public"
	default:
		return ""
	}
}

func resolveProjectSlug() string {
	if v := strings.TrimSpace(initProjectSlug); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_PROJECT_SLUG")); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_PROJECT")); v != "" {
		return v
	}
	return ""
}

func resolveExplicitNamespaceSlug() string {
	if v := strings.TrimSpace(initNamespaceSlug); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_NAMESPACE_SLUG")); v != "" {
		return v
	}
	return ""
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

func resolveAliasValue(explicit string) string {
	if v := strings.TrimSpace(explicit); v != "" {
		return v
	}
	return strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
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

func initRequiresWorkspaceRole(workingDir string, writeContext bool) bool {
	if !writeContext {
		return false
	}
	_, err := currentGitWorktreeRootFromDir(workingDir)
	return err == nil
}

func resolveRoleInput(requested string, suggestedRoles []string, allowPrompt bool, promptFreeform bool, in io.Reader, out io.Writer) (string, error) {
	requested = normalizeWorkspaceRole(requested)
	if len(suggestedRoles) > 0 {
		return selectRoleFromAvailableRoles(requested, suggestedRoles, allowPrompt && requested == "", in, out)
	}
	if requested != "" {
		if !isValidWorkspaceRole(requested) {
			return "", usageError("invalid role %q", requested)
		}
		return requested, nil
	}
	if !allowPrompt {
		return "", nil
	}
	if !promptFreeform {
		return "", nil
	}
	role, err := promptRequiredStringWithIO("Role", "developer", in, out)
	if err != nil {
		return "", err
	}
	role = normalizeWorkspaceRole(role)
	if !isValidWorkspaceRole(role) {
		return "", usageError("invalid role %q", role)
	}
	return role, nil
}

func promptIdentityLifetime(in io.Reader, out io.Writer) (bool, error) {
	fmt.Fprintf(out, "  1. Ephemeral — workspace-bound, for internal coordination\n")
	fmt.Fprintf(out, "  2. Permanent — survives beyond this workspace, can own public addresses\n")
	reader := bufferedPromptReader(in)
	for {
		fmt.Fprintf(out, "Identity type [1]: ")
		line, err := reader.ReadString('\n')
		if err != nil {
			return false, err
		}
		line = strings.TrimSpace(line)
		switch line {
		case "", "1":
			return false, nil
		case "2":
			return true, nil
		default:
			fmt.Fprintf(out, "Enter 1 or 2.\n")
		}
	}
}

func collectInitOptionsWithInput(flow initFlow, input initCollectionInput) (initOptions, error) {
	if input.PromptIn == nil {
		input.PromptIn = os.Stdin
	}
	if input.PromptOut == nil {
		input.PromptOut = os.Stderr
	}
	if strings.TrimSpace(input.WorkingDir) == "" {
		return initOptions{}, fmt.Errorf("working directory is required")
	}

	baseURL, serverName, err := initResolveBaseURLForCollection(input.CloudURL, input.ServerName)
	if err != nil {
		return initOptions{}, err
	}

	authToken := strings.TrimSpace(input.AuthToken)
	if flow == flowProjectKey {
		if authToken == "" {
			return initOptions{}, usageError("aw init requires AWEB_API_KEY with a project-scoped key; use `aw project create` for a new project")
		}
		if !strings.HasPrefix(authToken, "aw_sk_") {
			return initOptions{}, usageError("aw init requires a project-scoped API key (aw_sk_...). Hosted permanent identities are created from the dashboard")
		}
	}

	projectSlug := ""
	if flow == flowHeadless {
		projectSlug = strings.TrimSpace(input.ProjectSlug)
	}
	var suggestion *awid.SuggestAliasPrefixResponse
	if flow != flowInvite {
		suggestion = initFetchSuggestionForCollection(baseURL, projectSlug, authToken)
	}
	if flow == flowHeadless && projectSlug == "" && suggestion != nil {
		projectSlug = strings.TrimSpace(suggestion.ProjectSlug)
	}
	if flow == flowHeadless && projectSlug == "" {
		if input.Interactive && !input.JSONOutput {
			suggested := sanitizeSlug(filepath.Base(input.WorkingDir))
			v, err := promptStringWithIO("Project", suggested, input.PromptIn, input.PromptOut)
			if err != nil {
				return initOptions{}, err
			}
			projectSlug = strings.TrimSpace(v)
		} else {
			return initOptions{}, usageError("missing project slug (use --project or AWEB_PROJECT)")
		}
	}

	namespaceSlug := ""
	if flow == flowHeadless {
		namespaceSlug = strings.TrimSpace(input.NamespaceSlug)
		if namespaceSlug == "" {
			namespaceSlug = projectSlug
		}
	}

	alias := ""
	aliasExplicit := false
	name := strings.TrimSpace(input.Name)
	if input.Permanent {
		existingHandle, exists, err := detectExistingPersistentIdentityHandle(input.WorkingDir)
		if err != nil {
			return initOptions{}, err
		}
		if exists {
			if name != "" && name != existingHandle {
				return initOptions{}, usageError("--name %q does not match existing .aw/identity.yaml name %q", name, existingHandle)
			}
			name = existingHandle
		}
	}
	inviteAliasOptional := flow == flowInvite && !input.Interactive
	deferAliasPrompt := input.DeferAliasPrompt && flow == flowHeadless && !input.Permanent
	if !input.Permanent {
		alias = strings.TrimSpace(input.Alias)
		aliasExplicit = alias != ""
		if !aliasExplicit && !deferAliasPrompt {
			if !input.Interactive && flow == flowProjectKey {
				return initOptions{}, usageError("--alias is required when initializing an existing project workspace non-interactively")
			}
			if suggestion != nil && strings.TrimSpace(suggestion.NamePrefix) != "" {
				alias = strings.TrimSpace(suggestion.NamePrefix)
			}
		}
	}

	var suggestedRoles []string
	if suggestion != nil {
		suggestedRoles = suggestion.Roles
	}
	role := normalizeWorkspaceRole(input.Role)
	requiresWorkspaceRole := initRequiresWorkspaceRole(input.WorkingDir, input.WriteContext)
	if input.DeferRolePrompt {
		if role != "" && !isValidWorkspaceRole(role) {
			return initOptions{}, usageError("invalid role %q", role)
		}
	} else if role != "" || requiresWorkspaceRole {
		role, err = resolveRoleInput(input.Role, suggestedRoles, input.Interactive && !input.JSONOutput, input.PromptRole, input.PromptIn, input.PromptOut)
		if err != nil {
			return initOptions{}, err
		}
	}

	if input.Permanent {
		if input.PromptName && input.Interactive && !input.JSONOutput && strings.TrimSpace(name) == "" {
			v, err := promptRequiredStringWithIO("Name", name, input.PromptIn, input.PromptOut)
			if err != nil {
				return initOptions{}, err
			}
			name = strings.TrimSpace(v)
		}
	} else {
		if input.Interactive && !input.JSONOutput && !aliasExplicit && !deferAliasPrompt {
			if inviteAliasOptional {
				v, err := promptStringWithIO("Agent alias (optional)", alias, input.PromptIn, input.PromptOut)
				if err != nil {
					return initOptions{}, err
				}
				alias = strings.TrimSpace(v)
			} else {
				v, err := promptRequiredStringWithIO("Agent alias", alias, input.PromptIn, input.PromptOut)
				if err != nil {
					return initOptions{}, err
				}
				alias = strings.TrimSpace(v)
			}
		}
		if strings.TrimSpace(alias) == "" && !inviteAliasOptional && !deferAliasPrompt {
			return initOptions{}, usageError("alias is required (use --alias or accept a server-suggested alias)")
		}
	}
	if err := validateInitIdentityOptions(input.Permanent, strings.TrimSpace(alias), strings.TrimSpace(name), strings.TrimSpace(input.Reachability)); err != nil {
		return initOptions{}, err
	}

	return initOptions{
		Flow:                      flow,
		WorkingDir:                input.WorkingDir,
		PromptIn:                  input.PromptIn,
		PromptOut:                 input.PromptOut,
		BaseURL:                   baseURL,
		ServerName:                serverName,
		ProjectSlug:               projectSlug,
		NamespaceSlug:             namespaceSlug,
		IdentityAlias:             alias,
		IdentityName:              name,
		AddressReachability:       normalizeAddressReachability(strings.TrimSpace(input.Reachability)),
		HumanName:                 resolveHumanNameValue(strings.TrimSpace(input.HumanName)),
		AgentType:                 resolveAgentTypeValue(strings.TrimSpace(input.AgentType)),
		WriteContext:              input.WriteContext,
		AuthToken:                 authToken,
		InviteToken:               strings.TrimSpace(input.InviteToken),
		WorkspaceRole:             role,
		PromptAliasAfterBootstrap: input.DeferAliasPrompt,
		PromptRoleAfterBootstrap:  input.DeferRolePrompt,
		Lifetime:                  resolveInitLifetime(input.Permanent),
	}, nil
}

// fetchInitSuggestion calls the suggest-alias-prefix endpoint.
// When authToken is set, uses an authenticated client (server infers
// project from the token). Otherwise uses an anonymous client with nsSlug.
func fetchInitSuggestion(baseURL, nsSlug, authToken string) *awid.SuggestAliasPrefixResponse {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if strings.TrimSpace(authToken) != "" {
		client, err := aweb.NewWithAPIKey(baseURL, authToken)
		if err != nil {
			return &awid.SuggestAliasPrefixResponse{}
		}
		suggestion, err := client.SuggestAliasPrefix(ctx, nsSlug)
		if err != nil {
			return &awid.SuggestAliasPrefixResponse{}
		}
		return suggestion
	}

	client, err := aweb.New(baseURL)
	if err != nil {
		return &awid.SuggestAliasPrefixResponse{}
	}
	suggestion, err := client.SuggestAliasPrefix(ctx, nsSlug)
	if err != nil {
		return &awid.SuggestAliasPrefixResponse{}
	}
	return suggestion
}

func executeInit(opts initOptions) (*initResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	lifetime := strings.TrimSpace(opts.Lifetime)
	if lifetime == "" {
		lifetime = resolveInitLifetime(initPermanent)
	}

	identityMaterial, err := prepareInitIdentityMaterial(opts, lifetime)
	if err != nil {
		return nil, err
	}
	pub := identityMaterial.PublicKey
	priv := identityMaterial.SigningKey
	did := identityMaterial.DID
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	bootstrapAlias, bootstrapName := initBootstrapHandleValues(opts, identityMaterial, lifetime)
	var resp *awid.BootstrapIdentityResponse
	switch opts.Flow {
	case flowProjectKey:
		var client *aweb.Client
		client, err = aweb.NewWithAPIKey(opts.BaseURL, opts.AuthToken)
		if err != nil {
			return nil, err
		}
		// Project-scoped API key carries the project context — do not
		// send project_slug or project_name equivalents when the key
		// already identifies the project.
		req := &awid.WorkspaceInitRequest{
			HumanName:           opts.HumanName,
			AgentType:           opts.AgentType,
			DID:                 did,
			PublicKey:           pubKeyB64,
			Custody:             awid.CustodySelf,
			Lifetime:            lifetime,
			AddressReachability: opts.AddressReachability,
		}
		if strings.TrimSpace(bootstrapAlias) != "" {
			alias := strings.TrimSpace(bootstrapAlias)
			req.Alias = &alias
		}
		if strings.TrimSpace(bootstrapName) != "" {
			name := strings.TrimSpace(bootstrapName)
			req.Name = &name
		}
		resp, err = client.InitWorkspace(ctx, req)

	case flowHeadless:
		var client *aweb.Client
		client, err = aweb.New(opts.BaseURL)
		if err != nil {
			return nil, err
		}
		createReq := &awid.CreateProjectRequest{
			ProjectSlug:         opts.ProjectSlug,
			NamespaceSlug:       opts.NamespaceSlug,
			HumanName:           opts.HumanName,
			AgentType:           opts.AgentType,
			DID:                 did,
			PublicKey:           pubKeyB64,
			Custody:             awid.CustodySelf,
			Lifetime:            lifetime,
			AddressReachability: opts.AddressReachability,
		}
		if strings.TrimSpace(bootstrapAlias) != "" {
			alias := strings.TrimSpace(bootstrapAlias)
			createReq.Alias = &alias
		}
		if strings.TrimSpace(bootstrapName) != "" {
			name := strings.TrimSpace(bootstrapName)
			createReq.Name = &name
		}
		resp, err = client.CreateProject(ctx, createReq)

	default:
		return nil, fmt.Errorf("unsupported init flow %d", opts.Flow)
	}
	if err != nil {
		return nil, err
	}

	if opts.Flow == flowHeadless && opts.PromptAliasAfterBootstrap && lifetime == awid.LifetimeEphemeral {
		promptIn := opts.PromptIn
		if promptIn == nil {
			promptIn = os.Stdin
		}
		promptOut := opts.PromptOut
		if promptOut == nil {
			promptOut = os.Stderr
		}
		resp, pub, priv, err = maybeReplaceInitialCreateProjectIdentity(ctx, opts, resp, pub, priv, lifetime, promptIn, promptOut)
		if err != nil {
			return nil, err
		}
	}

	namespaceSlug := strings.TrimSpace(resp.NamespaceSlug)
	if namespaceSlug == "" {
		return nil, fmt.Errorf("identity bootstrap failed: missing namespace_slug in response")
	}

	attachURL := opts.BaseURL
	if v := strings.TrimSpace(resp.ServerURL); v != "" {
		attachURL = v
	}
	promptOut := opts.PromptOut
	if promptOut == nil {
		promptOut = os.Stderr
	}
	if lifetime == awid.LifetimePersistent && strings.TrimSpace(resp.Custody) == awid.CustodySelf {
		if err := validatePersistentBootstrapResponse(identityMaterial, resp); err != nil {
			return nil, err
		}
	}

	registryURL := strings.TrimSpace(identityMaterial.RegistryURL)
	registryStatus := ""
	if lifetime == awid.LifetimePersistent && strings.TrimSpace(resp.Custody) == awid.CustodySelf {
		var syncErr error
		registryURL, registryStatus, syncErr = syncPersistentIdentityRegistry(ctx, opts, resp, identityMaterial, attachURL)
		if syncErr != nil {
			fmt.Fprintf(promptOut, "Warning: could not sync identity at awid.ai: %v\n", syncErr)
		}
		if err := persistPermanentInitIdentity(identityMaterial, resp, registryURL, firstNonEmpty(registryStatus, "pending")); err != nil {
			return nil, err
		}
	}
	authClient, authClientErr := aweb.NewWithAPIKey(attachURL, resp.APIKey)

	workspaceRole := strings.TrimSpace(opts.WorkspaceRole)
	needsPostBootstrapRoleResolution := initRequiresWorkspaceRole(opts.WorkingDir, opts.WriteContext) && (opts.PromptRoleAfterBootstrap || workspaceRole == "")
	if needsPostBootstrapRoleResolution && authClientErr == nil {
		promptIn := opts.PromptIn
		if promptIn == nil {
			promptIn = os.Stdin
		}
		workspaceRole, err = resolveRole(authClient, workspaceRole, opts.PromptRoleAfterBootstrap && workspaceRole == "", promptIn, promptOut)
		if err != nil {
			return nil, err
		}
	} else if authClientErr != nil && needsPostBootstrapRoleResolution {
		return nil, authClientErr
	}

	handle := strings.TrimSpace(resp.IdentityHandle())
	if handle == "" {
		handle = handleFromAddress(resp.Address)
	}
	if handle == "" {
		return nil, fmt.Errorf("identity bootstrap failed: missing identity handle in response")
	}
	address := resp.Address
	if address == "" {
		address = deriveIdentityAddress(namespaceSlug, "", handle)
	}
	var signingKeyPath string
	if strings.TrimSpace(resp.Custody) == awid.CustodySelf {
		signingKeyPath = strings.TrimSpace(identityMaterial.SigningKeyPath)
		if signingKeyPath == "" {
			signingKeyPath = awconfig.WorktreeSigningKeyPath(opts.WorkingDir)
		}
		if err := awid.SaveSigningKey(signingKeyPath, priv); err != nil {
			return nil, err
		}
	}

	stableID := strings.TrimSpace(resp.StableID)
	if opts.WriteContext {
		if err := ensureWorktreeContextAt(opts.WorkingDir); err != nil {
			return nil, err
		}
	}

	var attachResult *contextAttachResult
	if opts.WriteContext {
		if authClientErr == nil {
			attachResult, err = autoAttachContext(opts.WorkingDir, authClient, workspaceRole)
			if err != nil {
				if shouldWarnOnWorkspaceAttach(err) {
					debugLog("workspace attach: %v", err)
					fmt.Fprintf(os.Stderr, "Warning: could not attach workspace context (coordination may not be available on this server)\n")
				} else {
					return nil, err
				}
			}
		} else {
			return nil, authClientErr
		}
	}

	finalRole := workspaceRole
	if attachResult != nil && attachResult.Workspace != nil && strings.TrimSpace(attachResult.Workspace.Role) != "" {
		finalRole = strings.TrimSpace(attachResult.Workspace.Role)
	}
	if err := persistWorkspaceBinding(workspaceBindingInput{
		WorkingDir:     opts.WorkingDir,
		AwebURL:        attachURL,
		APIKey:         strings.TrimSpace(resp.APIKey),
		ProjectID:      strings.TrimSpace(resp.ProjectID),
		ProjectSlug:    strings.TrimSpace(resp.ProjectSlug),
		NamespaceSlug:  namespaceSlug,
		IdentityID:     strings.TrimSpace(resp.IdentityID),
		IdentityHandle: handle,
		DID:            strings.TrimSpace(resp.DID),
		StableID:       stableID,
		SigningKey:     signingKeyPath,
		Custody:        strings.TrimSpace(resp.Custody),
		Lifetime:       strings.TrimSpace(resp.Lifetime),
		Role:           finalRole,
		AttachResult:   attachResult,
	}); err != nil {
		return nil, err
	}

	return &initResult{
		Response:        resp,
		ServerName:      opts.ServerName,
		Role:            finalRole,
		AttachResult:    attachResult,
		SigningKeyPath:  signingKeyPath,
		ExportBaseURL:   attachURL,
		ExportNamespace: namespaceSlug,
		JoinedViaInvite: opts.InviteToken != "",
	}, nil
}

func maybeReplaceInitialCreateProjectIdentity(
	ctx context.Context,
	opts initOptions,
	initialResp *awid.BootstrapIdentityResponse,
	initialPub []byte,
	initialPriv []byte,
	lifetime string,
	in io.Reader,
	out io.Writer,
) (*awid.BootstrapIdentityResponse, []byte, []byte, error) {
	if initialResp == nil || strings.TrimSpace(initialResp.APIKey) == "" {
		return initialResp, nil, nil, fmt.Errorf("identity bootstrap failed: missing api_key in response")
	}
	defaultAlias := strings.TrimSpace(initialResp.Alias)
	if defaultAlias == "" {
		return initialResp, initialPub, initialPriv, nil
	}
	attachURL := opts.BaseURL
	if v := strings.TrimSpace(initialResp.ServerURL); v != "" {
		attachURL = v
	}
	initialClient, err := aweb.NewWithAPIKey(attachURL, initialResp.APIKey)
	if err != nil {
		return nil, nil, nil, err
	}

	currentDefault := defaultAlias
	for {
		alias, err := promptRequiredStringWithIO("Agent alias", currentDefault, in, out)
		if err != nil {
			return nil, nil, nil, err
		}
		alias = strings.TrimSpace(alias)
		if err := validateInitIdentityOptions(false, alias, "", ""); err != nil {
			fmt.Fprintf(out, "%v\n", err)
			continue
		}
		if alias == defaultAlias {
			return initialResp, initialPub, initialPriv, nil
		}

		pub, priv, err := awid.GenerateKeypair()
		if err != nil {
			return nil, nil, nil, err
		}
		did := awid.ComputeDIDKey(pub)
		pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)
		req := &awid.WorkspaceInitRequest{
			HumanName:           opts.HumanName,
			AgentType:           opts.AgentType,
			DID:                 did,
			PublicKey:           pubKeyB64,
			Custody:             awid.CustodySelf,
			Lifetime:            lifetime,
			AddressReachability: opts.AddressReachability,
			Alias:               &alias,
		}
		replacementResp, err := initialClient.InitWorkspace(ctx, req)
		if err != nil {
			if code, ok := awid.HTTPStatusCode(err); ok && (code == 409 || code == 422) {
				fmt.Fprintf(out, "%v\n", err)
				currentDefault = alias
				continue
			}
			return nil, nil, nil, err
		}
		if err := initialClient.Deregister(ctx); err != nil {
			return nil, nil, nil, err
		}
		return replacementResp, pub, priv, nil
	}
}

func initBootstrapHandleValues(opts initOptions, identity *initIdentityMaterial, lifetime string) (string, string) {
	if strings.TrimSpace(lifetime) == awid.LifetimePersistent {
		if identity != nil && strings.TrimSpace(identity.Handle) != "" {
			return "", strings.TrimSpace(identity.Handle)
		}
		return "", strings.TrimSpace(opts.IdentityName)
	}
	return strings.TrimSpace(opts.IdentityAlias), ""
}

func shouldWarnOnWorkspaceAttach(err error) bool {
	if err == nil {
		return false
	}
	if code, ok := awid.HTTPStatusCode(err); ok && code == 404 {
		return true
	}
	return false
}

func printInitSummary(resp *awid.BootstrapIdentityResponse, serverName, role string, attachResult *contextAttachResult, signingKeyPath, workingDir, headline string) {
	if resp == nil {
		return
	}
	project := strings.TrimSpace(resp.ProjectSlug)
	namespace := strings.TrimSpace(resp.Namespace)
	if namespace == "" {
		namespace = strings.TrimSpace(resp.NamespaceSlug)
	}

	headline = strings.TrimSpace(headline)
	if headline == "" {
		headline = "Initialized workspace"
	}
	fmt.Println(headline)
	handle := strings.TrimSpace(resp.IdentityHandle())
	if handle != "" {
		label := "Alias"
		if awid.IdentityClassFromLifetime(resp.Lifetime) == awid.IdentityClassPermanent {
			label = "Name"
		}
		fmt.Printf("%-11s %s\n", label+":", handle)
	}
	if identityClass := describeIdentityClass(strings.TrimSpace(resp.Lifetime)); identityClass != "" {
		fmt.Printf("Identity:   %s\n", identityClass)
	}
	if strings.TrimSpace(resp.Custody) != "" {
		fmt.Printf("Custody:    %s\n", strings.TrimSpace(resp.Custody))
	}
	if project != "" {
		fmt.Printf("Project:    %s\n", project)
	}
	if namespace != "" && namespace != project {
		fmt.Printf("Namespace:  %s\n", namespace)
	}
	if strings.TrimSpace(role) != "" {
		fmt.Printf("Role:       %s\n", strings.TrimSpace(role))
	}
	if strings.TrimSpace(resp.Address) != "" {
		label := "Address"
		if strings.TrimSpace(resp.Lifetime) == awid.LifetimeEphemeral {
			label = "Routing"
		}
		fmt.Printf("%-10s %s\n", label+":", strings.TrimSpace(resp.Address))
	}
	if awid.IdentityClassFromLifetime(resp.Lifetime) == awid.IdentityClassPermanent && strings.TrimSpace(resp.AddressReachability) != "" {
		fmt.Printf("Reachability: %s\n", strings.TrimSpace(resp.AddressReachability))
	}
	if strings.TrimSpace(serverName) != "" {
		fmt.Printf("Server:     %s\n", strings.TrimSpace(serverName))
	}
	if awid.IdentityClassFromLifetime(resp.Lifetime) == awid.IdentityClassPermanent && strings.TrimSpace(signingKeyPath) != "" {
		fmt.Printf("Key:        %s\n", strings.TrimSpace(signingKeyPath))
	}
	if attachResult != nil {
		switch strings.TrimSpace(attachResult.ContextKind) {
		case "repo_worktree":
			if attachResult.Workspace != nil {
				fmt.Printf("Context:    attached %s\n", strings.TrimSpace(attachResult.Workspace.CanonicalOrigin))
			}
		case "local_dir":
			fmt.Println("Context:    attached local directory")
		}
	}
	if wd := abbreviateUserHome(workingDir); wd != "" {
		fmt.Printf("Directory:  %s\n", wd)
	}
	if handle != "" {
		fmt.Printf("Workspace:  this directory is now agent %s\n", handle)
	}
	fmt.Println("State:      .aw/ stores this agent's local identity and workspace binding")
}

func printPostInitActions(result *initResult, workingDir string) {
	if initPrintExports {
		fmt.Println("")
		fmt.Println("# Copy/paste to configure your shell:")
		fmt.Println("export AWEB_URL=" + result.ExportBaseURL)
		fmt.Println("export AWEB_API_KEY=" + result.Response.APIKey)
		fmt.Println("export AWEB_PROJECT=" + result.ExportNamespace)
		if strings.TrimSpace(result.Response.Alias) != "" {
			fmt.Println("export AWEB_ALIAS=" + result.Response.Alias)
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
		printInitNextSteps(result, workingDir, initInjectDocs, initSetupHooks, initSetupChannel)
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
	lines := []string{
		formatInitNextStep("aw run codex", "Start Codex in this directory"),
		formatInitNextStep("aw run claude", "Start Claude in this directory"),
	}

	if _, err := currentGitWorktreeRootFromDir(workingDir); err == nil {
		lines = append(lines, formatInitNextStep("aw workspace add-worktree <role>", "Create another agent in this same git repo"))
	}

	if shouldSuggestClaimHuman(result) {
		lines = append(lines, formatInitNextStep("aw claim-human --email you@example.com", "Attach your human account for dashboard access"))
	}
	if !didInjectDocs {
		lines = append(lines, formatInitNextStep("aw init --inject-docs", "Add coordination instructions to CLAUDE.md / AGENTS.md"))
	}
	if !didSetupHooks {
		lines = append(lines, formatInitNextStep("aw init --setup-hooks", "Set up Claude Code chat notification hook"))
	}
	if !didSetupChannel {
		lines = append(lines, formatInitNextStep("aw init --setup-channel", "Set up Claude Code channel MCP server"))
	}
	return lines
}

func formatInitNextStep(command, description string) string {
	return fmt.Sprintf("  %-36s %s", command, description)
}

func shouldSuggestClaimHuman(result *initResult) bool {
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

func resolveInitLifetime(permanent bool) string {
	if permanent {
		return awid.LifetimePersistent
	}
	return awid.LifetimeEphemeral
}

func describeIdentityClass(lifetime string) string {
	switch strings.TrimSpace(lifetime) {
	case awid.LifetimeEphemeral:
		return "ephemeral"
	case awid.LifetimePersistent:
		return "permanent"
	default:
		return strings.TrimSpace(lifetime)
	}
}

func cloudRootBaseURL(baseURL string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(baseURL))
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/api")
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
