package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

var initCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize a local workspace in an existing project",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat for init — no credentials yet.
	},
	RunE: runInit,
}

var (
	initServerURL     string
	initProjectSlug   string
	initNamespaceSlug string
	initAlias         string
	initName          string
	initReachability  string
	initInjectDocs    bool
	initSetupHooks    bool
	initHumanName     string
	initAgentType     string
	initSaveConfig    bool
	initSetDefault    bool
	initWriteContext  bool
	initPrintExports  bool
	initRole          string
	initPermanent     bool
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
	Flow                initFlow
	WorkingDir          string
	BaseURL             string
	ServerName          string
	ProjectSlug         string
	NamespaceSlug       string
	IdentityAlias       string
	IdentityName        string
	AddressReachability string
	HumanName           string
	AgentType           string
	SaveConfig          bool
	SetDefault          bool
	WriteContext        bool
	AuthToken           string // Bearer token for the selected flow
	InviteToken         string
	AccountName         string
	WorkspaceRole       string
	Lifetime            string // "ephemeral" (default) or "persistent"
}

type initResult struct {
	Response        *awid.BootstrapIdentityResponse
	AccountName     string
	ServerName      string
	Role            string
	AttachResult    *contextAttachResult
	SigningKeyPath  string
	ExportBaseURL   string
	ExportNamespace string
	JoinedViaInvite bool
}

func init() {
	initCmd.Flags().StringVar(&initServerURL, "server-url", "", "Base URL for the aweb server (or AWEB_URL). Any URL is accepted; aw probes common mounts (including /api).")
	initCmd.Flags().StringVar(&initServerURL, "server", "", "Base URL for the aweb server (alias for --server-url)")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initName, "name", "", "Permanent identity name (required with --permanent)")
	initCmd.Flags().StringVar(&initReachability, "reachability", "", "Permanent address reachability (private|org-visible|contacts-only|public)")
	initCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	initCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initSaveConfig, "save-config", true, "Write/update ~/.config/aw/config.yaml with the new credentials")
	initCmd.Flags().BoolVar(&initSetDefault, "set-default", false, "Set this account as default_account in ~/.config/aw/config.yaml")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Write/update .aw/context in the current directory (non-secret pointer)")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	initCmd.Flags().StringVar(&initRole, "role", "", "Workspace role (must match a role in the active project policy)")
	initCmd.Flags().BoolVar(&initPermanent, "permanent", false, "Create a durable self-custodial identity instead of the default ephemeral identity")

	rootCmd.AddCommand(initCmd)
}

func runInit(cmd *cobra.Command, args []string) error {
	// When only --inject-docs or --setup-hooks are requested, operate on the
	// existing workspace without running the full init flow.
	if (initInjectDocs || initSetupHooks) && !initNeedsFullInit() {
		wd, _ := os.Getwd()
		repoRoot := resolveRepoRoot(wd)
		if initInjectDocs {
			printInjectDocsResult(InjectAgentDocs(repoRoot))
		}
		if initSetupHooks {
			hookResult := SetupClaudeHooks(repoRoot, isTTY())
			printClaudeHooksResult(hookResult)
		}
		return nil
	}

	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) == "" {
		return usageError("aw init now initializes a workspace in an existing project; set AWEB_API_KEY to a project-scoped key or use `aw project create`")
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
		printInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, "Initialized workspace")
	}
	printPostInitActions(result, opts.WorkingDir)
	return nil
}

// initNeedsFullInit returns true if the user passed flags that require the
// full init flow, or if no .aw/context exists yet (first-time init).
func initNeedsFullInit() bool {
	if initServerURL != "" || initAlias != "" || initName != "" || initReachability != "" || initRole != "" || initPermanent {
		return true
	}
	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) != "" {
		return true
	}
	wd, _ := os.Getwd()
	_, _, err := awconfig.LoadWorktreeContextFromDir(wd)
	return err != nil
}

func collectInitOptionsForFlow(flow initFlow) (initOptions, error) {
	workingDir, err := os.Getwd()
	if err != nil {
		return initOptions{}, err
	}
	if err := validateInitIdentityFlags(); err != nil {
		return initOptions{}, err
	}

	// --- Validation ---

	// --- Base URL and server resolution ---

	baseURL, serverName, _, err := resolveBaseURLForInit(initServerURL, serverFlag)
	if err != nil {
		return initOptions{}, err
	}
	accountName := strings.TrimSpace(accountFlag)

	// --- Auth token for this flow ---

	authToken := ""
	switch flow {
	case flowProjectKey:
		authToken = strings.TrimSpace(os.Getenv("AWEB_API_KEY"))
		if authToken == "" {
			return initOptions{}, usageError("aw init requires AWEB_API_KEY with a project-scoped key; use `aw project create` for a new project")
		}
		if !strings.HasPrefix(authToken, "aw_sk_") {
			return initOptions{}, usageError("aw init requires a project-scoped API key (aw_sk_...). Hosted permanent identities are created from the dashboard")
		}
	}

	// --- Suggestion (one call, reused for project + alias + roles) ---

	projectSlug := ""
	if flow != flowProjectKey {
		projectSlug = resolveProjectSlug()
	}
	suggestion := fetchInitSuggestion(baseURL, projectSlug, authToken)
	if projectSlug == "" && suggestion != nil {
		projectSlug = strings.TrimSpace(suggestion.ProjectSlug)
	}
	if projectSlug == "" && flow != flowProjectKey {
		if isTTY() {
			suggested := sanitizeSlug(filepath.Base(workingDir))
			v, err := promptString("Project", suggested)
			if err != nil {
				return initOptions{}, err
			}
			projectSlug = v
		} else {
			return initOptions{}, usageError("missing project slug (use --project or AWEB_PROJECT)")
		}
	}

	namespaceSlug := ""
	if flow == flowHeadless {
		namespaceSlug = resolveExplicitNamespaceSlug()
		if namespaceSlug == "" {
			namespaceSlug = projectSlug
		}
	}

	// --- Human name and agent type ---

	humanName := resolveHumanName()
	agentType := resolveAgentType()

	// --- Identity handle ---

	alias := ""
	aliasExplicit := false
	name := ""
	if initPermanent {
		name = strings.TrimSpace(initName)
	} else {
		alias = strings.TrimSpace(initAlias)
		aliasExplicit = alias != ""
		if !aliasExplicit {
			alias = strings.TrimSpace(os.Getenv("AWEB_ALIAS"))
			aliasExplicit = alias != ""
		}
		if !aliasExplicit {
			if !isTTY() && flow == flowProjectKey {
				return initOptions{}, usageError("--alias is required when initializing an existing project workspace non-interactively")
			}
			if suggestion != nil && strings.TrimSpace(suggestion.NamePrefix) != "" {
				alias = strings.TrimSpace(suggestion.NamePrefix)
			}
		}
	}

	// --- Role ---

	var suggestedRoles []string
	if suggestion != nil {
		suggestedRoles = suggestion.Roles
	}
	role, err := resolveRoleFromFlags(suggestedRoles)
	if err != nil {
		return initOptions{}, err
	}

	// --- TTY prompts for alias (after role, so prompts are in logical order) ---

	if !initPermanent {
		if isTTY() && !aliasExplicit {
			v, err := promptRequiredString("Alias", alias)
			if err != nil {
				return initOptions{}, err
			}
			alias = strings.TrimSpace(v)
		}
		if strings.TrimSpace(alias) == "" {
			return initOptions{}, usageError("alias is required (use --alias or accept a server-suggested alias)")
		}
	}

	return initOptions{
		Flow:                flow,
		WorkingDir:          workingDir,
		BaseURL:             baseURL,
		ServerName:          serverName,
		ProjectSlug:         projectSlug,
		NamespaceSlug:       namespaceSlug,
		IdentityAlias:       alias,
		IdentityName:        name,
		AddressReachability: normalizeAddressReachability(strings.TrimSpace(initReachability)),
		HumanName:           humanName,
		AgentType:           agentType,
		SaveConfig:          initSaveConfig,
		SetDefault:          initSetDefault,
		WriteContext:        initWriteContext,
		AuthToken:           authToken,
		AccountName:         accountName,
		WorkspaceRole:       role,
		Lifetime:            resolveInitLifetime(initPermanent),
	}, nil
}

func validateInitIdentityFlags() error {
	alias := strings.TrimSpace(initAlias)
	name := strings.TrimSpace(initName)
	reachability := normalizeAddressReachability(strings.TrimSpace(initReachability))
	if initReachability != "" && reachability == "" {
		return usageError("invalid --reachability (use private|org-visible|contacts-only|public)")
	}
	if initPermanent {
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
	if v := strings.TrimSpace(initHumanName); v != "" {
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
	if v := strings.TrimSpace(initAgentType); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("AWEB_AGENT_TYPE")); v != "" {
		return v
	}
	return "agent"
}

// resolveRoleFromFlags resolves a role during workspace creation, before
// the workspace has an authenticated client. Uses roles from the suggestion
// endpoint (same policy source as fetchAvailableRoles, but available pre-auth).
// After creation, registerWorkspaceForRoot trusts this pre-validated role.
func resolveRoleFromFlags(suggestedRoles []string) (string, error) {
	requested := strings.TrimSpace(initRole)
	if requested == "" {
		requested = strings.TrimSpace(os.Getenv("AWEB_ROLE"))
	}
	if len(suggestedRoles) > 0 {
		return selectRoleFromAvailableRoles(requested, suggestedRoles, isTTY() && requested == "", os.Stdin, os.Stderr)
	}
	return normalizeWorkspaceRole(requested), nil
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

	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	did := awid.ComputeDIDKey(pub)
	pubKeyB64 := base64.RawStdEncoding.EncodeToString(pub)

	lifetime := strings.TrimSpace(opts.Lifetime)
	if lifetime == "" {
		lifetime = resolveInitLifetime(initPermanent)
	}

	var resp *awid.BootstrapIdentityResponse
	switch opts.Flow {
	case flowInvite:
		resp, err = acceptInviteViaCloud(ctx, opts.BaseURL, opts.InviteToken, opts.IdentityAlias, opts.IdentityName, opts.AddressReachability, opts.HumanName, opts.AgentType, did, pubKeyB64, lifetime)

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
		if strings.TrimSpace(opts.IdentityAlias) != "" {
			alias := strings.TrimSpace(opts.IdentityAlias)
			req.Alias = &alias
		}
		if strings.TrimSpace(opts.IdentityName) != "" {
			name := strings.TrimSpace(opts.IdentityName)
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
		if strings.TrimSpace(opts.IdentityAlias) != "" {
			alias := strings.TrimSpace(opts.IdentityAlias)
			createReq.Alias = &alias
		}
		if strings.TrimSpace(opts.IdentityName) != "" {
			name := strings.TrimSpace(opts.IdentityName)
			createReq.Name = &name
		}
		resp, err = client.CreateProject(ctx, createReq)
	}
	if err != nil {
		return nil, err
	}

	namespaceSlug := strings.TrimSpace(resp.NamespaceSlug)
	if namespaceSlug == "" {
		return nil, fmt.Errorf("identity bootstrap failed: missing namespace_slug in response")
	}

	handle := strings.TrimSpace(resp.IdentityHandle())
	if handle == "" {
		handle = handleFromAddress(resp.Address)
	}
	if handle == "" {
		return nil, fmt.Errorf("identity bootstrap failed: missing identity handle in response")
	}
	accountName := strings.TrimSpace(opts.AccountName)
	if accountName == "" {
		accountName = deriveAccountName(opts.ServerName, namespaceSlug, handle)
	}

	address := resp.Address
	if address == "" {
		address = deriveIdentityAddress(namespaceSlug, "", handle)
	}
	cfgPath, err := defaultGlobalPath()
	if err != nil {
		return nil, err
	}
	keysDir := awconfig.KeysDir(cfgPath)
	signingKeyPath := awid.SigningKeyPath(keysDir, address)
	if err := awid.SaveKeypair(keysDir, address, pub, priv); err != nil {
		return nil, err
	}

	stableID := strings.TrimSpace(resp.StableID)
	if opts.SaveConfig {
		if err := awconfig.UpdateGlobalAt(cfgPath, func(cfg *awconfig.GlobalConfig) error {
			if cfg.Servers == nil {
				cfg.Servers = map[string]awconfig.Server{}
			}
			if cfg.Accounts == nil {
				cfg.Accounts = map[string]awconfig.Account{}
			}
			serverURL := opts.BaseURL
			if v := strings.TrimSpace(resp.ServerURL); v != "" {
				serverURL = v
			}
			cfg.Servers[opts.ServerName] = awconfig.Server{URL: serverURL}
			cfg.Accounts[accountName] = awconfig.Account{Account: awid.Account{
				Server:         opts.ServerName,
				APIKey:         resp.APIKey,
				IdentityID:     resp.IdentityID,
				IdentityHandle: handle,
				NamespaceSlug:  namespaceSlug,
				DID:            resp.DID,
				StableID:       stableID,
				SigningKey:     signingKeyPath,
				Custody:        resp.Custody,
				Lifetime:       resp.Lifetime,
			}}
			if strings.TrimSpace(cfg.DefaultAccount) == "" || opts.SetDefault {
				cfg.DefaultAccount = accountName
			}
			return nil
		}); err != nil {
			return nil, err
		}
	}

	if opts.WriteContext {
		if err := writeOrUpdateContextAt(opts.WorkingDir, opts.ServerName, accountName, true); err != nil {
			return nil, err
		}
	}

	var attachResult *contextAttachResult
	if opts.WriteContext {
		attachURL := opts.BaseURL
		if v := strings.TrimSpace(resp.ServerURL); v != "" {
			attachURL = v
		}
		authClient, err := aweb.NewWithAPIKey(attachURL, resp.APIKey)
		if err == nil {
			attachResult, err = autoAttachContext(opts.WorkingDir, authClient, strings.TrimSpace(opts.WorkspaceRole))
			if err != nil {
				if shouldWarnOnWorkspaceAttach(err) {
					debugLog("workspace attach: %v", err)
					fmt.Fprintf(os.Stderr, "Warning: could not attach workspace context (coordination may not be available on this server)\n")
				} else {
					return nil, err
				}
			}
		}
	}

	finalRole := strings.TrimSpace(opts.WorkspaceRole)
	if attachResult != nil && attachResult.Workspace != nil && strings.TrimSpace(attachResult.Workspace.Role) != "" {
		finalRole = strings.TrimSpace(attachResult.Workspace.Role)
	}

	exportBaseURL := opts.BaseURL
	if v := strings.TrimSpace(resp.ServerURL); v != "" {
		exportBaseURL = v
	}

	return &initResult{
		Response:        resp,
		AccountName:     accountName,
		ServerName:      opts.ServerName,
		Role:            finalRole,
		AttachResult:    attachResult,
		SigningKeyPath:  signingKeyPath,
		ExportBaseURL:   exportBaseURL,
		ExportNamespace: namespaceSlug,
		JoinedViaInvite: opts.InviteToken != "",
	}, nil
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

func printInitSummary(resp *awid.BootstrapIdentityResponse, accountName, serverName, role string, attachResult *contextAttachResult, signingKeyPath, headline string) {
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
	if initSetupHooks {
		hookResult := SetupClaudeHooks(repoRoot, isTTY())
		printClaudeHooksResult(hookResult)
	}
	if !jsonFlag {
		printInitNextSteps(initInjectDocs, initSetupHooks)
	}
}

func printInitNextSteps(didInjectDocs, didSetupHooks bool) {
	if didInjectDocs && didSetupHooks {
		return
	}
	fmt.Println()
	fmt.Println("Next steps:")
	if !didInjectDocs {
		fmt.Println("  aw init --inject-docs    Add coordination instructions to CLAUDE.md / AGENTS.md")
	}
	if !didSetupHooks {
		fmt.Println("  aw init --setup-hooks    Set up Claude Code chat notification hook")
	}
}

func acceptInviteViaCloud(
	ctx context.Context,
	baseURL string,
	token string,
	alias string,
	name string,
	addressReachability string,
	humanName string,
	agentType string,
	did string,
	publicKey string,
	lifetime string,
) (*awid.BootstrapIdentityResponse, error) {
	client, err := newUnauthenticatedCloudClient(baseURL)
	if err != nil {
		return nil, fmt.Errorf("invite accept requires a valid URL: %w", err)
	}
	req := &awid.SpawnAcceptInviteRequest{
		Token:               token,
		AddressReachability: addressReachability,
		HumanName:           humanName,
		AgentType:           agentType,
		DID:                 did,
		PublicKey:           publicKey,
		Custody:             awid.CustodySelf,
		Lifetime:            lifetime,
	}
	if trimmed := strings.TrimSpace(alias); trimmed != "" {
		req.Alias = &trimmed
	}
	if trimmed := strings.TrimSpace(name); trimmed != "" {
		req.Name = &trimmed
	}
	resp, err := client.SpawnAcceptInvite(ctx, req)
	if err != nil {
		if code, ok := awid.HTTPStatusCode(err); ok && code == 422 {
			if body, ok := awid.HTTPErrorBody(err); ok {
				lower := strings.ToLower(body)
				if strings.TrimSpace(alias) == "" && strings.Contains(lower, "alias") {
					return nil, usageError("alias is required (use --alias)")
				}
				if strings.TrimSpace(name) == "" && strings.Contains(lower, "name") {
					return nil, usageError("name is required (use --name)")
				}
			}
		}
		return nil, err
	}
	if strings.TrimSpace(resp.APIKey) == "" {
		return nil, fmt.Errorf("invite accept failed: missing api_key in response")
	}
	return resp, nil
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

func sortedAccountNames(global *awconfig.GlobalConfig) []string {
	names := make([]string, 0, len(global.Accounts))
	for name := range global.Accounts {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
