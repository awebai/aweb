package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
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
		loadDotenvBestEffort()
		maybeCheckLatestVersion(cmd)
		// No heartbeat for init — no credentials yet.
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
	initPersistent         bool
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
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initName, "name", "", "Persistent identity name (required with --persistent unless .aw/identity.yaml already exists)")
	initCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
	initCmd.Flags().BoolVar(&initDoNotTouchAgentsMD, "do-not-touch-agents-md", false, "Do not create or update AGENTS.md or CLAUDE.md during init")
	initCmd.Flags().BoolVar(&initSetupHooks, "setup-hooks", false, "Set up Claude Code PostToolUse hook for aw notify")
	initCmd.Flags().BoolVar(&initSetupChannel, "setup-channel", false, "Set up Claude Code channel MCP server for real-time coordination")
	initCmd.Flags().StringVar(&initHumanName, "human-name", "", "Human name (default: AWEB_HUMAN or $USER)")
	initCmd.Flags().StringVar(&initAgentType, "agent-type", "", "Runtime type (default: AWEB_AGENT_TYPE or agent)")
	initCmd.Flags().BoolVar(&initWriteContext, "write-context", true, "Ensure .aw/context exists in the current directory")
	initCmd.Flags().BoolVar(&initPrintExports, "print-exports", false, "Print shell export lines after JSON output")
	addWorkspaceRoleFlags(initCmd, &initRole, "Workspace role name (must match a role in the active team roles bundle)")
	initCmd.Flags().BoolVar(&initPersistent, "persistent", false, "Create a durable self-custodial identity instead of the default ephemeral identity")

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
	if initInjectDocs && initDoNotTouchAgentsMD {
		return fmt.Errorf("--inject-docs and --do-not-touch-agents-md are mutually exclusive")
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
		result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
			WorkingDir:  wd,
			AwebURL:     awebURL,
			RegistryURL: registryURL,
			APIKey:      apiKey,
			Name:        strings.TrimSpace(initName),
			Alias:       resolveAliasValue(strings.TrimSpace(initAlias)),
			Role:        resolveRequestedRole(strings.TrimSpace(initRole)),
			HumanName:   resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:   resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
			Persistent:  initPersistent,
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
		awebURL, err := resolveInitAwebURL()
		if err != nil {
			return err
		}
		registryURL, err := resolveInitAWIDRegistryURL()
		if err != nil {
			return err
		}
		if initShouldUseImplicitLocalFlow(registryURL) {
			result, err := initRunImplicitLocalFlow(implicitLocalInitRequest{
				WorkingDir:  wd,
				AwebURL:     awebURL,
				RegistryURL: registryURL,
				Alias:       resolveAliasValue(strings.TrimSpace(initAlias)),
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
		canPrompt := initIsTTY() && !jsonFlag
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
				if initPersistent {
					return strings.TrimSpace(initAlias)
				}
				return resolveAliasValue(strings.TrimSpace(initAlias))
			}(),
			Name:               strings.TrimSpace(initName),
			HumanName:          resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:          resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
			Role:               resolveRequestedRole(strings.TrimSpace(initRole)),
			Persistent:         initPersistent,
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
	return initBYOD || initPersistent
}

func resolveInitAwebURL() (string, error) {
	value := resolveInitAwebURLOverride()
	if value == "" {
		value = DefaultAwebURL
	}
	return normalizeAwebBaseURL(value)
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
	awebURL, err := cleanBaseURL(DefaultAwebURL + "/api")
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
		strings.TrimSpace(initName) == "" &&
		!initPersistent
}

// initNeedsFullInitForAddonOnly returns true when an add-on request must
// escalate to full init because it changes identity/team state or has no
// existing workspace to operate on.
func initNeedsFullInitForAddonOnly() bool {
	if initBYOD || initUsername != "" || initDomain != "" || initAlias != "" || initName != "" || initRole != "" || initPersistent {
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
	fmt.Fprintln(out, "To use the channel directly inside Claude Code (real-time coordination):")
	fmt.Fprintln(out, "  /plugin marketplace add awebai/claude-plugins")
	fmt.Fprintln(out, "  /plugin install aweb-channel@awebai-marketplace")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Then start Claude Code with the channel enabled:")
	fmt.Fprintln(out, "  claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace")
	fmt.Fprintln(out)
	fmt.Fprintln(out, "Note: Claude Code will warn that --dangerously-load-development-channels is a")
	fmt.Fprintln(out, "security risk and ask you to confirm. That warning is expected — channels are")
	fmt.Fprintln(out, "still in beta. Confirm to enable.")
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
	lines = append(lines, "  Install the channel directly inside Claude Code (real-time coordination):")
	lines = append(lines, "    /plugin marketplace add awebai/claude-plugins")
	lines = append(lines, "    /plugin install aweb-channel@awebai-marketplace")
	lines = append(lines, "")
	lines = append(lines, "  Then start Claude Code with the channel enabled:")
	lines = append(lines, "    claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace")
	lines = append(lines, "")
	lines = append(lines, "  Tell your agent: please read https://aweb.ai/docs/cli-tutorial.md")
	return lines
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
