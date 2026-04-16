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
- create a hosted aweb.ai account with --hosted
- launch guided onboarding in a TTY when this directory is still clean`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		loadDotenvBestEffort()
		// No heartbeat for init — no credentials yet.
	},
	RunE: runInit,
}

var (
	initURL            string
	initAwebURL        string
	initAWIDRegistry   string
	initHosted         bool
	initHostedUsername string
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
	initPersistent     bool
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
}

func init() {
	initCmd.Flags().StringVar(&initURL, "url", "", "Base URL for the aweb server used for init, bootstrap, and hosted onboarding flows")
	initCmd.Flags().StringVar(&initAwebURL, "aweb-url", "", "Base URL for the aweb server used by aw init (overrides AWEB_URL)")
	initCmd.Flags().StringVar(&initAWIDRegistry, "awid-registry", "", "Base URL for the awid registry used by aw init (overrides AWID_REGISTRY_URL)")
	initCmd.Flags().BoolVar(&initHosted, "hosted", false, "Create a hosted aweb.ai identity in this directory")
	initCmd.Flags().StringVar(&initHostedUsername, "username", "", "Hosted username to create with --hosted")
	initCmd.Flags().StringVar(&initAlias, "alias", "", "Ephemeral identity routing alias (optional; default: server-suggested)")
	initCmd.Flags().StringVar(&initName, "name", "", "Persistent identity name (required with --persistent unless .aw/identity.yaml already exists)")
	initCmd.Flags().StringVar(&initReachability, "reachability", "", "Persistent address reachability (nobody|org-only|team-members-only|public)")
	initCmd.Flags().BoolVar(&initInjectDocs, "inject-docs", false, "Inject aw coordination instructions into CLAUDE.md and AGENTS.md")
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
			Name:         strings.TrimSpace(initName),
			Alias:        resolveAliasValue(strings.TrimSpace(initAlias)),
			Reachability: strings.TrimSpace(initReachability),
			Role:         resolveRequestedRole(strings.TrimSpace(initRole)),
			HumanName:   resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:   resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
			Persistent:  initPersistent,
		})
		if err != nil {
			return err
		}
		printOutput(result, formatConnect)
		if err := runRequestedInitPostSetup(wd); err != nil {
			return err
		}
		if !jsonFlag {
			printPostInitActions(&initResult{
				ServerName:    hostFromBaseURL(result.AwebURL),
				ExportBaseURL: result.AwebURL,
				Alias:         strings.TrimSpace(result.Alias),
			}, wd)
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
			if !jsonFlag {
				printPostInitActions(&initResult{
					ServerName:    hostFromBaseURL(serviceURLs.AwebURL),
					ExportBaseURL: serviceURLs.AwebURL,
					Alias:         strings.TrimSpace(result.Alias),
				}, wd)
			}
			return nil
		}
	}

	if hostedInitRequested() {
		return runHostedInit(cmd)
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
		if initRegistryIsLocalhost(registryURL) {
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
			if !jsonFlag {
				printPostInitActions(&initResult{
					ServerName:    hostFromBaseURL(awebURL),
					ExportBaseURL: awebURL,
					Alias:         strings.TrimSpace(result.Alias),
				}, wd)
			}
			return nil
		}
		if !initIsTTY() {
			return usageError("current directory is not initialized for aw; rerun `aw init` in a TTY for guided onboarding or get a team certificate first with `aw id team accept-invite`")
		}
		result, err := guidedOnboardingWizard(guidedOnboardingRequest{
			WorkingDir:  wd,
			PromptIn:    os.Stdin,
			PromptOut:   os.Stderr,
			BaseURL:     awebURL,
			RegistryURL: registryURL,
			ServerName:  serverFlag,
			Alias: func() string {
				if initPersistent {
					return strings.TrimSpace(initAlias)
				}
				return resolveAliasValue(strings.TrimSpace(initAlias))
			}(),
			Name:               strings.TrimSpace(initName),
			Reachability:       strings.TrimSpace(initReachability),
			HumanName:          resolveHumanNameValue(strings.TrimSpace(initHumanName)),
			AgentType:          resolveAgentTypeValue(strings.TrimSpace(initAgentType)),
			Role:               resolveRequestedRole(strings.TrimSpace(initRole)),
			Persistent:         initPersistent,
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
	return usageError("this directory already has a workspace; use a fresh directory")
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

func hostedInitRequested() bool {
	return initHosted || strings.TrimSpace(initHostedUsername) != ""
}

// initNeedsFullInit returns true if the user passed flags that require the
// full init flow, or if no local workspace binding exists yet (first-time init).
func initNeedsFullInit() bool {
	if initURL != "" || initAwebURL != "" || initAWIDRegistry != "" || initAlias != "" || initName != "" || initReachability != "" || initRole != "" || initPersistent {
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
	fmt.Println("Ask it to read the agent guide at https://aweb.ai/agent-guide.md")
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

func promptIdentityLifetime(in io.Reader, out io.Writer) (bool, error) {
	fmt.Fprintf(out, "  1. Ephemeral — workspace-bound, for internal coordination\n")
	fmt.Fprintf(out, "  2. Persistent — survives beyond this workspace, can own public addresses\n")
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

func printPostInitActions(result *initResult, workingDir string) {
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
	lines = append(lines, "  Start Claude Code with the channel enabled:")
	lines = append(lines, "    claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace")
	lines = append(lines, "")
	lines = append(lines, "  Agent guide: docs/agent-guide.md")
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
