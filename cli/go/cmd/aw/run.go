package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	awrun "github.com/awebai/aw/run"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	runWaitSeconds   int
	runContinueMode  bool
	runMaxRuns       int
	runIdleWait      int
	runInitialPrompt string
	runBasePrompt    string
	runWorkPrompt    string
	runCommsPrompt   string
	runWorkingDir    string
	runAllowedTools  string
	runModel         string
	runProviderPTY   bool
	runAutofeedWork  bool
	runInitConfig    bool
)

var (
	runLoadUserConfig  = awrun.LoadUserConfig
	runInitUserConfig  = awrun.InitUserConfig
	runResolveSettings = awrun.ResolveSettings
	runNewProvider     = awrun.NewProvider
	runNewLoop         = awrun.NewLoop
	runExecuteLoop     = func(loop *awrun.Loop, ctx context.Context, opts awrun.LoopOptions) error { return loop.Run(ctx, opts) }
	runNewEventBus     = func(client *aweb.Client) *awrun.EventBus {
		return awrun.NewEventBus(awrun.EventBusConfig{
			Stream: awrun.NewEventStreamOpener(client.Client),
		})
	}
	runNewScreenController  = awrun.NewScreenController
	runResolveClientForDir  = resolveClientSelectionForDir
	runExecuteInitFlow      = executeInit
	runExecuteConnectFlow   = executeConnect
	runInspectCredential    = inspectRunCredentialKind
	runWorkspaceStateForDir = resolveRunWorkspaceStateForDir
	runPrintInitSummary     = printInitSummary
	runPrintPostInitActions = printPostInitActions
	runGetwd                = os.Getwd
)

var runCmd = &cobra.Command{
	Use:   "run <provider>",
	Short: "Start an AI coding agent here, onboarding this directory if needed",
	Long: `Start the requested AI coding agent in this directory.

In a TTY, if this directory is not initialized yet, aw run can guide you
through project creation, existing-project init, invite acceptance, or
identity import before starting the provider. The explicit bootstrap
commands remain available for scripts and expert use: aw project create,
aw init, aw spawn accept-invite, and aw connect.

Current implementation includes:
  - repeated provider invocations (currently Claude and Codex)
  - provider session continuity when --continue is requested
  - /stop, /wait, /resume, /autofeed on|off, /quit, and prompt override controls
  - aw event-stream wakeups for mail, chat, and optional work events
  - optional background services declared in aw run config

This aw-first command intentionally excludes bead-specific dispatch and policy glue.`,
	Args: cobra.MaximumNArgs(1),
	RunE: runRun,
}

func init() {
	runCmd.Flags().StringVar(&runInitialPrompt, "prompt", "", "Initial prompt for the first provider run")
	runCmd.Flags().StringVar(&runBasePrompt, "base-prompt", "", "Override the configured base mission prompt for this run")
	runCmd.Flags().StringVar(&runWorkPrompt, "work-prompt-suffix", "", "Override the configured work cycle prompt suffix for this run")
	runCmd.Flags().StringVar(&runCommsPrompt, "comms-prompt-suffix", "", "Override the configured comms cycle prompt suffix for this run")
	runCmd.Flags().IntVar(&runWaitSeconds, "wait", awrun.DefaultWaitSeconds, "Idle seconds per wake-stream wait cycle")
	runCmd.Flags().IntVar(&runIdleWait, "idle-wait", awrun.DefaultIdleWaitSeconds, "Reserved idle-wait setting for future dispatch modes")
	runCmd.Flags().BoolVar(&runContinueMode, "continue", false, "Continue the most recent provider session across runs")
	runCmd.Flags().BoolVar(&runContinueMode, "session", false, "Deprecated alias for --continue")
	_ = runCmd.Flags().MarkDeprecated("session", "use --continue instead")
	runCmd.Flags().IntVar(&runMaxRuns, "max-runs", 0, "Stop after N runs (0 means infinite)")
	runCmd.Flags().StringVar(&runWorkingDir, "dir", "", "Working directory for the agent process")
	runCmd.Flags().StringVar(&runAllowedTools, "allowed-tools", "", "Provider-specific allowed tools string")
	runCmd.Flags().StringVar(&runModel, "model", "", "Provider-specific model override")
	runCmd.Flags().BoolVar(&runProviderPTY, "provider-pty", false, "Run the provider subprocess inside a pseudo-terminal instead of plain pipes when interactive controls are available")
	runCmd.Flags().BoolVar(&runAutofeedWork, "autofeed-work", false, "Wake for work-related events in addition to incoming mail/chat")
	runCmd.Flags().BoolVar(&runInitConfig, "init", false, "Prompt for ~/.config/aw/run.json values and write them")

	rootCmd.AddCommand(runCmd)
}

func runRun(cmd *cobra.Command, args []string) error {
	if runMaxRuns < 0 {
		return fmt.Errorf("--max-runs must be >= 0")
	}

	workingDir, err := effectiveRunDir()
	if err != nil {
		return err
	}

	runCfg, err := runLoadUserConfig(workingDir)
	if err != nil {
		return err
	}
	if runInitConfig {
		return runInitUserConfig(cmd.InOrStdin(), cmd.OutOrStdout(), runCfg)
	}

	settings, err := runResolveSettings(runCfg, awrun.SettingOverrides{
		BasePrompt:        changedStringPtr(cmd, "base-prompt", runBasePrompt),
		WorkPromptSuffix:  changedStringPtr(cmd, "work-prompt-suffix", runWorkPrompt),
		CommsPromptSuffix: changedStringPtr(cmd, "comms-prompt-suffix", runCommsPrompt),
		WaitSeconds:       changedIntPtr(cmd, "wait", runWaitSeconds),
		IdleWaitSeconds:   changedIntPtr(cmd, "idle-wait", runIdleWait),
	})
	if err != nil {
		return err
	}

	screen := runNewScreenController(cmd.InOrStdin(), cmd.OutOrStdout())
	promptInput := bufferedPromptReader(cmd.InOrStdin())
	providerName, initialPrompt, err := resolveRunInvocation(cmd, args, screen != nil, promptInput)
	if err != nil {
		return err
	}
	client, sel, err := resolveRunClientForDir(cmd, workingDir, screen != nil, promptInput)
	if err != nil {
		return err
	}
	allowInteractiveEmptyPrompt := screen != nil
	if strings.TrimSpace(settings.BasePrompt) == "" && initialPrompt == "" && !allowInteractiveEmptyPrompt {
		return usageError("missing prompt (pass --prompt, --base-prompt, or configure base_prompt with `aw run --init`)")
	}

	provider, err := runNewProvider(providerName)
	if err != nil {
		return err
	}

	repoSlug := runDetectRepoSlug(workingDir)
	statusIdentity := awrun.StatusIdentity(providerName, sel.NamespaceSlug, repoSlug, sel.IdentityHandle)

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()

	loop := runNewLoop(provider, cmd.OutOrStdout())
	loop.EventBus = runNewEventBus(client)
	loop.Control = screen
	loop.Dispatch = newRunDispatcher(settings, newRunWakeValidator(client))
	loop.StatusIdentity = statusIdentity
	loop.OnUserPrompt = func(text string) {
		appendInteractionLogForDir(workingDir, &InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindUser,
			Text:      text,
		})
	}
	loop.OnRunComplete = func(summary awrun.RunSummary) {
		appendInteractionLogForDir(workingDir, &InteractionEntry{
			Timestamp: time.Now().UTC().Format(time.RFC3339),
			Kind:      interactionKindAgent,
			SessionID: summary.SessionID,
			Text:      summary.AgentText,
		})
	}

	if runContinueMode {
		if recap := loadRunContinueRecap(workingDir, cmd.OutOrStdout()); recap != "" {
			fmt.Fprint(cmd.OutOrStdout(), recap)
		}
	}

	opts := awrun.LoopOptions{
		InitialPrompt:   initialPrompt,
		BasePrompt:      settings.BasePrompt,
		WaitSeconds:     settings.WaitSeconds,
		IdleWaitSeconds: settings.IdleWaitSeconds,
		MaxRuns:         runMaxRuns,
		Autofeed:        runAutofeedWork,
		ContinueMode:    runContinueMode,
		WorkingDir:      workingDir,
		AllowedTools:    runAllowedTools,
		Model:           runModel,
		ProviderPTY:     effectiveProviderPTY(cmd, screen != nil),
		Services:        settings.Services,
	}

	err = runExecuteLoop(loop, ctx, opts)
	if err == nil || err == context.Canceled {
		return nil
	}
	return err
}

func loadRunContinueRecap(workingDir string, out io.Writer) string {
	entries, err := readInteractionLog(interactionLogPath(workingDir), 8)
	if err != nil {
		return ""
	}
	return formatInteractionRecapStyled(entries, 8, writerSupportsANSI(out), writerDisplayWidth(out))
}

func writerSupportsANSI(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	return term.IsTerminal(int(f.Fd()))
}

func writerDisplayWidth(w io.Writer) int {
	f, ok := w.(*os.File)
	if !ok {
		return 80
	}
	width, _, err := term.GetSize(int(f.Fd()))
	if err != nil || width <= 0 {
		return 80
	}
	return width
}

func effectiveProviderPTY(cmd *cobra.Command, interactive bool) bool {
	if !interactive {
		return false
	}
	if cmd != nil && cmd.Flags().Changed("provider-pty") {
		return runProviderPTY
	}
	return false
}

func runDetectRepoSlug(dir string) string {
	cmd := exec.Command("git", "-C", dir, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return awrun.ShortRepoName(strings.TrimSpace(string(out)), "")
}

func effectiveRunDir() (string, error) {
	dir := strings.TrimSpace(runWorkingDir)
	if dir == "" {
		return runGetwd()
	}
	return filepath.Abs(dir)
}

func changedStringPtr(cmd *cobra.Command, name string, value string) *string {
	if !cmd.Flags().Changed(name) {
		return nil
	}
	result := value
	return &result
}

func changedIntPtr(cmd *cobra.Command, name string, value int) *int {
	if !cmd.Flags().Changed(name) {
		return nil
	}
	result := value
	return &result
}

func initRunCommandVars() {
	runWaitSeconds = awrun.DefaultWaitSeconds
	runContinueMode = false
	runMaxRuns = 0
	runIdleWait = awrun.DefaultIdleWaitSeconds
	runInitialPrompt = ""
	runBasePrompt = ""
	runWorkPrompt = ""
	runCommsPrompt = ""
	runWorkingDir = ""
	runAllowedTools = ""
	runModel = ""
	runProviderPTY = false
	runAutofeedWork = false
	runInitConfig = false
}

func setRunCommandIO(cmd *cobra.Command, in io.Reader, out io.Writer, errOut io.Writer) {
	cmd.SetIn(in)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
}

func resolveRunInvocation(cmd *cobra.Command, args []string, interactive bool, promptInput io.Reader) (string, string, error) {
	providerName := ""
	if len(args) > 0 {
		providerName = strings.TrimSpace(args[0])
	}
	if providerName == "" {
		if !interactive {
			return "", "", usageError("missing provider (use `aw run <provider>`)")
		}
		selected, err := promptIndexedChoice("Provider", []string{"claude", "codex"}, 0, promptInput, cmd.ErrOrStderr())
		if err != nil {
			return "", "", err
		}
		providerName = strings.TrimSpace(selected)
	}
	return providerName, strings.TrimSpace(runInitialPrompt), nil
}

type runWorkspaceState int

const (
	runWorkspaceStateInitialized runWorkspaceState = iota
	runWorkspaceStateMissing
)

type runCredentialKind int

const (
	runCredentialKindProject runCredentialKind = iota
	runCredentialKindIdentity
	runCredentialKindUser
)

func resolveRunClientForDir(cmd *cobra.Command, workingDir string, interactive bool, promptInput io.Reader) (*aweb.Client, *awconfig.Selection, error) {
	state, err := runWorkspaceStateForDir(workingDir)
	if err != nil {
		return nil, nil, err
	}
	if state == runWorkspaceStateMissing {
		if !interactive {
			return nil, nil, usageError("current directory is not initialized for aw; run `aw project create`, `aw init`, `aw spawn accept-invite`, or `aw connect`, or rerun in a TTY for guided onboarding")
		}
		proceed, promptErr := promptRunYesNo(
			"This directory is not initialized as an aweb workspace. Initialize now?",
			true,
			promptInput,
			cmd.ErrOrStderr(),
		)
		if promptErr != nil {
			return nil, nil, promptErr
		}
		if !proceed {
			return nil, nil, usageError("current directory is not initialized for aw; run `aw project create`, `aw init`, `aw spawn accept-invite`, or `aw connect`")
		}

		if onboardingErr := runOnboardingWizard(cmd, workingDir, promptInput); onboardingErr != nil {
			return nil, nil, onboardingErr
		}
	}

	client, sel, err := runResolveClientForDir(workingDir)
	if err != nil {
		return nil, nil, err
	}
	return client, sel, nil
}

func resolveRunWorkspaceStateForDir(workingDir string) (runWorkspaceState, error) {
	_, _, err := awconfig.LoadWorktreeContextFromDir(workingDir)
	if err == nil {
		return runWorkspaceStateInitialized, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return runWorkspaceStateMissing, nil
	}
	return runWorkspaceStateInitialized, fmt.Errorf("invalid local workspace context: %w", err)
}

func promptRunYesNo(label string, defaultYes bool, in io.Reader, out io.Writer) (bool, error) {
	defaultValue := "y"
	if !defaultYes {
		defaultValue = "n"
	}
	answer, err := promptStringWithIO(label+" (y/n)", defaultValue, in, out)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, usageError("please answer y or n")
	}
}

func runOnboardingWizard(cmd *cobra.Command, workingDir string, promptInput io.Reader) error {
	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) != "" {
		return runWizardUseProvidedKey(cmd, workingDir, promptInput, strings.TrimSpace(os.Getenv("AWEB_API_KEY")))
	}

	hasProject, err := promptRunYesNo("Do you already have an aweb project?", true, promptInput, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	if hasProject {
		return runWizardJoinExistingProject(cmd, workingDir, promptInput)
	}
	return runWizardCreateProject(cmd, workingDir, promptInput)
}

func runWizardUseProvidedKey(cmd *cobra.Command, workingDir string, promptInput io.Reader, apiKey string) error {
	serverURL, err := promptRequiredStringWithIO("Server URL", defaultWizardServerURL(), promptInput, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	baseURL, _, _, err := initResolveBaseURLForCollection(serverURL, serverFlag)
	if err != nil {
		return err
	}
	kind, err := runInspectCredential(baseURL, apiKey)
	if err != nil {
		return err
	}
	switch kind {
	case runCredentialKindIdentity:
		fmt.Fprintln(cmd.ErrOrStderr(), "Using an identity-bound API key to connect this directory.")
		return runWizardConnectExistingIdentity(cmd, workingDir, baseURL, apiKey)
	case runCredentialKindProject:
		fmt.Fprintln(cmd.ErrOrStderr(), "Using a project-scoped API key to initialize this directory in an existing project.")
		return runWizardInitExistingProject(cmd, workingDir, promptInput, serverURL, apiKey)
	default:
		return usageError("this API key is not usable for agent onboarding; use a project-scoped key, an identity-bound key, or a spawn invite")
	}
}

func runWizardInitExistingProject(cmd *cobra.Command, workingDir string, promptInput io.Reader, serverURL, apiKey string) error {
	opts, err := collectInitOptionsWithInput(flowProjectKey, initCollectionInput{
		WorkingDir:   workingDir,
		Interactive:  true,
		PromptIn:     promptInput,
		PromptOut:    cmd.ErrOrStderr(),
		ServerURL:    serverURL,
		ServerName:   serverFlag,
		Alias:        resolveAliasValue(""),
		HumanName:    resolveHumanName(),
		AgentType:    resolveAgentType(),
		SaveConfig:   true,
		WriteContext: true,
		AuthToken:    strings.TrimSpace(apiKey),
	})
	if err != nil {
		return err
	}

	result, err := runExecuteInitFlow(opts)
	if err != nil {
		return err
	}
	runPrintInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, workingDir, "Initialized workspace")
	runPrintPostInitActions(result, workingDir)
	return nil
}

func runWizardConnectExistingIdentity(cmd *cobra.Command, workingDir, baseURL, apiKey string) error {
	result, err := runExecuteConnectFlow(connectOptions{
		WorkingDir: workingDir,
		BaseURL:    baseURL,
		APIKey:     apiKey,
		SetDefault: false,
	})
	if err != nil {
		return err
	}
	printConnectSummary(cmd.ErrOrStderr(), result)
	return nil
}

func runWizardCreateProject(cmd *cobra.Command, workingDir string, promptInput io.Reader) error {
	serverURL, err := promptRequiredStringWithIO("Server URL", defaultWizardServerURL(), promptInput, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	opts, err := collectInitOptionsWithInput(flowHeadless, initCollectionInput{
		WorkingDir:   workingDir,
		Interactive:  true,
		PromptIn:     promptInput,
		PromptOut:    cmd.ErrOrStderr(),
		ServerURL:    serverURL,
		ServerName:   serverFlag,
		ProjectSlug:  sanitizeSlug(filepath.Base(workingDir)),
		Alias:        resolveAliasValue(""),
		HumanName:    resolveHumanName(),
		AgentType:    resolveAgentType(),
		SaveConfig:   true,
		WriteContext: true,
	})
	if err != nil {
		return err
	}

	result, err := runExecuteInitFlow(opts)
	if err != nil {
		return err
	}
	runPrintInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, workingDir, "Created project and initialized workspace")
	runPrintPostInitActions(result, workingDir)
	return nil
}

func defaultWizardServerURL() string {
	serverDefault := strings.TrimSpace(os.Getenv("AWEB_URL"))
	if serverDefault == "" {
		serverDefault = DefaultServerURL
	}
	return serverDefault
}

func runWizardJoinExistingProject(cmd *cobra.Command, workingDir string, promptInput io.Reader) error {
	choice, err := promptIndexedChoice(
		"Join path",
		[]string{
			"Use a spawn invite token",
			"Use a key from the dashboard",
			"Stop and get credentials first",
		},
		0,
		promptInput,
		cmd.ErrOrStderr(),
	)
	if err != nil {
		return err
	}
	if choice == "Use a key from the dashboard" {
		apiKey, err := promptRequiredStringWithIO("API key", strings.TrimSpace(os.Getenv("AWEB_API_KEY")), promptInput, cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		return runWizardUseProvidedKey(cmd, workingDir, promptInput, apiKey)
	}
	if choice != "Use a spawn invite token" {
		return usageError("get a spawn invite from another agent with `aw spawn create-invite`, or get AWEB_URL/AWEB_API_KEY from the dashboard and use `aw init` or `aw connect`")
	}

	token, err := promptRequiredStringWithIO("Invite token", "", promptInput, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	serverURL, err := promptRequiredStringWithIO("Server URL", defaultWizardServerURL(), promptInput, cmd.ErrOrStderr())
	if err != nil {
		return err
	}
	opts, err := collectInviteInitOptionsWithInput(token, initCollectionInput{
		WorkingDir:   workingDir,
		Interactive:  true,
		PromptIn:     promptInput,
		PromptOut:    cmd.ErrOrStderr(),
		ServerURL:    serverURL,
		ServerName:   serverFlag,
		Alias:        resolveAliasValue(""),
		HumanName:    resolveHumanName(),
		AgentType:    resolveAgentType(),
		SaveConfig:   true,
		WriteContext: true,
		Role:         resolveRequestedRole(""),
	})
	if err != nil {
		return err
	}

	result, err := runExecuteInitFlow(opts)
	if err != nil {
		return err
	}
	runPrintInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, workingDir, "Accepted spawn invite")
	runPrintPostInitActions(result, workingDir)
	return nil
}

func inspectRunCredentialKind(baseURL, apiKey string) (runCredentialKind, error) {
	client, err := aweb.NewWithAPIKey(baseURL, strings.TrimSpace(apiKey))
	if err != nil {
		return runCredentialKindUser, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := client.Introspect(ctx)
	if err != nil {
		return runCredentialKindUser, err
	}
	if strings.TrimSpace(resp.CurrentIdentityID()) != "" {
		return runCredentialKindIdentity, nil
	}
	if strings.TrimSpace(resp.ProjectID) != "" {
		return runCredentialKindProject, nil
	}
	return runCredentialKindUser, nil
}
