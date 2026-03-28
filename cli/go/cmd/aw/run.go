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
	"slices"
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
	runTripOnDanger  bool
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
	runNewScreenController   = awrun.NewScreenController
	runResolveClientForDir   = resolveClientSelectionForDir
	runExecuteInitFlow       = executeInit
	runWorkspaceStateForDir  = resolveRunWorkspaceStateForDir
	runPrintInitSummary      = printInitSummary
	runGetwd                 = os.Getwd
	runInjectDocs            = InjectAgentDocs
	runSetupHooks            = SetupClaudeHooks
	runResolveClaimedTaskRef = resolveRunClaimedTaskRef
)

var runCmd = &cobra.Command{
	Use:   "run <provider>",
	Short: "Start an AI coding agent here, onboarding this directory if needed",
	Long: `Start the requested AI coding agent in this directory.

In a TTY, if this directory is not initialized yet, aw run can guide you
through new-project creation or existing-project init before starting the
provider. The explicit bootstrap commands remain available for scripts and
expert use: aw project create, aw init, aw spawn accept-invite, and aw connect.

Current implementation includes:
  - repeated provider invocations (currently Claude and Codex)
  - provider session continuity when --continue is requested
  - /stop, /wait, /resume, /autofeed on|off, /quit, and prompt override controls
  - aw event-stream wakeups for mail, chat, and optional work events
  - optional background services declared in aw run config

This aw-first command intentionally excludes bead-specific dispatch.`,
	Args: cobra.ArbitraryArgs,
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
	runCmd.Flags().BoolVar(&runTripOnDanger, "trip-on-danger", false, "Remove provider bypass flags and use native provider safety checks")
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
	providerName, initialPrompt, providerArgs, err := resolveRunInvocation(cmd, args, screen != nil, promptInput)
	if err != nil {
		return err
	}
	client, sel, onboarding, err := resolveRunClientForDir(cmd, workingDir, screen != nil, promptInput)
	if err != nil {
		return err
	}
	if strings.TrimSpace(initialPrompt) == "" && onboarding != nil && strings.TrimSpace(onboarding.InitialPrompt) != "" {
		initialPrompt = strings.TrimSpace(onboarding.InitialPrompt)
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
	claimedTaskRef := ""
	if taskRef, taskErr := runResolveClaimedTaskRef(cmd.Context(), client, sel.IdentityID); taskErr == nil {
		claimedTaskRef = taskRef
	}

	ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt)
	defer stop()

	loop := runNewLoop(provider, cmd.OutOrStdout())
	lastSessionID := ""
	var lastBuildOptions awrun.BuildOptions
	loop.EventBus = runNewEventBus(client)
	loop.Control = screen
	loop.Dispatch = newRunDispatcher(settings, newRunWakeValidator(client, sel.IdentityHandle))
	loop.StatusIdentity = statusIdentity
	loop.OnSessionID = func(sessionID string) {
		lastSessionID = strings.TrimSpace(sessionID)
	}
	loop.OnBuildCommand = func(_ []string, opts awrun.BuildOptions) {
		lastBuildOptions = opts
	}
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
		TripOnDanger:    runTripOnDanger,
		ClaimedTaskRef:  claimedTaskRef,
		ProviderArgs:    providerArgs,
		ProviderPTY:     effectiveProviderPTY(cmd, screen != nil),
		Services:        settings.Services,
	}

	err = runExecuteLoop(loop, ctx, opts)
	printRunExitCommands(cmd.OutOrStdout(), providerName, workingDir, provider, lastSessionID, lastBuildOptions)
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

func resolveRunInvocation(cmd *cobra.Command, args []string, interactive bool, promptInput io.Reader) (string, string, []string, error) {
	positionalArgs, providerArgs, err := splitRunInvocationArgs(args, argsLenAtDash(cmd))
	if err != nil {
		return "", "", nil, err
	}
	providerName := ""
	if len(positionalArgs) > 0 {
		providerName = strings.TrimSpace(positionalArgs[0])
	}
	if providerName == "" {
		if !interactive {
			return "", "", nil, usageError("missing provider (use `aw run <provider>`)")
		}
		selected, err := promptIndexedChoice("Provider", []string{"claude", "codex"}, 0, promptInput, cmd.ErrOrStderr())
		if err != nil {
			return "", "", nil, err
		}
		providerName = strings.TrimSpace(selected)
	}
	return providerName, strings.TrimSpace(runInitialPrompt), providerArgs, nil
}

func splitRunInvocationArgs(args []string, argsLenAtDash int) ([]string, []string, error) {
	parts := slices.Clone(args)
	if argsLenAtDash < 0 {
		if len(parts) > 1 {
			return nil, nil, usageError("unexpected arguments after provider; use `--` to pass flags through to the provider")
		}
		return parts, nil, nil
	}
	if argsLenAtDash > len(parts) {
		argsLenAtDash = len(parts)
	}
	positional := slices.Clone(parts[:argsLenAtDash])
	if len(positional) > 1 {
		return nil, nil, usageError("unexpected arguments before `--`; expected only the provider name")
	}
	return positional, slices.Clone(parts[argsLenAtDash:]), nil
}

func argsLenAtDash(cmd *cobra.Command) int {
	if cmd == nil {
		return -1
	}
	return cmd.ArgsLenAtDash()
}

func printRunExitCommands(out io.Writer, providerName string, workingDir string, provider awrun.Provider, sessionID string, buildOpts awrun.BuildOptions) {
	sessionID = strings.TrimSpace(sessionID)
	if out == nil || provider == nil || sessionID == "" {
		return
	}

	resumeOpts := buildOpts
	resumeOpts.SessionID = sessionID
	resumeOpts.ContinueSession = false
	resumeOpts.AddDirs = append([]string(nil), buildOpts.AddDirs...)
	resumeOpts.ProviderArgs = append([]string(nil), buildOpts.ProviderArgs...)

	providerCommand, err := provider.BuildResumeCommand(resumeOpts)
	if err != nil {
		return
	}

	awCommand := []string{"aw", "run"}
	if dir := strings.TrimSpace(workingDir); dir != "" {
		awCommand = append(awCommand, "--dir", dir)
	}
	if name := strings.TrimSpace(providerName); name != "" {
		awCommand = append(awCommand, name)
	}
	awCommand = append(awCommand, "--continue")

	fmt.Fprintf(out, "\nSession %s\n", sessionID)
	fmt.Fprintf(out, "Continue with aw:\n  %s\n\n", formatShellCommand(awCommand))
	fmt.Fprintf(out, "Run %s directly:\n  %s\n", provider.Name(), formatShellCommand(providerCommand))
}

func formatShellCommand(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, arg := range argv {
		parts = append(parts, shellQuote(arg))
	}
	return strings.Join(parts, " ")
}

func shellQuote(arg string) string {
	if arg == "" {
		return "''"
	}
	if !strings.ContainsAny(arg, " \t\n'\"\\$`()[]{}*?<>|&;!") {
		return arg
	}
	return "'" + strings.ReplaceAll(arg, "'", `'"'"'`) + "'"
}

func resolveRunClaimedTaskRef(ctx context.Context, client *aweb.Client, workspaceID string) (string, error) {
	if client == nil || strings.TrimSpace(workspaceID) == "" {
		return "", nil
	}
	statusCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	resp, err := client.ClaimsList(statusCtx, strings.TrimSpace(workspaceID), 1)
	if err != nil {
		return "", err
	}
	if resp == nil || len(resp.Claims) == 0 {
		return "", nil
	}
	return strings.TrimSpace(resp.Claims[0].BeadID), nil
}

type runWorkspaceState int

const (
	runWorkspaceStateInitialized runWorkspaceState = iota
	runWorkspaceStateMissing
)

type runOnboardingResult struct {
	InitialPrompt string
}

func resolveRunClientForDir(cmd *cobra.Command, workingDir string, interactive bool, promptInput io.Reader) (*aweb.Client, *awconfig.Selection, *runOnboardingResult, error) {
	state, err := runWorkspaceStateForDir(workingDir)
	if err != nil {
		return nil, nil, nil, err
	}
	if state == runWorkspaceStateMissing {
		if !interactive {
			return nil, nil, nil, usageError("current directory is not initialized for aw; run `aw project create`, `aw init`, `aw spawn accept-invite`, or `aw connect`, or rerun in a TTY for guided onboarding")
		}
		proceed, promptErr := promptRunYesNo(
			"This directory is not initialized as an aweb workspace. Initialize now?",
			true,
			promptInput,
			cmd.ErrOrStderr(),
		)
		if promptErr != nil {
			return nil, nil, nil, promptErr
		}
		if !proceed {
			return nil, nil, nil, usageError("current directory is not initialized for aw; run `aw project create`, `aw init`, `aw spawn accept-invite`, or `aw connect`")
		}

		onboarding, onboardingErr := runOnboardingWizard(cmd, workingDir, promptInput)
		if onboardingErr != nil {
			return nil, nil, nil, onboardingErr
		}
		client, sel, err := runResolveClientForDir(workingDir)
		if err != nil {
			return nil, nil, nil, err
		}
		return client, sel, onboarding, nil
	}

	client, sel, err := runResolveClientForDir(workingDir)
	if err != nil {
		return nil, nil, nil, err
	}
	return client, sel, nil, nil
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

func runOnboardingWizard(cmd *cobra.Command, workingDir string, promptInput io.Reader) (*runOnboardingResult, error) {
	if strings.TrimSpace(os.Getenv("AWEB_API_KEY")) != "" {
		return runWizardInitExistingProject(cmd, workingDir, promptInput, strings.TrimSpace(os.Getenv("AWEB_API_KEY")))
	}
	return runWizardCreateProject(cmd, workingDir, promptInput)
}

func runWizardInitExistingProject(cmd *cobra.Command, workingDir string, promptInput io.Reader, apiKey string) (*runOnboardingResult, error) {
	serverURL, err := promptRequiredStringWithIO("Server URL", defaultWizardServerURL(), promptInput, cmd.ErrOrStderr())
	if err != nil {
		return nil, err
	}
	permanent, err := promptIdentityLifetime(promptInput, cmd.ErrOrStderr())
	if err != nil {
		return nil, err
	}
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
		Permanent:    permanent,
		PromptRole:   true,
		PromptName:   true,
	})
	if err != nil {
		return nil, err
	}

	result, err := runExecuteInitFlow(opts)
	if err != nil {
		return nil, err
	}
	runPrintInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, workingDir, "Initialized workspace")
	return &runOnboardingResult{}, nil
}

func runWizardCreateProject(cmd *cobra.Command, workingDir string, promptInput io.Reader) (*runOnboardingResult, error) {
	serverURL, err := promptRequiredStringWithIO("Server URL", defaultWizardServerURL(), promptInput, cmd.ErrOrStderr())
	if err != nil {
		return nil, err
	}
	projectSlug, err := promptStringWithIO("Project", sanitizeSlug(filepath.Base(workingDir)), promptInput, cmd.ErrOrStderr())
	if err != nil {
		return nil, err
	}
	permanent, err := promptIdentityLifetime(promptInput, cmd.ErrOrStderr())
	if err != nil {
		return nil, err
	}
	opts, err := collectInitOptionsWithInput(flowHeadless, initCollectionInput{
		WorkingDir:       workingDir,
		Interactive:      true,
		PromptIn:         promptInput,
		PromptOut:        cmd.ErrOrStderr(),
		ServerURL:        serverURL,
		ServerName:       serverFlag,
		ProjectSlug:      sanitizeSlug(projectSlug),
		Alias:            "",
		HumanName:        resolveHumanName(),
		AgentType:        resolveAgentType(),
		SaveConfig:       true,
		WriteContext:     true,
		Permanent:        permanent,
		PromptName:       true,
		DeferAliasPrompt: true,
		DeferRolePrompt:  true,
	})
	if err != nil {
		return nil, err
	}

	result, err := runExecuteInitFlow(opts)
	if err != nil {
		return nil, err
	}
	runPrintInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, workingDir, "Created project and initialized workspace")

	if docs, err := promptRunYesNo("Inject agent docs into this repo?", false, promptInput, cmd.ErrOrStderr()); err == nil && docs {
		printInjectDocsResult(runInjectDocs(resolveRepoRoot(workingDir)))
	} else if err != nil {
		return nil, err
	}
	if hooks, err := promptRunYesNo("Set up Claude hooks for aw notify?", false, promptInput, cmd.ErrOrStderr()); err == nil && hooks {
		printClaudeHooksResult(runSetupHooks(resolveRepoRoot(workingDir), false))
	} else if err != nil {
		return nil, err
	}
	return &runOnboardingResult{InitialPrompt: "Download and study the agent guide at https://aweb.ai/agent-guide.txt before doing anything else."}, nil
}

func defaultWizardServerURL() string {
	if serverURL := strings.TrimSpace(os.Getenv("AWEB_URL")); serverURL != "" {
		return serverURL
	}
	return DefaultServerURL
}
