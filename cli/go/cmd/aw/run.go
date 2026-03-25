package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	aweb "github.com/awebai/aw"
	awrun "github.com/awebai/aw/run"
	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var (
	runWaitSeconds  int
	runContinueMode bool
	runMaxRuns      int
	runIdleWait     int
	runBasePrompt   string
	runWorkPrompt   string
	runCommsPrompt  string
	runWorkingDir   string
	runAllowedTools string
	runModel        string
	runProviderName string
	runProviderPTY  bool
	runAutofeedWork bool
	runInitConfig   bool
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
	runNewScreenController = awrun.NewScreenController
	runResolveClientForDir = resolveClientSelectionForDir
	runGetwd               = os.Getwd
)

var runCmd = &cobra.Command{
	Use:   "run [prompt]",
	Short: "Run an AI coding agent in a loop",
	Long: `Run an AI coding agent in a loop.

Current implementation includes:
  - repeated provider invocations (currently Claude and Codex)
  - provider session continuity when --continue is requested
  - /stop, /wait, /resume, /autofeed on|off, /quit, and prompt override controls
  - aw event-stream wakeups for mail, chat, and optional work events
  - optional background services declared in aw run config

This aw-first command intentionally excludes bead-specific dispatch and policy glue.`,
	Args: cobra.ArbitraryArgs,
	RunE: runRun,
}

func init() {
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
	runCmd.Flags().StringVar(&runProviderName, "provider", "claude", "Agent provider to run")
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

	initialPrompt := strings.TrimSpace(strings.Join(args, " "))
	screen := runNewScreenController(cmd.InOrStdin(), cmd.OutOrStdout())
	allowInteractiveEmptyPrompt := screen != nil
	if strings.TrimSpace(settings.BasePrompt) == "" && initialPrompt == "" && !allowInteractiveEmptyPrompt {
		return usageError("missing prompt (pass a prompt argument, --base-prompt, or configure base_prompt with `aw run --init`)")
	}

	provider, err := runNewProvider(runProviderName)
	if err != nil {
		return err
	}

	client, sel, err := runResolveClientForDir(workingDir)
	if err != nil {
		return err
	}

	repoSlug := runDetectRepoSlug(workingDir)
	statusIdentity := awrun.StatusIdentity(runProviderName, sel.NamespaceSlug, repoSlug, sel.IdentityHandle)

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
	runBasePrompt = ""
	runWorkPrompt = ""
	runCommsPrompt = ""
	runWorkingDir = ""
	runAllowedTools = ""
	runModel = ""
	runProviderName = "claude"
	runProviderPTY = false
	runAutofeedWork = false
	runInitConfig = false
}

func setRunCommandIO(cmd *cobra.Command, in io.Reader, out io.Writer, errOut io.Writer) {
	cmd.SetIn(in)
	cmd.SetOut(out)
	cmd.SetErr(errOut)
}
