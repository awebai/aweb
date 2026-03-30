package run

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	awid "github.com/awebai/aw/awid"
)

type Loop struct {
	Provider          Provider
	Runner            CommandRunner
	Sleep             SleepFunc
	EventBus          *EventBus
	ServiceSupervisor ServiceSupervisor
	Out               io.Writer
	Control           InputController
	Dispatch          Dispatcher
	Now               func() time.Time
	InputPromptLabel  string
	StatusIdentity    string
	OnUserPrompt      func(string)
	OnRunComplete     func(RunSummary)
	OnSessionID       func(string)
	OnBuildCommand    func([]string, BuildOptions)

	writeMu sync.Mutex
}

type state struct {
	Run                int
	RunPhase           RunPhase
	CumulativeCostUSD  float64
	SessionID          string
	RanOnce            bool
	RunInterrupted     bool
	PauseAfterRun      bool
	PauseNoticeShown   bool
	StopRequested      bool
	Paused             bool
	ExitConfirmPending bool
	Autofeed           bool
	NextPrompt         string
	NextImagePaths     []string
	PendingInput       bool
	InputBuffer        string
	StructuredOut      bool
	LastWakeEvent      *awid.AgentEvent
	LastRunError       string
	LastRunUsage       UsageStats
	HasRunUsage        bool
	ConnState          ConnectionState
	ProviderInput      *providerInputState
	ClaimedTaskRef     string
}

type providerInputState struct {
	mu     sync.Mutex
	writer io.WriteCloser
}

func (p *providerInputState) SetWriter(w io.WriteCloser) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writer = w
}

func (p *providerInputState) Clear() {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	p.writer = nil
}

func (p *providerInputState) SendLine(text string) error {
	if p == nil {
		return fmt.Errorf("provider input unavailable")
	}
	p.mu.Lock()
	writer := p.writer
	p.mu.Unlock()
	if writer == nil {
		return fmt.Errorf("provider input unavailable")
	}
	if _, err := io.WriteString(writer, text+"\n"); err != nil {
		return err
	}
	return nil
}

const (
	pausedNoticeText = "paused. type a prompt or clear the input to resume."
	pausedStatusText = "paused: type or clear input to resume"
	exitStatusText   = "exit aw run? [y/N]"
	startupBanner    = `                                         _           _
  __ ___      __  _    __ ___      _____| |__   __ _(_)
 / _` + "`" + ` \ \ /\ / / (_)  / _` + "`" + ` \ \ /\ / / _ \ '_ \ / _` + "`" + ` | |
| (_| |\ V  V /   _  | (_| |\ V  V /  __/ |_) | (_| | |
 \__,_| \_/\_/   (_)  \__,_| \_/\_/ \___|_.__(_)__,_|_|`
	helpText = `available commands:
  /wait           pause after the current run
  /stop           stop the current run and pause
  /provider TEXT  send one line to the active provider stdin
  /autofeed on    enable autofeed (work events wake the agent)
  /autofeed off   disable autofeed
  /quit           exit aw run
  /help           show this help`
)

func NewLoop(provider Provider, out io.Writer) *Loop {
	return &Loop{
		Provider:         provider,
		Runner:           RealCommandRunner,
		Sleep:            SleepWithContext,
		Out:              out,
		Now:              time.Now,
		InputPromptLabel: DefaultInputPromptLabel,
	}
}

func (l *Loop) Run(ctx context.Context, opts LoopOptions) error {
	if opts.MaxRuns < 0 {
		return fmt.Errorf("max runs must be >= 0")
	}
	if l.Provider == nil {
		return fmt.Errorf("provider is required")
	}
	if l.Runner == nil {
		l.Runner = RealCommandRunner
	}
	if l.Sleep == nil {
		l.Sleep = SleepWithContext
	}
	if l.Now == nil {
		l.Now = time.Now
	}
	if l.Out == nil {
		l.Out = io.Discard
	}
	if l.Dispatch == nil && strings.TrimSpace(opts.BasePrompt) == "" && strings.TrimSpace(opts.InitialPrompt) == "" && l.Control == nil {
		return fmt.Errorf("prompt cannot be empty when dispatch is unavailable")
	}

	state := &state{
		Autofeed:       opts.Autofeed,
		ClaimedTaskRef: strings.TrimSpace(opts.ClaimedTaskRef),
	}
	if l.Control != nil {
		if err := l.Control.Start(); err != nil {
			return err
		}
		defer func() { _ = l.Control.Stop() }()
	}
	serviceSupervisor := l.ServiceSupervisor
	if serviceSupervisor == nil && len(opts.Services) > 0 {
		serviceSupervisor = NewServiceManager(l.println)
	}
	if serviceSupervisor != nil && len(opts.Services) > 0 {
		if err := serviceSupervisor.Start(ctx, opts.Services, opts.WorkingDir); err != nil {
			return err
		}
		defer func() { _ = serviceSupervisor.Stop() }()
	}
	if l.EventBus != nil {
		l.EventBus.onStateChange = func(cs ConnectionState) {
			state.ConnState = cs
			l.refreshStatusLine(state)
		}
		l.EventBus.onError = func(ev awid.AgentEvent) {
			if text := strings.TrimSpace(ev.Text); text != "" {
				l.printf("info: event stream error: %s\n", text)
			} else {
				l.println("info: event stream error")
			}
		}
		l.EventBus.Start(ctx)
		defer l.EventBus.Stop()
	}
	l.refreshStatusLine(state)
	l.showStartupGreeting(opts, state)

	for {
		decision, err := l.nextPrompt(ctx, opts, state)
		if err != nil {
			return err
		}
		if decision.Skip {
			if err := l.waitForWork(ctx, decision.WaitSeconds, state); err != nil {
				if state.StopRequested && errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
			continue
		}

		mission := resolveMission(strings.TrimSpace(opts.BasePrompt), decision.Mission)
		fullPrompt := composeFullPrompt(mission, decision.CycleContext, opts.Services)
		cycleLabel := displayCycleLabel(mission, decision.CycleContext)
		displayLines := decision.DisplayLines
		if len(displayLines) == 0 {
			displayLines = formatUserInputDisplay(cycleLabel)
		}
		if strings.TrimSpace(fullPrompt) == "" {
			if l.Dispatch == nil && state.Run > 0 && strings.TrimSpace(opts.BasePrompt) == "" && strings.TrimSpace(opts.InitialPrompt) != "" {
				l.println("done: initial prompt consumed; use a persistent base prompt.")
				return nil
			}
			return fmt.Errorf("prompt cannot be empty")
		}
		state.Run++
		if err := l.runOnce(ctx, opts, state, fullPrompt, decision.ImagePaths, displayLines, decision.UserPrompt); err != nil {
			if state.StopRequested && (errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)) {
				return nil
			}
			return err
		}
		if state.ExitConfirmPending {
			if err := l.waitForExitConfirmation(ctx, state); err != nil {
				if state.StopRequested && errors.Is(err, context.Canceled) {
					return nil
				}
				return err
			}
		}
		if opts.MaxRuns > 0 && state.Run >= opts.MaxRuns {
			l.printf("\ndone: reached max-runs (%d)\n", opts.MaxRuns)
			return nil
		}
		if err := l.waitForNextCycle(ctx, decision.WaitSeconds, state); err != nil {
			if state.StopRequested && errors.Is(err, context.Canceled) {
				return nil
			}
			return err
		}
	}
}

func (l *Loop) nextPrompt(ctx context.Context, opts LoopOptions, st *state) (DispatchDecision, error) {
	queuedMissionPrompt := strings.TrimSpace(st.NextPrompt)
	queuedImagePaths := append([]string(nil), st.NextImagePaths...)
	if queuedMissionPrompt != "" {
		st.NextPrompt = ""
		st.NextImagePaths = nil
	}
	explicitMissionPrompt := queuedMissionPrompt
	if explicitMissionPrompt == "" && st.Run == 0 {
		explicitMissionPrompt = strings.TrimSpace(opts.InitialPrompt)
	}
	if explicitMissionPrompt != "" {
		return DispatchDecision{
			Mission:     explicitMissionPrompt,
			UserPrompt:  explicitMissionPrompt,
			ImagePaths:  queuedImagePaths,
			WaitSeconds: opts.WaitSeconds,
		}, nil
	}
	if st.Run == 0 && strings.TrimSpace(opts.BasePrompt) != "" {
		return DispatchDecision{Mission: strings.TrimSpace(opts.BasePrompt), WaitSeconds: opts.WaitSeconds}, nil
	}
	if l.Dispatch == nil && st.Run == 0 && l.Control != nil && strings.TrimSpace(opts.BasePrompt) == "" {
		return DispatchDecision{WaitSeconds: opts.WaitSeconds, Skip: true}, nil
	}
	if l.Dispatch != nil {
		wakeEvent := st.LastWakeEvent
		decision, err := l.Dispatch.Next(ctx, st.Autofeed, wakeEvent)
		if err != nil {
			l.printf("info: dispatch failed: %v\n", err)
			l.println("info: waiting for dispatch recovery before starting a run.")
			return DispatchDecision{WaitSeconds: opts.IdleWaitSeconds, Skip: true}, nil
		}
		if decision.Skip && decision.WaitSeconds <= 0 {
			decision.WaitSeconds = opts.WaitSeconds
		}
		st.LastWakeEvent = nil
		return decision, nil
	}
	// Without an external dispatcher, run one cycle then rely on wake/control
	// signals for subsequent cycles when event streaming is available.
	if st.Run > 0 && l.EventBus != nil {
		return DispatchDecision{WaitSeconds: opts.WaitSeconds, Skip: true}, nil
	}
	return DispatchDecision{Mission: explicitMissionPrompt, WaitSeconds: opts.WaitSeconds}, nil
}

func (l *Loop) runOnce(ctx context.Context, opts LoopOptions, st *state, prompt string, imagePaths []string, displayLines []DisplayLine, userPrompt string) error {
	l.clearStatusLine()
	st.LastRunError = ""
	st.LastRunUsage = UsageStats{}
	st.HasRunUsage = false
	if text := strings.TrimSpace(userPrompt); text != "" && l.OnUserPrompt != nil {
		l.OnUserPrompt(text)
	}
	expectedSessionID := strings.TrimSpace(st.SessionID)
	followUpRun := st.RanOnce
	buildOpts := BuildOptions{
		AllowedTools:    opts.AllowedTools,
		Model:           opts.Model,
		TripOnDanger:    opts.TripOnDanger,
		ImagePaths:      append([]string(nil), imagePaths...),
		PromptTransport: PromptTransportStdin,
		ProviderArgs:    append([]string(nil), opts.ProviderArgs...),
	}
	if opts.ProviderPTY {
		buildOpts.PromptTransport = PromptTransportArg
	}
	worktreeGitDir, err := detectWorktreeGitDir(opts.WorkingDir)
	if err != nil {
		return err
	}
	if strings.TrimSpace(worktreeGitDir) != "" {
		buildOpts.AddDirs = append(buildOpts.AddDirs, worktreeGitDir)
	}
	if followUpRun {
		if expectedSessionID == "" {
			return fmt.Errorf("provider %s did not report a session id for the previous run; cannot guarantee continuity", l.Provider.Name())
		}
		buildOpts.SessionID = expectedSessionID
		buildOpts.ContinueSession = true
	} else if opts.ContinueMode {
		buildOpts.ContinueSession = true
	}

	argv, err := l.Provider.BuildCommand(prompt, buildOpts)
	if err != nil {
		return err
	}
	if l.OnBuildCommand != nil {
		buildCopy := buildOpts
		buildCopy.AddDirs = append([]string(nil), buildOpts.AddDirs...)
		buildCopy.ImagePaths = append([]string(nil), buildOpts.ImagePaths...)
		buildCopy.ProviderArgs = append([]string(nil), buildOpts.ProviderArgs...)
		l.OnBuildCommand(append([]string(nil), argv...), buildCopy)
	}

	st.RunPhase = RunPhaseWorking
	l.setBusy(true)
	defer l.setBusy(false)
	if len(displayLines) > 0 {
		if st != nil && st.Run > 1 {
			l.displayText(DisplayKindPlain, "\n")
		}
		for _, line := range displayLines {
			l.displayLine(line.Kind, line.Text)
		}
		l.displayText(DisplayKindPlain, "\n")
	}
	l.setStatusLine(formatRunStatus(st))
	l.renderInputPrompt(st)

	presenter := &presenterState{}
	st.StructuredOut = false
	observedSessionID := ""
	var agentText strings.Builder
	var providerInput *providerInputState
	if opts.ProviderPTY {
		providerInput = &providerInputState{}
		st.ProviderInput = providerInput
	}
	defer func() {
		if providerInput != nil {
			providerInput.Clear()
		}
		st.ProviderInput = nil
		if l.OnRunComplete == nil {
			return
		}
		text := strings.TrimSpace(agentText.String())
		if text == "" {
			return
		}
		l.OnRunComplete(RunSummary{
			UserPrompt: strings.TrimSpace(userPrompt),
			SessionID:  strings.TrimSpace(st.SessionID),
			AgentText:  text,
			Failed:     strings.TrimSpace(st.LastRunError) != "",
		})
	}()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	errCh := make(chan error, 1)

	var busInterrupts <-chan BusEvent
	if l.EventBus != nil {
		busInterrupts = l.EventBus.Interrupts()
	}

	sinks := &commandOutputSinks{
		usePTY: opts.ProviderPTY,
	}
	if buildOpts.PromptTransport == PromptTransportStdin {
		sinks.stdinText = prompt
	}
	if opts.ProviderPTY {
		sinks.stdinReady = func(w io.WriteCloser) {
			providerInput.SetWriter(w)
		}
		sinks.ptyPartial = func(chunk string) {
			l.handleRawProviderChunk("provider", chunk, presenter)
		}
	} else {
		sinks.stderrLine = func(line string) {
			l.handleRawProviderChunk("provider stderr", line+"\n", presenter)
		}
		sinks.stderrPartial = func(chunk string) {
			l.handleRawProviderChunk("provider stderr", chunk, presenter)
		}
		sinks.stdoutPartial = func(chunk string) {
			l.handleRawProviderChunk("provider stdout", chunk, presenter)
		}
	}

	go func() {
		errCh <- l.Runner(runCtx, opts.WorkingDir, argv, func(line string) {
			l.handleOutputLine(line, presenter, st, &observedSessionID, &agentText)
		}, sinks)
	}()

	for {
		select {
		case err := <-errCh:
			st.RunPhase = RunPhaseIdle
			l.drainPendingControlEvents(st, true)
			st.RanOnce = true
			if st.RunInterrupted {
				st.Paused = true
				st.PauseAfterRun = true
				st.RunInterrupted = false
				return nil
			}
			st.RunInterrupted = false
			if strings.TrimSpace(st.LastRunError) != "" {
				return errors.New(st.LastRunError)
			}
			if followUpRun {
				switch {
				case strings.TrimSpace(observedSessionID) == "":
					l.resetSessionContinuity(st, fmt.Sprintf(
						"provider %s did not report a session id for follow-up run; starting a fresh session",
						l.Provider.Name(),
					))
					return nil
				case observedSessionID != expectedSessionID:
					l.resetSessionContinuity(st, fmt.Sprintf(
						"provider %s switched sessions unexpectedly (expected %s, got %s); starting a fresh session",
						l.Provider.Name(),
						expectedSessionID,
						observedSessionID,
					))
					return nil
				}
			}
			return err
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, true, cancel)
		case busEvt := <-busInterrupts:
			l.applyBusInterrupt(busEvt, st, cancel)
		case <-ctx.Done():
			cancel()
			st.StopRequested = true
			return ctx.Err()
		}
	}
}

func (l *Loop) resetSessionContinuity(st *state, message string) {
	if st == nil {
		return
	}
	st.SessionID = ""
	st.RanOnce = false
	l.printf("warning: %s\n", message)
}

func (l *Loop) drainPendingControlEvents(st *state, activeRun bool) {
	for {
		select {
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, activeRun, nil)
		default:
			return
		}
	}
}

func (l *Loop) handleOutputLine(line string, presenter *presenterState, st *state, observedSessionID *string, agentText *strings.Builder) {
	event, err := l.Provider.ParseOutput(line)
	if err != nil {
		l.runPresenterEnsureTextSpacing(presenter)
		l.println(line)
		presenter.lastWasStructured = false
		presenter.lastWasText = false
		presenter.lastTextEndedWithNewline = true
		return
	}
	if sid := l.Provider.SessionID(event); sid != "" {
		if sid != st.SessionID && l.OnSessionID != nil {
			l.OnSessionID(sid)
		}
		st.SessionID = sid
		if observedSessionID != nil {
			*observedSessionID = sid
		}
	}
	statusChanged := false
	if event != nil && event.Usage != nil {
		st.LastRunUsage = *event.Usage
		st.HasRunUsage = true
		statusChanged = true
	}
	if event != nil && event.CostUSD != nil {
		st.CumulativeCostUSD += *event.CostUSD
		statusChanged = true
	}
	if statusChanged {
		l.setStatusLine(formatRunStatus(st))
	}
	switch event.Type {
	case EventText:
		if agentText != nil {
			agentText.WriteString(event.Text)
		}
		l.runPresenterEnsureTextSpacing(presenter)
		startsAtLine := presenter == nil || !presenter.lastWasText || presenter.lastTextEndedWithNewline
		renderedText := renderAssistantText(l.Provider.Name(), event.Text, l.Out, startsAtLine)
		l.displayText(DisplayKindAgentText, renderedText)
		presenter.lastWasText = true
		presenter.lastWasStructured = false
		presenter.lastTextEndedWithNewline = strings.HasSuffix(renderedText, "\n")
		presenter.lastTextKind = DisplayKindAgentText
	case EventToolCall:
		st.StructuredOut = true
		l.runPresenterEnsureStructuredSpacing(presenter)
		for _, call := range event.ToolCalls {
			for _, line := range formatToolCallDisplay(call) {
				l.displayLine(line.Kind, line.Text)
			}
		}
		presenter.lastWasStructured = true
	case EventToolResult:
		// Successful tool results stay out of the main transcript; the
		// tool call itself is the only normal structured line we show.
	case EventDone:
		if event.IsError && strings.TrimSpace(event.Text) != "" {
			st.LastRunError = strings.TrimSpace(event.Text)
			st.StructuredOut = true
			l.runPresenterEnsureStructuredSpacing(presenter)
			l.displayLine(DisplayKindDone, formatDone(event))
			presenter.lastWasStructured = true
		}
	case EventSystem:
		// System info suppressed from display
	}
	l.renderInputPrompt(st)
}

func (l *Loop) handleRawProviderChunk(label string, chunk string, presenter *presenterState) {
	if chunk == "" {
		return
	}
	l.runPresenterEnsureRawSpacing(presenter)
	kind := DisplayKindAgentText
	switch label {
	case "provider stderr":
		kind = DisplayKindProviderStderr
	case "provider stdout":
		kind = DisplayKindProviderStdout
	case "provider":
		kind = DisplayKindProviderStdout
	case "":
		kind = DisplayKindAgentText
	default:
		kind = DisplayKindPlain
	}
	for len(chunk) > 0 {
		if presenter == nil || !presenter.rawLineOpen || presenter.rawLineLabel != label {
			if label != "" {
				l.displayText(kind, label+": ")
			}
			if presenter != nil {
				presenter.rawLineOpen = true
				presenter.rawLineLabel = label
			}
		}
		newline := strings.IndexByte(chunk, '\n')
		if newline < 0 {
			l.displayText(kind, chunk)
			if presenter != nil {
				presenter.lastWasText = true
				presenter.lastWasStructured = false
				presenter.lastTextEndedWithNewline = false
				presenter.lastTextKind = kind
			}
			return
		}
		l.displayText(kind, chunk[:newline+1])
		if presenter != nil {
			presenter.rawLineOpen = false
			presenter.rawLineLabel = ""
			presenter.lastWasText = true
			presenter.lastWasStructured = false
			presenter.lastTextEndedWithNewline = true
			presenter.lastTextKind = kind
		}
		chunk = chunk[newline+1:]
	}
}

func (l *Loop) runPresenterEnsureTextSpacing(presenter *presenterState) {
	if presenter != nil && presenter.lastWasStructured {
		l.print("\n")
		presenter.lastWasStructured = false
	}
}

func (l *Loop) runPresenterEnsureRawSpacing(presenter *presenterState) {
	l.runPresenterEnsureTextSpacing(presenter)
	if presenter == nil || presenter.rawLineOpen {
		return
	}
	if presenter.lastWasText && !presenter.lastTextEndedWithNewline {
		l.print("\n")
		presenter.lastTextEndedWithNewline = true
	}
}

func (l *Loop) runPresenterEnsureStructuredSpacing(presenter *presenterState) {
	if presenter == nil {
		return
	}
	if presenter.lastWasText {
		if l.screen() != nil {
			if presenter.lastTextEndedWithNewline {
				l.displayText(presenter.lastTextKind, "\n")
			} else {
				l.displayText(presenter.lastTextKind, "\n\n")
			}
		} else {
			if presenter.lastTextEndedWithNewline {
				l.print("\n")
			} else {
				l.print("\n\n")
			}
		}
		presenter.lastWasText = false
		presenter.lastTextEndedWithNewline = false
		presenter.lastTextKind = ""
	}
}

func (l *Loop) waitForNextCycle(ctx context.Context, waitSeconds int, st *state) error {
	if st.StopRequested {
		return context.Canceled
	}
	if l.Control == nil {
		return l.idle(ctx, waitSeconds)
	}
	if strings.TrimSpace(st.NextPrompt) != "" {
		return nil
	}
	if st.PauseAfterRun || st.Paused {
		st.Paused = true
		st.PauseAfterRun = false
		if !st.PendingInput && !st.PauseNoticeShown {
			l.println(pausedNoticeText)
			st.PauseNoticeShown = true
		}
		return l.waitWhilePaused(ctx, st)
	}
	if l.EventBus != nil {
		return l.waitForBusEvents(ctx, waitSeconds, st)
	}
	return l.idleWithControls(ctx, waitSeconds, st)
}

func (l *Loop) waitForWork(ctx context.Context, waitSeconds int, st *state) error {
	if l.EventBus != nil {
		return l.waitForBusEvents(ctx, waitSeconds, st)
	}
	return l.idleWithControlsLabel(ctx, waitSeconds, st, "waiting for work")
}

func (l *Loop) waitForBusEvents(ctx context.Context, waitSeconds int, st *state) error {
	if waitSeconds <= 0 {
		return nil
	}
	if st.StopRequested {
		return context.Canceled
	}
	if strings.TrimSpace(st.NextPrompt) != "" {
		return nil
	}

	bus := l.EventBus

	// Drain anything already queued, respecting the autofeed filter.
	for {
		evt, ok := bus.Queue().Pop()
		if !ok {
			break
		}
		if l.shouldWakeForBusEvent(evt, st) {
			return l.processWakeEvent(ctx, evt, st)
		}
	}

	l.refreshStatusLine(st)

	remaining := time.Duration(waitSeconds) * time.Second
	timer := time.NewTimer(remaining)
	defer timer.Stop()

	for {
		select {
		case <-bus.Queue().Ready():
			for {
				evt, ok := bus.Queue().Pop()
				if !ok {
					break
				}
				if l.shouldWakeForBusEvent(evt, st) {
					return l.processWakeEvent(ctx, evt, st)
				}
			}
		case busEvt := <-bus.Interrupts():
			wakeNow := l.applyBusInterrupt(busEvt, st, nil)
			if st.StopRequested {
				return context.Canceled
			}
			if wakeNow {
				return nil
			}
			// During idle wait there is no active run, so PauseAfterRun
			// should take effect immediately.
			if st.PauseAfterRun && !st.Paused {
				st.Paused = true
			}
			if st.Paused {
				return l.waitWhilePaused(ctx, st)
			}
			l.refreshStatusLine(st)
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
			if st.StopRequested {
				return context.Canceled
			}
			if strings.TrimSpace(st.NextPrompt) != "" {
				return nil
			}
			if st.Paused {
				return l.waitWhilePaused(ctx, st)
			}
			l.refreshStatusLine(st)
		case <-timer.C:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (l *Loop) shouldWakeForBusEvent(evt BusEvent, st *state) bool {
	autofeed := st != nil && st.Autofeed
	if evt.Priority == PriorityCoordination && !autofeed {
		return false
	}
	return true
}

func (l *Loop) processWakeEvent(ctx context.Context, evt BusEvent, st *state) error {
	st.LastWakeEvent = &evt.Event
	return nil
}

// applyBusInterrupt handles an interrupt-priority event from the EventBus.
// Called from runOnce (active run), waitForBusEvents (idle), and
// waitWhilePaused. cancel is non-nil only during an active run.
// Returns true when a non-pausing control event should trigger an immediate next
// cycle from idle wait without entering paused handling.
func (l *Loop) applyBusInterrupt(evt BusEvent, st *state, cancel context.CancelFunc) bool {
	switch evt.Event.Type {
	case awid.AgentEventControlInterrupt:
		st.PendingInput = false
		st.InputBuffer = ""
		st.Paused = true
		if cancel != nil {
			st.PauseAfterRun = true
			st.RunInterrupted = true
			l.println("\nstopped current run. " + pausedNoticeText)
		} else {
			st.PauseAfterRun = false
			st.RunInterrupted = false
			l.println(pausedNoticeText)
		}
		st.PauseNoticeShown = true
		if cancel != nil {
			cancel()
		}
		return false
	case awid.AgentEventControlPause:
		st.PauseAfterRun = true
		l.println("\nwill pause after this run.")
		return false
	case awid.AgentEventControlResume:
		st.Paused = false
		st.PauseNoticeShown = false
		st.PauseAfterRun = false
		l.renderInputPrompt(st)
		return false
	default:
		return false
	}
}

func (l *Loop) waitWhilePaused(ctx context.Context, st *state) error {
	var busInterrupts <-chan BusEvent
	if l.EventBus != nil {
		busInterrupts = l.EventBus.Interrupts()
	}

	for {
		l.refreshStatusLine(st)
		if st.StopRequested {
			return context.Canceled
		}
		if st.ExitConfirmPending {
			if err := l.waitForExitConfirmation(ctx, st); err != nil {
				return err
			}
		}
		if strings.TrimSpace(st.NextPrompt) != "" {
			st.Paused = false
			return nil
		}
		if !st.Paused {
			return nil
		}
		select {
		case busEvt := <-busInterrupts:
			if l.applyBusInterrupt(busEvt, st, nil) {
				st.Paused = false
				return nil
			}
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
			if st.StopRequested {
				return context.Canceled
			}
			if st.ExitConfirmPending {
				if err := l.waitForExitConfirmation(ctx, st); err != nil {
					return err
				}
			}
			if strings.TrimSpace(st.NextPrompt) != "" {
				st.Paused = false
				return nil
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (l *Loop) idle(ctx context.Context, seconds int) error {
	if seconds <= 0 {
		return nil
	}
	for remaining := seconds; remaining > 0; remaining-- {
		l.renderIdleLine("next run", remaining, nil)
		if err := l.Sleep(ctx, time.Second); err != nil {
			l.clearStatusLine()
			return err
		}
	}
	l.clearStatusLine()
	return nil
}

func (l *Loop) idleWithControls(ctx context.Context, seconds int, st *state) error {
	return l.idleWithControlsLabel(ctx, seconds, st, "next run")
}

func (l *Loop) idleWithControlsLabel(ctx context.Context, seconds int, st *state, label string) error {
	if seconds <= 0 {
		return nil
	}
	for remaining := seconds; remaining > 0; remaining-- {
		l.renderIdleLine(label, remaining, st)
		select {
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
			if st.StopRequested {
				return context.Canceled
			}
			if st.ExitConfirmPending {
				if err := l.waitForExitConfirmation(ctx, st); err != nil {
					return err
				}
			}
			if strings.TrimSpace(st.NextPrompt) != "" {
				return nil
			}
			if st.Paused {
				return l.waitWhilePaused(ctx, st)
			}
			remaining++
		case <-ctx.Done():
			l.clearStatusLine()
			return ctx.Err()
		default:
			if err := l.Sleep(ctx, time.Second); err != nil {
				l.clearStatusLine()
				return err
			}
		}
	}
	l.clearStatusLine()
	return nil
}

func (l *Loop) controlEvents() <-chan ControlEvent {
	if l.Control == nil {
		return nil
	}
	return l.Control.Events()
}

func (l *Loop) applyControlEvent(event ControlEvent, st *state, activeRun bool, cancel context.CancelFunc) {
	switch event.Type {
	case ControlHelp:
		l.println(helpText)
		l.renderInputPrompt(st)
		return
	case ControlUnknownCommand:
		resolved, handled, err := resolvePromptInput(event.Text)
		if err != nil {
			l.printf("info: failed to attach input: %v\n", err)
			l.renderInputPrompt(st)
			return
		}
		if handled {
			l.queuePromptText(st, resolved.Text, resolved.ImagePaths, activeRun)
			l.renderInputPrompt(st)
			return
		}
		l.printf("unknown command: %s — type /help for available commands\n", event.Text)
		l.renderInputPrompt(st)
		return
	case ControlExitConfirm:
		l.confirmExit(st, activeRun, cancel)
		return
	case ControlExitCancel:
		l.cancelExitConfirmation(st)
		l.renderInputPrompt(st)
		return
	case ControlInterrupt:
		switch {
		case st.ExitConfirmPending:
			l.confirmExit(st, activeRun, cancel)
			return
		case st.PendingInput || st.InputBuffer != "":
			l.clearPendingInput(st)
			return
		case activeRun && cancel != nil:
			event = ControlEvent{Type: ControlStop}
		default:
			l.offerExit(st)
			l.renderInputPrompt(st)
			return
		}
	case ControlExitPrompt:
		if st.ExitConfirmPending {
			l.confirmExit(st, activeRun, cancel)
			return
		}
		l.offerExit(st)
		l.renderInputPrompt(st)
		return
	}

	if st.ExitConfirmPending {
		l.cancelExitConfirmation(st)
	}

	switch event.Type {
	case ControlTypingStarted:
		st.PendingInput = true
		if !activeRun {
			st.Paused = true
		}
		l.renderInputPrompt(st)
	case ControlBufferUpdated:
		st.InputBuffer = event.Text
		st.PendingInput = event.Text != ""
		if !activeRun {
			if st.PendingInput {
				st.Paused = true
			} else if !st.PauseAfterRun {
				st.Paused = false
				st.PauseNoticeShown = false
			}
		}
		l.renderInputPrompt(st)
	case ControlPrompt:
		st.PendingInput = false
		st.InputBuffer = ""
		resolved, handled, err := resolvePromptInput(event.Text)
		if err != nil {
			l.printf("info: failed to attach input: %v\n", err)
			l.renderInputPrompt(st)
			return
		}
		if handled {
			l.queuePromptText(st, resolved.Text, resolved.ImagePaths, activeRun)
		} else {
			l.queuePromptText(st, event.Text, nil, activeRun)
		}
		l.renderInputPrompt(st)
	case ControlWait:
		st.PendingInput = false
		st.InputBuffer = ""
		st.PauseAfterRun = true
		st.Paused = !activeRun
		if activeRun {
			l.println("\nwill pause after this run.")
		} else {
			l.println(pausedNoticeText)
			st.PauseNoticeShown = true
		}
	case ControlResume:
		st.PendingInput = false
		st.InputBuffer = ""
		st.Paused = false
		st.PauseNoticeShown = false
		if activeRun {
			st.PauseAfterRun = false
		}
		l.renderInputPrompt(st)
	case ControlAutofeedOn:
		st.Autofeed = true
		l.announceAutofeedState(true, "on. work events can wake the agent.")
		l.renderInputPrompt(st)
	case ControlAutofeedOff:
		st.Autofeed = false
		l.announceAutofeedState(false, "off. only comms can wake the agent.")
		l.renderInputPrompt(st)
	case ControlProviderInput:
		st.PendingInput = false
		st.InputBuffer = ""
		if !activeRun {
			l.println("info: no active provider run to send input to.")
			l.renderInputPrompt(st)
			return
		}
		if st.ProviderInput == nil {
			l.println("info: provider stdin unavailable.")
			l.renderInputPrompt(st)
			return
		}
		if err := st.ProviderInput.SendLine(event.Text); err != nil {
			l.printf("info: failed to send provider input: %v\n", err)
		} else {
			l.printf("info: sent provider input: %s\n", truncateText(event.Text, 80))
		}
		l.renderInputPrompt(st)
	case ControlStreamError:
		if text := strings.TrimSpace(event.Text); text != "" {
			l.printf("info: event stream error: %s\n", text)
		} else {
			l.println("info: event stream error")
		}
		l.renderInputPrompt(st)
	case ControlQuit:
		l.confirmExit(st, activeRun, cancel)
	case ControlStop:
		st.PendingInput = false
		st.InputBuffer = ""
		st.Paused = true
		st.PauseAfterRun = true
		if activeRun && cancel != nil {
			st.RunInterrupted = true
			l.println("\nstopped current run. " + pausedNoticeText)
			st.PauseNoticeShown = true
			cancel()
			return
		}
		l.println(pausedNoticeText)
		st.PauseNoticeShown = true
	}
}

func (l *Loop) queuePromptText(st *state, rawText string, imagePaths []string, activeRun bool) {
	if st == nil {
		return
	}
	newText := strings.TrimSpace(rawText)
	st.NextImagePaths = append(st.NextImagePaths, imagePaths...)
	if newText == "" {
		if len(imagePaths) == 0 {
			return
		}
		newText = formatAttachedImagePrompt(imagePaths)
	}

	if existing := strings.TrimSpace(st.NextPrompt); existing != "" && newText != "" {
		st.NextPrompt = existing + "\n\n" + newText
	} else {
		st.NextPrompt = newText
	}
	st.Paused = false
	st.PauseNoticeShown = false
	if st.Autofeed {
		st.Autofeed = false
		l.announceAutofeedState(false, "disabled for manual conversation. use /autofeed on to re-enable.")
	}
	if activeRun {
		l.printf("\nqueued: %s\n", newText)
		if st.RunPhase == RunPhaseWorking {
			l.setStatusLine(formatRunStatus(st))
		}
	}
}

func (l *Loop) renderInputPrompt(st *state) {
	if st == nil {
		return
	}
	if screen := l.screen(); screen != nil && screen.HasActiveProgram() {
		return
	}
	if !st.PendingInput && !st.Paused && st.InputBuffer == "" {
		if screen := l.screen(); screen != nil {
			screen.ClearInputLine()
		}
		return
	}
	prompt := FormatInputLine(l.promptLabel(), st.InputBuffer)
	if st.Paused && st.InputBuffer == "" {
		prompt = l.promptLabel()
	}
	if screen := l.screen(); screen != nil {
		screen.SetInputLine(prompt)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprintf(l.Out, "\r\033[K%s", prompt)
}

func (l *Loop) promptLabel() string {
	if strings.TrimSpace(l.InputPromptLabel) == "" {
		return DefaultInputPromptLabel
	}
	return l.InputPromptLabel
}

func (l *Loop) renderIdleLine(label string, remaining int, st *state) {
	line := fmt.Sprintf("%s in %ds", label, remaining)
	if st != nil {
		switch label {
		case "waiting for prompt":
			st.RunPhase = RunPhaseWaitingForPrompt
		default:
			st.RunPhase = RunPhaseWaitingForWork
		}
	}
	if screen := l.screen(); screen != nil {
		screen.SetStatusLine(ComposeStatusLine(l.StatusIdentity, line))
		l.renderInputPrompt(st)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	if st != nil && strings.TrimSpace(st.InputBuffer) != "" {
		line = fmt.Sprintf("%s  >  %s", line, st.InputBuffer)
	}
	fmt.Fprintf(l.Out, "\r\033[K%s", line)
}

func (l *Loop) announceAutofeedState(enabled bool, detail string) {
	l.println("info: autofeed " + detail)
	mode := "off"
	if enabled {
		mode = "on"
	}
	l.setStatusLine("autofeed " + mode)
}

func (l *Loop) print(text string) {
	if screen := l.screen(); screen != nil {
		screen.AppendText(text)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprint(l.Out, text)
}

func (l *Loop) displayText(kind DisplayKind, text string) {
	if screen := l.screen(); screen != nil {
		if appender, ok := screen.(interface {
			AppendDisplayText(DisplayKind, string)
		}); ok {
			appender.AppendDisplayText(kind, text)
			return
		}
		screen.AppendText(text)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprint(l.Out, text)
}

func (l *Loop) printf(format string, args ...any) {
	if screen := l.screen(); screen != nil {
		screen.AppendText(fmt.Sprintf(format, args...))
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprintf(l.Out, format, args...)
}

func (l *Loop) displayLine(kind DisplayKind, text string) {
	if screen := l.screen(); screen != nil {
		if appender, ok := screen.(interface {
			AppendDisplayLine(DisplayKind, string)
		}); ok {
			appender.AppendDisplayLine(kind, text)
			return
		}
		screen.AppendLine(text)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprintln(l.Out, text)
}

func (l *Loop) println(text string) {
	if screen := l.screen(); screen != nil {
		screen.AppendLine(text)
		return
	}
	l.writeMu.Lock()
	defer l.writeMu.Unlock()
	fmt.Fprintln(l.Out, text)
}

func (l *Loop) offerExit(st *state) {
	if st == nil {
		return
	}
	st.ExitConfirmPending = true
	l.setExitConfirmation(true)
	l.setStatusLine(exitStatusText)
	if l.screen() == nil {
		l.println(exitStatusText)
	}
}

func (l *Loop) cancelExitConfirmation(st *state) {
	if st == nil || !st.ExitConfirmPending {
		return
	}
	st.ExitConfirmPending = false
	l.setExitConfirmation(false)
	l.refreshStatusLine(st)
}

func (l *Loop) confirmExit(st *state, activeRun bool, cancel context.CancelFunc) {
	if st == nil {
		return
	}
	st.PendingInput = false
	st.InputBuffer = ""
	st.StopRequested = true
	st.Paused = false
	st.PauseNoticeShown = false
	st.PauseAfterRun = false
	st.ExitConfirmPending = false
	l.setExitConfirmation(false)
	l.clearStatusLine()
	l.renderInputPrompt(st)
	if activeRun && cancel != nil {
		l.println("\nquitting.")
		cancel()
	}
}

func (l *Loop) clearPendingInput(st *state) {
	if st == nil {
		return
	}
	st.PendingInput = false
	st.InputBuffer = ""
	if !st.PauseAfterRun {
		st.Paused = false
		st.PauseNoticeShown = false
	}
	if screen := l.screen(); screen != nil {
		screen.ClearInputLine()
		return
	}
	l.renderInputPrompt(st)
}

func (l *Loop) waitForExitConfirmation(ctx context.Context, st *state) error {
	if st == nil || !st.ExitConfirmPending {
		return nil
	}
	l.setStatusLine(exitStatusText)
	for st.ExitConfirmPending && !st.StopRequested {
		select {
		case event := <-l.controlEvents():
			l.applyControlEvent(event, st, false, nil)
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if st.StopRequested {
		return context.Canceled
	}
	return nil
}

func (l *Loop) setStatusLine(text string) {
	if screen := l.screen(); screen != nil {
		screen.SetStatusLine(ComposeStatusLine(l.StatusIdentity, text))
	}
}

func (l *Loop) showStartupGreeting(opts LoopOptions, st *state) {
	if l.screen() == nil || opts.ContinueMode {
		return
	}

	l.println(startupBanner)
	l.println("The aweb agent runner")
	if strings.TrimSpace(l.StatusIdentity) != "" {
		l.println(l.StatusIdentity)
	}
	l.println("type /help for controls, or enter a prompt to begin")
	l.println("info: mail and chat wake the agent while idle.")
	if opts.Autofeed {
		l.println("info: work events also wake the agent.")
	} else {
		l.println("info: work events stay muted until /autofeed on.")
	}
	l.renderInputPrompt(st)
}

func (l *Loop) refreshStatusLine(st *state) {
	if st == nil {
		l.clearStatusLine()
		return
	}
	if st.ExitConfirmPending {
		l.setStatusLine(exitStatusText)
		return
	}
	if st.Paused {
		st.RunPhase = RunPhasePaused
		l.setStatusLine(pausedStatusText)
		return
	}
	if status := formatRunStatus(st); strings.TrimSpace(status) != "" {
		l.setStatusLine(status)
		return
	}
	label := "waiting for work"
	if st.Run == 0 && !st.RanOnce {
		st.RunPhase = RunPhaseWaitingForPrompt
		label = "waiting for prompt"
	} else {
		st.RunPhase = RunPhaseWaitingForWork
	}
	l.setStatusLine(formatWaitStatus(label, st))
}

func (l *Loop) clearStatusLine() {
	if screen := l.screen(); screen != nil {
		if strings.TrimSpace(l.StatusIdentity) != "" {
			screen.SetStatusLine(l.StatusIdentity)
		} else {
			screen.ClearStatusLine()
		}
	}
}

func (l *Loop) setExitConfirmation(active bool) {
	if screen := l.screen(); screen != nil {
		screen.SetExitConfirmation(active)
	}
}

func (l *Loop) setBusy(active bool) {
	if l == nil || l.Control == nil {
		return
	}
	if busyUI, ok := l.Control.(interface{ SetBusy(bool) }); ok {
		busyUI.SetBusy(active)
	}
}

func (l *Loop) screen() UI {
	if l == nil || l.Control == nil {
		return nil
	}
	screen, _ := l.Control.(UI)
	return screen
}

func resolveMission(basePrompt string, overridePrompt string) string {
	overridePrompt = strings.TrimSpace(overridePrompt)
	if overridePrompt != "" {
		return overridePrompt
	}
	return strings.TrimSpace(basePrompt)
}

func composeMissionAndContext(mission string, cycleContext string) string {
	mission = strings.TrimSpace(mission)
	cycleContext = strings.TrimSpace(cycleContext)
	if mission == "" {
		return cycleContext
	}
	if cycleContext == "" {
		return mission
	}
	return fmt.Sprintf("Primary mission:\n%s\n\nCurrent cycle:\n%s", mission, cycleContext)
}

func composeFullPrompt(mission string, cycleContext string, services []ServiceConfig) string {
	base := composeMissionAndContext(mission, cycleContext)
	servicesSection := FormatServicesPromptSection(services)
	if servicesSection == "" {
		return base
	}
	if strings.TrimSpace(base) == "" {
		return servicesSection
	}
	return fmt.Sprintf("%s\n\n%s", base, servicesSection)
}

func displayCycleLabel(mission string, cycleContext string) string {
	cycleContext = strings.TrimSpace(cycleContext)
	if cycleContext != "" {
		return cycleContext
	}
	return strings.TrimSpace(mission)
}

func SleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func RealCommandRunner(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
	if len(argv) == 0 {
		return fmt.Errorf("empty command")
	}
	sinks, _ := stderrSink.(*commandOutputSinks)
	if sinks != nil && sinks.usePTY {
		return realPTYCommandRunner(ctx, dir, argv, onLine, sinks)
	}

	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Dir = dir

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}

	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}

	stdinCallback := stdinReadyCallback(stderrSink)
	stdinText := stdinTextPayload(stderrSink)
	var stdin io.WriteCloser
	if stdinCallback != nil || stdinText != "" {
		stdin, err = cmd.StdinPipe()
		if err != nil {
			return err
		}
	}

	if err := cmd.Start(); err != nil {
		return err
	}
	if stdinText != "" {
		if _, err := io.WriteString(stdin, stdinText); err != nil {
			_ = stdin.Close()
			_ = cmd.Wait()
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return err
		}
		if stdinCallback == nil {
			_ = stdin.Close()
			stdin = nil
		}
	}
	if stdinCallback != nil {
		stdinCallback(stdin)
	}

	stderrResultCh := make(chan pipeScanResult, 1)
	go func() {
		stderrResultCh <- scanCommandPipe(stderr, stderrLineCallback(stderrSink), stderrPartialCallback(stderrSink), true, false, false)
	}()

	if result := scanCommandPipe(stdout, onLine, stdoutPartialCallback(stderrSink), false, true, false); result.Err != nil {
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return result.Err
	}

	stderrResult := <-stderrResultCh
	if stderrResult.Err != nil {
		_ = cmd.Wait()
		if ctx.Err() != nil {
			return ctx.Err()
		}
		return stderrResult.Err
	}

	if err := cmd.Wait(); err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		stderrText := strings.TrimSpace(stderrResult.Text)
		if stderrText != "" {
			return fmt.Errorf("%w: %s", err, stderrText)
		}
		return err
	}
	return nil
}

type pipeScanResult struct {
	Text string
	Err  error
}

type commandOutputSinks struct {
	stdinReady    func(io.WriteCloser)
	stdinText     string
	usePTY        bool
	ptyPartial    func(string)
	stderrLine    func(string)
	stderrPartial func(string)
	stdoutPartial func(string)
}

func scanCommandPipe(r io.Reader, lineSink func(string), partialSink func(string), collectText bool, suppressJSONPartial bool, allowEIOEOF bool) pipeScanResult {
	reader := bufio.NewReader(r)
	var (
		lineBuf        bytes.Buffer
		collectedLines []string
		partialEmitted bool
	)
	buf := make([]byte, 1024)

	flushCompleteLine := func() {
		line := strings.TrimSuffix(lineBuf.String(), "\r")
		if collectText {
			collectedLines = append(collectedLines, line)
		}
		if partialEmitted {
			if partialSink != nil {
				partialSink("\n")
			}
		} else if lineSink != nil {
			lineSink(line)
		}
		lineBuf.Reset()
		partialEmitted = false
	}

	for {
		n, err := reader.Read(buf)
		if n > 0 {
			chunk := buf[:n]
			for len(chunk) > 0 {
				newline := bytes.IndexByte(chunk, '\n')
				if newline < 0 {
					lineBuf.Write(chunk)
					if partialSink != nil && shouldEmitPartialLine(lineBuf.Bytes(), suppressJSONPartial) {
						partialSink(string(chunk))
						partialEmitted = true
					}
					break
				}
				segment := chunk[:newline]
				if len(segment) > 0 {
					lineBuf.Write(segment)
					if partialEmitted && partialSink != nil {
						partialSink(string(segment))
					}
				}
				flushCompleteLine()
				chunk = chunk[newline+1:]
			}
		}
		if err == nil {
			continue
		}
		if allowEIOEOF && errors.Is(err, syscall.EIO) {
			break
		}
		if !errors.Is(err, io.EOF) {
			return pipeScanResult{Err: err}
		}
		break
	}

	if lineBuf.Len() > 0 {
		line := strings.TrimSuffix(lineBuf.String(), "\r")
		if collectText {
			collectedLines = append(collectedLines, line)
		}
		if !partialEmitted && lineSink != nil {
			lineSink(line)
		}
	}

	return pipeScanResult{
		Text: strings.Join(collectedLines, "\n"),
	}
}

func shouldEmitPartialLine(line []byte, suppressJSONPartial bool) bool {
	if len(line) == 0 {
		return false
	}
	if !suppressJSONPartial {
		return true
	}
	trimmed := bytes.TrimLeft(line, " \t\r")
	if len(trimmed) == 0 {
		return true
	}
	return trimmed[0] != '{' && trimmed[0] != '['
}

func stderrLineCallback(stderrSink any) func(string) {
	sinks, _ := stderrSink.(*commandOutputSinks)
	if sinks == nil {
		return nil
	}
	return sinks.stderrLine
}

func stderrPartialCallback(stderrSink any) func(string) {
	sinks, _ := stderrSink.(*commandOutputSinks)
	if sinks == nil {
		return nil
	}
	return sinks.stderrPartial
}

func stdoutPartialCallback(stderrSink any) func(string) {
	sinks, _ := stderrSink.(*commandOutputSinks)
	if sinks == nil {
		return nil
	}
	return sinks.stdoutPartial
}

func stdinReadyCallback(stderrSink any) func(io.WriteCloser) {
	sinks, _ := stderrSink.(*commandOutputSinks)
	if sinks == nil {
		return nil
	}
	return sinks.stdinReady
}

func stdinTextPayload(stderrSink any) string {
	sinks, _ := stderrSink.(*commandOutputSinks)
	if sinks == nil {
		return ""
	}
	return sinks.stdinText
}
