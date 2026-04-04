package run

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

type fakeInputController struct {
	events chan ControlEvent
}

func newFakeInputController() *fakeInputController {
	return &fakeInputController{events: make(chan ControlEvent, 32)}
}

func (f *fakeInputController) Start() error                { return nil }
func (f *fakeInputController) Stop() error                 { return nil }
func (f *fakeInputController) Events() <-chan ControlEvent { return f.events }
func (f *fakeInputController) HasPendingInput() bool       { return false }

type recordingUI struct {
	*fakeInputController
	statusMu sync.Mutex
	statuses []string
	busyMu   sync.Mutex
	busy     []bool
	outputMu sync.Mutex
	output   string
}

func newRecordingUI() *recordingUI {
	return &recordingUI{fakeInputController: newFakeInputController()}
}

func (r *recordingUI) AppendText(text string) {
	r.outputMu.Lock()
	defer r.outputMu.Unlock()
	r.output += text
}

func (r *recordingUI) AppendDisplayText(_ DisplayKind, text string) {
	r.AppendText(text)
}

func (r *recordingUI) AppendLine(text string) {
	r.AppendText(text + "\n")
}
func (r *recordingUI) AppendDisplayLine(_ DisplayKind, text string) {
	r.AppendLine(text)
}
func (r *recordingUI) SetInputLine(string)      {}
func (r *recordingUI) ClearInputLine()          {}
func (r *recordingUI) SetExitConfirmation(bool) {}
func (r *recordingUI) HasActiveProgram() bool   { return true }
func (r *recordingUI) SetBusy(active bool) {
	r.busyMu.Lock()
	defer r.busyMu.Unlock()
	r.busy = append(r.busy, active)
}

func (r *recordingUI) SetStatusLine(text string) {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.statuses = append(r.statuses, text)
}

func (r *recordingUI) ClearStatusLine() {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	r.statuses = append(r.statuses, "")
}

func (r *recordingUI) sawStatusContaining(substr string) bool {
	r.statusMu.Lock()
	defer r.statusMu.Unlock()
	for _, status := range r.statuses {
		if strings.Contains(status, substr) {
			return true
		}
	}
	return false
}

func (r *recordingUI) sawOutputContaining(substr string) bool {
	r.outputMu.Lock()
	defer r.outputMu.Unlock()
	return strings.Contains(r.output, substr)
}

func (r *recordingUI) sawBusy(active bool) bool {
	r.busyMu.Lock()
	defer r.busyMu.Unlock()
	for _, state := range r.busy {
		if state == active {
			return true
		}
	}
	return false
}

type screenLikeUI struct {
	*fakeInputController
	outputMu sync.Mutex
	output   string
	current  string
}

func newScreenLikeUI() *screenLikeUI {
	return &screenLikeUI{fakeInputController: newFakeInputController()}
}

func (s *screenLikeUI) AppendText(text string) {
	s.AppendDisplayText(DisplayKindPlain, text)
}

func (s *screenLikeUI) AppendDisplayText(_ DisplayKind, text string) {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	parts := strings.Split(text, "\n")
	if len(parts) == 1 {
		s.current += parts[0]
		return
	}
	s.current += parts[0]
	s.output += s.current + "\n"
	for _, part := range parts[1 : len(parts)-1] {
		s.output += part + "\n"
	}
	s.current = parts[len(parts)-1]
}

func (s *screenLikeUI) AppendLine(text string) {
	s.AppendDisplayLine(DisplayKindPlain, text)
}

func (s *screenLikeUI) AppendDisplayLine(_ DisplayKind, text string) {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	if s.current != "" {
		s.output += s.current + "\n"
		s.current = ""
	}
	s.output += text + "\n"
}

func (s *screenLikeUI) DiscardCurrentDisplayLine() {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	s.current = ""
}

func (s *screenLikeUI) SetInputLine(string)      {}
func (s *screenLikeUI) ClearInputLine()          {}
func (s *screenLikeUI) SetExitConfirmation(bool) {}
func (s *screenLikeUI) HasActiveProgram() bool   { return true }
func (s *screenLikeUI) SetBusy(bool)             {}
func (s *screenLikeUI) SetStatusLine(string)     {}
func (s *screenLikeUI) ClearStatusLine()         {}

func (s *screenLikeUI) outputString() string {
	s.outputMu.Lock()
	defer s.outputMu.Unlock()
	return s.output + s.current
}

type fakeDispatcher struct {
	decisions []DispatchDecision
	index     int
}

func (d *fakeDispatcher) Next(_ context.Context, _ bool, _ *awid.AgentEvent) (DispatchDecision, error) {
	if d.index >= len(d.decisions) {
		return DispatchDecision{}, errors.New("no dispatch decision available")
	}
	decision := d.decisions[d.index]
	d.index++
	return decision, nil
}

type recordingDispatcher struct {
	decision DispatchDecision
	events   []*awid.AgentEvent
}

func (d *recordingDispatcher) Next(_ context.Context, _ bool, wakeEvent *awid.AgentEvent) (DispatchDecision, error) {
	if wakeEvent == nil {
		d.events = append(d.events, nil)
		return d.decision, nil
	}
	copy := *wakeEvent
	d.events = append(d.events, &copy)
	return d.decision, nil
}

type fakeProvider struct {
	event *Event
}

func (fakeProvider) Name() string { return "fake" }

func (fakeProvider) BuildCommand(prompt string, opts BuildOptions) ([]string, error) {
	return []string{"fake-provider", prompt}, nil
}

func (fakeProvider) BuildResumeCommand(opts BuildOptions) ([]string, error) {
	return []string{"fake-provider", "resume", opts.SessionID}, nil
}

func (fakeProvider) BuildResumeHint(opts BuildOptions) ([]string, error) {
	return []string{"fake-provider", "resume", opts.SessionID}, nil
}

func (f fakeProvider) ParseOutput(line string) (*Event, error) {
	return f.event, nil
}

func (fakeProvider) SessionID(event *Event) string {
	if event == nil {
		return ""
	}
	return event.Session
}

func TestLoopMaintainsClaudeSessionContinuity(t *testing.T) {
	var commands [][]string
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		commands = append(commands, append([]string(nil), argv...))
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	controller := newFakeInputController()
	loop.Control = controller
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{Mission: "persistent mission", WaitSeconds: 1},
			{Mission: "persistent mission", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     2,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(commands))
	}
	if strings.Contains(strings.Join(commands[0], " "), "resume") {
		t.Fatalf("first run should not resume an existing session: %q", strings.Join(commands[0], " "))
	}
	if !strings.Contains(strings.Join(commands[1], " "), "--continue") {
		t.Fatalf("second run should continue the same session: %q", strings.Join(commands[1], " "))
	}
}

func TestLoopMaintainsCodexSessionContinuity(t *testing.T) {
	var commands [][]string
	loop := NewLoop(CodexProvider{}, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		commands = append(commands, append([]string(nil), argv...))
		onLine(`{"type":"thread.started","thread_id":"019ccab4-4844-7ff3-80f2-b2d3b0c25e79"}`)
		onLine(`{"type":"turn.completed"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{Mission: "persistent mission", WaitSeconds: 1},
			{Mission: "persistent mission", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     2,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(commands) != 2 {
		t.Fatalf("expected 2 commands, got %d", len(commands))
	}
	if strings.Contains(strings.Join(commands[0], " "), "resume") {
		t.Fatalf("first codex run should start fresh, got %q", strings.Join(commands[0], " "))
	}
	if !strings.Contains(strings.Join(commands[1], " "), "resume 019ccab4-4844-7ff3-80f2-b2d3b0c25e79") {
		t.Fatalf("second codex run should use exact session id, got %q", strings.Join(commands[1], " "))
	}
}

func TestLoopDoesNotExposeProviderInputWithoutPTY(t *testing.T) {
	loop := NewLoop(fakeProvider{event: &Event{Type: EventDone}}, &bytes.Buffer{})
	var sawStdinReady bool
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		sinks, _ := stderrSink.(*commandOutputSinks)
		sawStdinReady = sinks != nil && sinks.stdinReady != nil
		onLine("ignored")
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{{Mission: "first", WaitSeconds: 0}},
	}

	err := loop.Run(context.Background(), LoopOptions{MaxRuns: 1})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if sawStdinReady {
		t.Fatal("expected non-PTY run to avoid provider stdin wiring")
	}
}

func TestLoopExposesProviderInputWithPTY(t *testing.T) {
	loop := NewLoop(fakeProvider{event: &Event{Type: EventDone}}, &bytes.Buffer{})
	var sawStdinReady bool
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		sinks, _ := stderrSink.(*commandOutputSinks)
		sawStdinReady = sinks != nil && sinks.stdinReady != nil
		onLine("ignored")
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{{Mission: "first", WaitSeconds: 0}},
	}

	err := loop.Run(context.Background(), LoopOptions{MaxRuns: 1, ProviderPTY: true})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !sawStdinReady {
		t.Fatal("expected PTY run to keep provider stdin wiring")
	}
}

func TestLoopMarksUIBusyDuringRun(t *testing.T) {
	ui := newRecordingUI()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Control = ui
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{{Mission: "check status", WaitSeconds: 0}},
	}

	if err := loop.Run(context.Background(), LoopOptions{MaxRuns: 1}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if !ui.sawBusy(true) {
		t.Fatal("expected loop to mark UI busy during the run")
	}
	if !ui.sawBusy(false) {
		t.Fatal("expected loop to clear busy state after the run")
	}
}

func TestLoopWaitForWorkWakesOnChatMessage(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventActionableChat, FromAlias: "mia"},
	)
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, &state{})
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForBusEvents returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for wake on chat message")
	}
	cancel()
	bus.Stop()
}

func TestEventBusDeliversInterruptDuringRun(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlInterrupt},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case evt := <-bus.Interrupts():
		if evt.Event.Type != awid.AgentEventControlInterrupt {
			t.Fatalf("expected control_interrupt, got %s", evt.Event.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for interrupt from bus")
	}
	cancel()
	bus.Stop()
}

func TestLoopDoesNotSuppressBdhSpecificEchoText(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{
			Type: EventText,
			Text: "Primary mission:\nAGENTS.md instructions\nProject Context\n",
		},
	}, &out)
	st := &state{}

	loop.handleOutputLine("ignored", &presenterState{}, st, nil, nil)

	got := out.String()
	if !strings.Contains(got, "AGENTS.md instructions") {
		t.Fatalf("expected echoed prompt text to be preserved, got %q", got)
	}
	if strings.Contains(got, "[suppressed prompt echo]") {
		t.Fatalf("unexpected suppression marker in output: %q", got)
	}
}

func TestLoopRendersCodexMarkdownWithBulletLane(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(CodexProvider{}, &out)
	st := &state{}

	loop.handleOutputLine(`{"type":"item.completed","item":{"type":"agent_message","text":"## Title\n\n- first item\n"}}`, &presenterState{}, st, nil, nil)

	got := out.String()
	if strings.Contains(got, "## Title") {
		t.Fatalf("expected markdown heading to be rendered, got %q", got)
	}
	if !strings.Contains(got, "● Title") {
		t.Fatalf("expected rendered text to start in the assistant bullet lane, got %q", got)
	}
	if !strings.Contains(got, "first item") {
		t.Fatalf("expected list item content to remain, got %q", got)
	}
}

func TestLoopAddsClaudeBulletLaneAcrossStreamingChunks(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{}
	presenter := &presenterState{}

	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"Hello "}}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"world\n- item"}}}`, presenter, st, nil, nil)

	got := out.String()
	if !strings.Contains(got, "● Hello world") {
		t.Fatalf("expected Claude text to start with the assistant bullet lane, got %q", got)
	}
	if !strings.Contains(got, "\n  - item") {
		t.Fatalf("expected Claude continuation line to keep the hanging indent, got %q", got)
	}
	if strings.Contains(got, "Hello   world") {
		t.Fatalf("expected no extra indentation injected mid-line, got %q", got)
	}
}

func TestLoopLeavesBlankLineAfterAgentTextBeforeToolOutput(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{}
	presenter := &presenterState{}

	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"I am checking the current diff."}}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"git status --short"}}]}}`, presenter, st, nil, nil)

	got := out.String()
	if !strings.Contains(got, "I am checking the current diff.\n\n· git status --short") {
		t.Fatalf("expected a blank line between agent text and the next tool line, got %q", got)
	}
}

func TestScreenKeepsShortAssistantPrefixAboveToolCall(t *testing.T) {
	ui := newScreenLikeUI()
	loop := NewLoop(ClaudeProvider{}, io.Discard)
	loop.Control = ui
	st := &state{}
	presenter := &presenterState{}

	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"Here"}}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"git status --short"}}]}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"'s what I see, Juan:\n"}}}`, presenter, st, nil, nil)

	got := ui.outputString()
	if !strings.Contains(got, "● Here\n\n· git status --short\n\n● 's what I see, Juan:\n") {
		t.Fatalf("expected short assistant text to stay above the tool call and resume below it, got %q", got)
	}
}

func TestScreenKeepsLongAssistantPrefixAboveToolCall(t *testing.T) {
	ui := newScreenLikeUI()
	loop := NewLoop(ClaudeProvider{}, io.Discard)
	loop.Control = ui
	st := &state{}
	presenter := &presenterState{}

	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"The linter changes are already committed or were in-memory only. "}}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"Let me check if the provider_claude.go on disk"}}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"head -25 cli/go/run/provider_claude.go"}}]}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":" matches what the system showed.\n"}}}`, presenter, st, nil, nil)

	got := ui.outputString()
	if !strings.Contains(got, "● The linter changes are already committed or were in-memory only. Let me check if the provider_claude.go on disk\n\n· head -25 cli/go/run/provider_claude.go\n\n●  matches what the system showed.\n") {
		t.Fatalf("expected long assistant prefix to stay above the tool call and resume below it, got %q", got)
	}
	if strings.Contains(got, "● The linter changes are already committed or were in-memory only. Let me check if the provider_claude.go on disk matches what the system showed.\n") {
		t.Fatalf("expected long assistant prefix not to be rejoined across the tool call, got %q", got)
	}
}

func TestScreenKeepsFullAssistantLineAcrossMultipleChunks(t *testing.T) {
	ui := newScreenLikeUI()
	loop := NewLoop(ClaudeProvider{}, io.Discard)
	loop.Control = ui
	st := &state{}
	presenter := &presenterState{}

	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"The old code had "}}}`, presenter, st, nil, nil)
	loop.handleOutputLine("{\"type\":\"stream_event\",\"event\":{\"delta\":{\"type\":\"text_delta\",\"text\":\"`-p` followed by \"}}}", presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"the prompt text as the next argument.\n"}}}`, presenter, st, nil, nil)

	got := ui.outputString()
	want := "● The old code had `-p` followed by the prompt text as the next argument.\n"
	if got != want {
		t.Fatalf("expected streamed assistant chunks to append into one line, got %q", got)
	}
}

func TestScreenDoesNotRejoinLongAssistantTextAcrossToolCall(t *testing.T) {
	ui := newScreenLikeUI()
	loop := NewLoop(ClaudeProvider{}, io.Discard)
	loop.Control = ui
	st := &state{}
	presenter := &presenterState{}

	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"But I need to check the provider_claude.go change more carefully. "}}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"The system told me it was modified. Let me compare what's on disk vs what's committed."}}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"assistant","message":{"content":[{"type":"tool_use","name":"Bash","input":{"command":"git diff HEAD -- cli/go/run/provider_claude.go cli/go/run/types.go 2>&1"}}]}}`, presenter, st, nil, nil)
	loop.handleOutputLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"No diff — they match what's committed.\n"}}}`, presenter, st, nil, nil)

	got := ui.outputString()
	if strings.Contains(got, "what's committed.No diff") {
		t.Fatalf("expected assistant continuation after tool call to start on a fresh line, got %q", got)
	}
	if !strings.Contains(got, "what's committed.\n\n· git diff HEAD -- cli/go/run/provider_claude.go cli/go/run/types.go 2>&1\n\n● No diff — they match what's committed.\n") {
		t.Fatalf("expected tool call to stay between the original assistant text and the resumed assistant text, got %q", got)
	}
}

func TestLoopDisplaysManualPromptInUserLaneWithoutLeadingBlankLine(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{event: &Event{Type: EventDone}}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine("done")
		return nil
	}
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{{Mission: "review the display lane", WaitSeconds: 0}},
	}

	if err := loop.Run(context.Background(), LoopOptions{MaxRuns: 1}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	got := out.String()
	if strings.HasPrefix(got, "\n") {
		t.Fatalf("expected first run transcript to avoid a leading blank line, got %q", got)
	}
	if !strings.Contains(got, "> review the display lane\n") {
		t.Fatalf("expected manual prompt in user lane, got %q", got)
	}
}

func TestScreenModeAddsBlankLineBeforeStructuredOutputAfterCompletedAgentLine(t *testing.T) {
	ui := newRecordingUI()
	loop := NewLoop(ClaudeProvider{}, io.Discard)
	loop.Control = ui
	presenter := &presenterState{
		lastWasText:              true,
		lastTextEndedWithNewline: true,
		lastTextKind:             DisplayKindAgentText,
	}

	loop.runPresenterEnsureStructuredSpacing(presenter)

	ui.outputMu.Lock()
	defer ui.outputMu.Unlock()
	if ui.output != "\n" {
		t.Fatalf("expected one blank separator line after a completed agent line, got %q", ui.output)
	}
}

func TestLoopInitialPromptOnlyWaitsForWakeInsteadOfTimerExit(t *testing.T) {
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			InitialPrompt: "what are we working on?",
			WaitSeconds:   1,
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled after explicit cancel, got %v", err)
	}
}

func TestLoopBasePromptDoesNotAutoRerunWithoutWake(t *testing.T) {
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runCount := 0
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		runCount++
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			BasePrompt:  "persistent mission",
			WaitSeconds: 1,
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(150 * time.Millisecond):
	}

	if runCount != 1 {
		t.Fatalf("expected exactly one run without wake events, got %d", runCount)
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled after explicit cancel, got %v", err)
	}
}

func TestFormatRunStatusOmitsRunLabel(t *testing.T) {
	st := &state{RunPhase: RunPhaseWaitingForWork}
	got := formatRunStatus(st)
	if got != "" {
		t.Fatalf("expected empty status with only run label, got %q", got)
	}
}

func TestFormatWaitStatusShowsConnectionStateAndAutofeed(t *testing.T) {
	st := &state{Autofeed: true, ConnState: ConnReconnecting}
	got := formatWaitStatus("waiting for prompt", st)
	want := "waiting for prompt · autofeed · reconnecting..."
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatWaitStatusShowsClaimedTaskRef(t *testing.T) {
	st := &state{ClaimedTaskRef: "aweb-aaag"}
	got := formatWaitStatus("waiting for prompt", st)
	want := "waiting for prompt · task aweb-aaag"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunStatusShowsCostAndAutofeed(t *testing.T) {
	st := &state{
		RunPhase:          RunPhaseWorking,
		CumulativeCostUSD: 0.05,
		Autofeed:          true,
		ConnState:         ConnStreaming,
	}
	got := formatRunStatus(st)
	want := "$0.05 · autofeed · streaming"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunStatusShowsClaimedTaskRef(t *testing.T) {
	st := &state{
		RunPhase:       RunPhaseWorking,
		ClaimedTaskRef: "aweb-aaag",
		ConnState:      ConnStreaming,
	}
	got := formatRunStatus(st)
	want := "task aweb-aaag · streaming"
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunStatusShowsReconnecting(t *testing.T) {
	st := &state{
		RunPhase:          RunPhaseWorking,
		CumulativeCostUSD: 0.05,
		ConnState:         ConnReconnecting,
	}
	got := formatRunStatus(st)
	want := "$0.05 · reconnecting..."
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}

func TestFormatRunStatusShowsQueuedWhenPromptPending(t *testing.T) {
	st := &state{
		RunPhase:   RunPhaseWorking,
		NextPrompt: "fix the bug",
	}
	got := formatRunStatus(st)
	if got != "queued" {
		t.Fatalf("expected 'queued', got %q", got)
	}
}

func TestFormatRunStatusOmitsQueuedWhenNoPromptPending(t *testing.T) {
	st := &state{RunPhase: RunPhaseWorking}
	got := formatRunStatus(st)
	if strings.Contains(got, "queued") {
		t.Fatalf("expected no 'queued' indicator without pending prompt, got %q", got)
	}
}

func TestHandleOutputLineAccumulatesCost(t *testing.T) {
	cost := 0.05
	provider := &fakeProvider{
		event: &Event{
			Type:    EventDone,
			CostUSD: &cost,
			Session: "sess-1",
		},
	}
	var out bytes.Buffer
	loop := NewLoop(provider, &out)
	st := &state{RunPhase: RunPhaseWorking}
	presenter := &presenterState{}
	sid := ""

	loop.handleOutputLine("event1", presenter, st, &sid, nil)
	if st.CumulativeCostUSD != 0.05 {
		t.Fatalf("expected 0.05, got %f", st.CumulativeCostUSD)
	}

	loop.handleOutputLine("event2", presenter, st, &sid, nil)
	if st.CumulativeCostUSD != 0.10 {
		t.Fatalf("expected 0.10, got %f", st.CumulativeCostUSD)
	}
}

func TestFollowUpRunsDoNotEmitSeparatorLine(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{Mission: "first", WaitSeconds: 0},
			{Mission: "second", WaitSeconds: 0},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{MaxRuns: 2})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	output := out.String()
	if strings.Contains(output, strings.Repeat("─", 40)) {
		t.Fatalf("expected no run separator line, got:\n%s", output)
	}
	firstPromptIdx := strings.Index(output, "> first")
	secondPromptIdx := strings.Index(output, "> second")
	if firstPromptIdx < 0 || secondPromptIdx < 0 {
		t.Fatalf("expected both prompts in output, got:\n%s", output)
	}
	if secondPromptIdx <= firstPromptIdx {
		t.Fatalf("expected second prompt after first prompt, got:\n%s", output)
	}
}

func TestEventBusDisconnectsWhenServerReturns404(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/v1/events/stream") {
			http.Error(w, `{"detail":"Not Found"}`, http.StatusNotFound)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	bus := NewEventBus(EventBusConfig{
		Stream: NewEventStreamOpener(client),
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	// Wait for the bus goroutine to exit on 404.
	select {
	case <-bus.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bus to disconnect on 404")
	}

	if bus.State() != ConnDisconnected {
		t.Fatalf("expected disconnected, got %s", bus.State())
	}
	cancel()
	bus.Stop()
}

func TestLoopContinuesViaTimeoutWhenBusDisconnected(t *testing.T) {
	// EventBus that immediately disconnects (404).
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			return nil, &awid.APIError{StatusCode: 404, Body: "not found"}
		},
	})

	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runCount := 0
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		runCount++
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{Mission: "first", WaitSeconds: 1},
			{Mission: "second", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     2,
	})
	if err != nil {
		t.Fatalf("run returned error: %v", err)
	}
	if runCount != 2 {
		t.Fatalf("expected 2 runs via timeout fallback, got %d", runCount)
	}
}

// --- EventBus integration tests ---

func newTestEventBus(events ...awid.AgentEvent) *EventBus {
	source := newFakeEventSource(events...)
	called := false
	return NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})
}

func TestLoopEventBusWakesOnMailMessage(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "alice"},
	)
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			InitialPrompt: "hello",
			WaitSeconds:   30,
		})
	}()

	// Wait for the bus event to wake the loop into a second run wait.
	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(300 * time.Millisecond):
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestNextPromptConsumesWakeEventAfterDispatch(t *testing.T) {
	dispatcher := &recordingDispatcher{
		decision: DispatchDecision{CycleContext: "handle wake"},
	}
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Dispatch = dispatcher

	st := &state{
		Run:           1,
		LastWakeEvent: &awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "alice"},
	}
	opts := LoopOptions{WaitSeconds: 5, IdleWaitSeconds: 9}

	first, err := loop.nextPrompt(context.Background(), opts, st)
	if err != nil {
		t.Fatalf("nextPrompt returned error: %v", err)
	}
	if first.CycleContext != "handle wake" {
		t.Fatalf("unexpected first decision: %+v", first)
	}
	if st.LastWakeEvent != nil {
		t.Fatalf("expected wake event to be consumed, got %+v", st.LastWakeEvent)
	}

	second, err := loop.nextPrompt(context.Background(), opts, st)
	if err != nil {
		t.Fatalf("second nextPrompt returned error: %v", err)
	}
	if len(dispatcher.events) != 2 {
		t.Fatalf("expected two dispatch calls, got %d", len(dispatcher.events))
	}
	if dispatcher.events[0] == nil || dispatcher.events[0].FromAlias != "alice" {
		t.Fatalf("expected first dispatch to receive wake event, got %+v", dispatcher.events[0])
	}
	if dispatcher.events[1] != nil {
		t.Fatalf("expected second dispatch to receive nil wake event, got %+v", dispatcher.events[1])
	}
	if second.CycleContext != "handle wake" {
		t.Fatalf("unexpected second decision: %+v", second)
	}
}

func TestNextPromptRunsBasePromptBeforeDispatchOnFirstCycle(t *testing.T) {
	dispatcher := &recordingDispatcher{
		decision: DispatchDecision{Skip: true},
	}
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Dispatch = dispatcher

	st := &state{}
	opts := LoopOptions{
		BasePrompt:      "persistent mission",
		WaitSeconds:     5,
		IdleWaitSeconds: 9,
	}

	decision, err := loop.nextPrompt(context.Background(), opts, st)
	if err != nil {
		t.Fatalf("nextPrompt returned error: %v", err)
	}
	if decision.Mission != "persistent mission" {
		t.Fatalf("expected first cycle to run base prompt, got %+v", decision)
	}
	if len(dispatcher.events) != 0 {
		t.Fatalf("expected dispatcher to be bypassed on first base-prompt cycle, got %d calls", len(dispatcher.events))
	}
}

func TestLoopShowsStartupStatusBeforeFirstPromptWhileEventBusRuns(t *testing.T) {
	ui := newRecordingUI()
	bus := newTestEventBus()

	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Control = ui
	loop.EventBus = bus
	loop.StatusIdentity = "claude@aweb:aw:rose"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{WaitSeconds: 30})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ui.sawStatusContaining("claude@aweb:aw:rose · waiting for prompt") {
			cancel()
			err := <-done
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context canceled, got %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	_ = <-done
	t.Fatal("timed out waiting for startup status line")
}

func TestLoopShowsFreshStartGreetingWithoutContinue(t *testing.T) {
	ui := newRecordingUI()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Control = ui
	loop.StatusIdentity = "claude@aweb:aw:rose"

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{WaitSeconds: 30})
	}()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if ui.sawOutputContaining("__ ___      __  _    __ ___") && ui.sawOutputContaining("The aweb agent runner") && ui.sawOutputContaining("type /help for controls, or enter a prompt to begin") {
			cancel()
			err := <-done
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("expected context canceled, got %v", err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	cancel()
	_ = <-done
	t.Fatal("timed out waiting for startup greeting")
}

func TestLoopSkipsFreshStartGreetingInContinueMode(t *testing.T) {
	ui := newRecordingUI()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Control = ui

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			WaitSeconds:  30,
			ContinueMode: true,
		})
	}()

	time.Sleep(150 * time.Millisecond)
	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
	if ui.sawOutputContaining("The aweb agent runner") {
		t.Fatal("did not expect startup greeting in continue mode")
	}
}

func TestLoopEmitsInteractionCallbacksForExplicitPrompt(t *testing.T) {
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"I checked the wake path. "}}}`)
		onLine(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"The fix is small."}}}`)
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	var prompts []string
	var summaries []RunSummary
	loop.OnUserPrompt = func(text string) { prompts = append(prompts, text) }
	loop.OnRunComplete = func(summary RunSummary) { summaries = append(summaries, summary) }

	if err := loop.Run(context.Background(), LoopOptions{
		InitialPrompt: "debug the continue UX",
		WaitSeconds:   1,
		MaxRuns:       1,
	}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	if len(prompts) != 1 || prompts[0] != "debug the continue UX" {
		t.Fatalf("unexpected prompts: %#v", prompts)
	}
	if len(summaries) != 1 {
		t.Fatalf("expected 1 summary, got %d", len(summaries))
	}
	if summaries[0].SessionID != "sess-42" {
		t.Fatalf("session_id=%q", summaries[0].SessionID)
	}
	if summaries[0].UserPrompt != "debug the continue UX" {
		t.Fatalf("user_prompt=%q", summaries[0].UserPrompt)
	}
	if summaries[0].AgentText != "I checked the wake path. The fix is small." {
		t.Fatalf("agent_text=%q", summaries[0].AgentText)
	}
}

func TestLoopEventBusInterruptDuringRun(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlInterrupt},
	)
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runStarted := make(chan struct{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		close(runStarted)
		// Block until context is cancelled by interrupt.
		<-ctx.Done()
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return ctx.Err()
	}
	controller := newFakeInputController()
	loop.Control = controller

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			InitialPrompt: "work",
			WaitSeconds:   1,
		})
	}()

	// Wait for run to start.
	select {
	case <-runStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for run to start")
	}

	// The interrupt should cancel the run and pause.
	time.Sleep(200 * time.Millisecond)

	// Send /quit to exit after the interrupt.
	controller.events <- ControlEvent{Type: ControlQuit}
	controller.events <- ControlEvent{Type: ControlExitConfirm}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("expected clean exit, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loop to exit")
	}

	if !strings.Contains(out.String(), "stopped current run") {
		t.Fatalf("expected interrupt notice, got %q", out.String())
	}
}

func TestLoopEventBusBasePromptWaitsForEvents(t *testing.T) {
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	runCount := 0
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		runCount++
		onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(ctx, LoopOptions{
			BasePrompt:  "persistent mission",
			WaitSeconds: 1,
		})
	}()

	select {
	case err := <-done:
		t.Fatalf("loop exited unexpectedly: %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	if runCount != 1 {
		t.Fatalf("expected exactly one run without wake events, got %d", runCount)
	}

	cancel()
	err := <-done
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context canceled, got %v", err)
	}
}

func TestWaitForBusEventsSkipsCoordinationWithoutAutofeed(t *testing.T) {
	// Pre-queue a coordination event, then a communication event.
	bus := newTestEventBus()
	bus.queue.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable, TaskID: "t1"}})
	bus.queue.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "alice"}})

	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	// Autofeed OFF — coordination should be skipped, mail should wake.
	st := &state{Autofeed: false}
	err := loop.waitForBusEvents(context.Background(), 30, st)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.LastWakeEvent == nil {
		t.Fatal("expected LastWakeEvent to be set")
	}
	if st.LastWakeEvent.Type != awid.AgentEventActionableMail {
		t.Fatalf("expected mail message wake (skipping coordination), got %s", st.LastWakeEvent.Type)
	}
}

func TestApplyBusInterruptResumeClearsPause(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{
		Paused:           true,
		PauseAfterRun:    true,
		PauseNoticeShown: true,
	}

	wakeNow := loop.applyBusInterrupt(BusEvent{
		Event:    awid.AgentEvent{Type: awid.AgentEventControlResume},
		Priority: PriorityInterrupt,
	}, st, nil)

	if wakeNow {
		t.Fatal("control resume should not request an immediate wake")
	}
	if st.Paused {
		t.Fatal("expected Paused to be cleared")
	}
	if st.PauseAfterRun {
		t.Fatal("expected PauseAfterRun to be cleared")
	}
	if st.PauseNoticeShown {
		t.Fatal("expected PauseNoticeShown to be cleared")
	}
}

func TestEmptyBufferResumesFromPause(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{
		Paused:           true,
		PendingInput:     true,
		InputBuffer:      "partial text",
		PauseNoticeShown: true,
	}

	// Simulate the user deleting all text — buffer becomes empty
	loop.applyControlEvent(ControlEvent{Type: ControlBufferUpdated, Text: ""}, st, false, nil)

	if st.PendingInput {
		t.Fatal("expected PendingInput=false after empty buffer")
	}
	if st.Paused {
		t.Fatal("expected Paused=false after buffer emptied")
	}
}

func TestCtrlCClearsInputAndResumes(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{
		Paused:       true,
		PendingInput: true,
		InputBuffer:  "some text",
	}

	// Ctrl-C with pending input should clear and resume
	loop.applyControlEvent(ControlEvent{Type: ControlInterrupt}, st, false, nil)

	if st.PendingInput {
		t.Fatal("expected PendingInput=false after Ctrl-C")
	}
	if st.Paused {
		t.Fatal("expected Paused=false after Ctrl-C cleared input")
	}
}

func TestEmptyBufferDoesNotOverrideWaitPause(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{
		Paused:           true,
		PauseAfterRun:    true,
		PauseNoticeShown: true,
		PendingInput:     true,
		InputBuffer:      "partial text",
	}

	// User backspaces to empty after /wait — should NOT unpause
	loop.applyControlEvent(ControlEvent{Type: ControlBufferUpdated, Text: ""}, st, false, nil)

	if !st.Paused {
		t.Fatal("expected Paused=true — /wait pause should survive empty buffer")
	}
	if !st.PauseAfterRun {
		t.Fatal("expected PauseAfterRun=true — /wait should be preserved")
	}
}

func TestCtrlCDoesNotOverrideWaitPause(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{
		Paused:        true,
		PauseAfterRun: true,
		PendingInput:  true,
		InputBuffer:   "some text",
	}

	// Ctrl-C with /wait active — should clear input but not unpause
	loop.applyControlEvent(ControlEvent{Type: ControlInterrupt}, st, false, nil)

	if !st.Paused {
		t.Fatal("expected Paused=true — /wait pause should survive Ctrl-C")
	}
	if st.PendingInput {
		t.Fatal("expected PendingInput=false — input should be cleared")
	}
}

func TestSlashResumeIsNotRecognized(t *testing.T) {
	event := ParseControlSubmission("/resume")
	if event.Type == ControlResume {
		t.Fatal("/resume should no longer be recognized as a resume command")
	}
}

func TestApplyBusInterruptIgnoresCommunicationWakeEvents(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	st := &state{}
	cancelled := false

	wakeNow := loop.applyBusInterrupt(BusEvent{
		Event: awid.AgentEvent{
			Type:          awid.AgentEventActionableChat,
			FromAlias:     "mia",
			WakeMode:      "interrupt",
			SenderWaiting: true,
			SessionID:     "s-1",
		},
		Priority: PriorityCommunication,
	}, st, func() {
		cancelled = true
	})

	if wakeNow {
		t.Fatal("communication wake should not request an immediate idle wake")
	}
	if cancelled {
		t.Fatal("communication wake should not cancel the active run")
	}
	if st.LastWakeEvent != nil {
		t.Fatalf("communication wake should not be handled by applyBusInterrupt, got %#v", st.LastWakeEvent)
	}
	if out.Len() != 0 {
		t.Fatalf("expected no interrupt output, got %q", out.String())
	}
}

func TestRemoteResumeDeliveredThroughBusInterrupts(t *testing.T) {
	// Verify control_resume reaches the interrupts channel.
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlResume},
	)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case evt := <-bus.Interrupts():
		if evt.Event.Type != awid.AgentEventControlResume {
			t.Fatalf("expected control_resume, got %s", evt.Event.Type)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for resume interrupt")
	}
	cancel()
	bus.Stop()
}

func TestWaitForBusEventsDrainsQueueAfterReady(t *testing.T) {
	// Simulate the bug: two events arrive close together.
	// The first is filtered (coordination, no autofeed), the second should wake.
	bus := newTestEventBus()

	// Pre-push both events before waitForBusEvents is called.
	// This simulates them arriving between Ready() checks.
	bus.queue.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable}})
	bus.queue.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "bob"}})

	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	// The initial drain should skip coordination and find the mail.
	st := &state{Autofeed: false}
	err := loop.waitForBusEvents(context.Background(), 30, st)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if st.LastWakeEvent == nil || st.LastWakeEvent.Type != awid.AgentEventActionableMail {
		t.Fatalf("expected mail wake, got %v", st.LastWakeEvent)
	}
}

func TestWaitForBusEventsReturnsOnQueuedActionableChatWake(t *testing.T) {
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	st := &state{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, st)
	}()

	time.Sleep(50 * time.Millisecond)
	bus.queue.Push(BusEvent{
		Event: awid.AgentEvent{
			Type:          awid.AgentEventActionableChat,
			FromAlias:     "henry",
			WakeMode:      "interrupt",
			SenderWaiting: true,
			SessionID:     "s-9",
		},
		Priority: PriorityCommunication,
	})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for interrupt wake")
	}

	if st.LastWakeEvent == nil || st.LastWakeEvent.Type != awid.AgentEventActionableChat {
		t.Fatalf("expected actionable chat wake, got %#v", st.LastWakeEvent)
	}
	if st.Paused {
		t.Fatal("communication wake while idle should not pause the loop")
	}
}

func TestWaitForBusEventsDrainsQueueFromReadySignal(t *testing.T) {
	// Test the Ready() path (not the initial drain): coordination then mail
	// arrive after waitForBusEvents enters the select loop.
	bus := newTestEventBus()
	loop := NewLoop(ClaudeProvider{}, &bytes.Buffer{})
	loop.EventBus = bus

	st := &state{Autofeed: false}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, st)
	}()

	// Let the goroutine enter the select loop.
	time.Sleep(50 * time.Millisecond)

	// Push coordination first, then mail. Only one Ready() signal fires.
	bus.queue.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable}})
	bus.queue.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "carol"}})

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out — mail event stuck in queue after coordination was filtered")
	}

	if st.LastWakeEvent == nil || st.LastWakeEvent.FromAlias != "carol" {
		t.Fatalf("expected carol mail wake, got %v", st.LastWakeEvent)
	}
}

func TestRemoteResumeUnblocksPausedLoop(t *testing.T) {
	// A remote control_resume sent while the loop is paused should
	// unblock waitWhilePaused via the EventBus interrupts channel.
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlResume},
	)

	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus

	st := &state{Paused: true, PauseAfterRun: true, PauseNoticeShown: true}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bus.Start(ctx)
	defer bus.Stop()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitWhilePaused(ctx, st)
	}()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitWhilePaused returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out — remote resume did not unblock paused loop")
	}

	if st.Paused {
		t.Fatal("expected Paused=false after remote resume")
	}
}

func TestRemotePauseDuringIdleWait(t *testing.T) {
	// A remote control_pause sent while idle (waitForBusEvents) should
	// cause the loop to enter the paused state. We send pause then resume
	// so waitWhilePaused unblocks and the function returns.
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlPause},
	)

	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus

	st := &state{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bus.Start(ctx)
	defer bus.Stop()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, st)
	}()

	// Give the pause event time to be consumed, then send resume
	// to unblock waitWhilePaused.
	time.Sleep(200 * time.Millisecond)
	bus.interrupts <- BusEvent{
		Event:    awid.AgentEvent{Type: awid.AgentEventControlResume},
		Priority: PriorityInterrupt,
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForBusEvents returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out — remote pause+resume did not complete during idle wait")
	}

	// After pause+resume, PauseAfterRun should have been set (pause)
	// then cleared (resume).
	if st.Paused {
		t.Fatal("expected Paused=false after resume")
	}
}

func TestRemoteInterruptDuringIdleDoesNotLeakIntoNextRun(t *testing.T) {
	bus := newTestEventBus(
		awid.AgentEvent{Type: awid.AgentEventControlInterrupt},
	)

	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventDone},
	}, &out)
	loop.EventBus = bus
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine("done")
		return nil
	}

	st := &state{}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	bus.Start(ctx)
	defer bus.Stop()

	done := make(chan error, 1)
	go func() {
		done <- loop.waitForBusEvents(ctx, 30, st)
	}()

	time.Sleep(200 * time.Millisecond)
	bus.interrupts <- BusEvent{
		Event:    awid.AgentEvent{Type: awid.AgentEventControlResume},
		Priority: PriorityInterrupt,
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("waitForBusEvents returned error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for idle interrupt+resume")
	}

	if st.RunInterrupted {
		t.Fatal("expected RunInterrupted=false after idle interrupt handling")
	}

	if err := loop.runOnce(context.Background(), LoopOptions{}, st, "review", nil, []DisplayLine{{Kind: DisplayKindPrompt, Text: "> review"}}, "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}

	if st.Paused {
		t.Fatal("expected next run to finish without re-pausing")
	}
	if st.PauseAfterRun {
		t.Fatal("expected PauseAfterRun=false after next run")
	}
}

func TestLoopAllowsInteractiveStartWithoutPrompt(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{event: &Event{Type: EventDone}}, &out)
	controller := newFakeInputController()
	loop.Control = controller
	ran := make(chan []string, 1)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		ran <- append([]string(nil), argv...)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error {
		return SleepWithContext(ctx, 10*time.Millisecond)
	}

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(context.Background(), LoopOptions{
			WaitSeconds: 1,
			MaxRuns:     1,
		})
	}()

	time.Sleep(100 * time.Millisecond)
	controller.events <- ControlEvent{Type: ControlPrompt, Text: "hello from user"}

	select {
	case argv := <-ran:
		if len(argv) < 2 || argv[1] != "hello from user" {
			t.Fatalf("unexpected command argv %q", argv)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for manual prompt to start first run")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loop to finish after first manual run")
	}
}

func TestLoopAllowsInteractiveStartWithoutPromptWhenDispatcherSkipsIdle(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{event: &Event{Type: EventDone}}, &out)
	controller := newFakeInputController()
	loop.Control = controller
	loop.Dispatch = &recordingDispatcher{
		decision: DispatchDecision{Skip: true},
	}
	ran := make(chan []string, 1)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		ran <- append([]string(nil), argv...)
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error {
		return SleepWithContext(ctx, 10*time.Millisecond)
	}

	done := make(chan error, 1)
	go func() {
		done <- loop.Run(context.Background(), LoopOptions{
			WaitSeconds: 1,
			MaxRuns:     1,
		})
	}()

	time.Sleep(100 * time.Millisecond)
	controller.events <- ControlEvent{Type: ControlPrompt, Text: "hello from user"}

	select {
	case argv := <-ran:
		if len(argv) < 2 || argv[1] != "hello from user" {
			t.Fatalf("unexpected command argv %q", argv)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for manual prompt to start first run with dispatcher")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for loop to finish after first manual run with dispatcher")
	}
}

func TestRunOnceSurfacesProviderStderr(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventDone},
	}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		sinks, ok := stderrSink.(*commandOutputSinks)
		if !ok || sinks == nil || sinks.stderrLine == nil {
			t.Fatal("expected stderr sinks")
		}
		sinks.stderrLine("approval required")
		onLine("done")
		return nil
	}

	if err := loop.runOnce(context.Background(), LoopOptions{}, &state{}, "review", nil, []DisplayLine{{Kind: DisplayKindPrompt, Text: "> review"}}, "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}

	if got := out.String(); !strings.Contains(got, "provider stderr: approval required") {
		t.Fatalf("expected streamed stderr in output, got %q", got)
	}
}

func TestRunOnceSurfacesProviderStdoutPartial(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventDone},
	}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		sinks, ok := stderrSink.(*commandOutputSinks)
		if !ok || sinks == nil || sinks.stdoutPartial == nil {
			t.Fatal("expected stdout partial sink")
		}
		sinks.stdoutPartial("Allow? [y/N]")
		return nil
	}

	if err := loop.runOnce(context.Background(), LoopOptions{}, &state{}, "review", nil, []DisplayLine{{Kind: DisplayKindPrompt, Text: "> review"}}, "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}

	if got := out.String(); !strings.Contains(got, "provider stdout: Allow? [y/N]") {
		t.Fatalf("expected streamed stdout partial in output, got %q", got)
	}
}

func TestRunOnceRendersIncomingCycleWithoutPromptMarker(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventDone},
	}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine("done")
		return nil
	}

	if err := loop.runOnce(context.Background(), LoopOptions{}, &state{}, "review", nil, []DisplayLine{{Kind: DisplayKindCommunication, Text: "● from architect (chat): can you review the retry path?"}}, ""); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}

	got := out.String()
	if strings.Contains(got, "> ● from architect (chat): can you review the retry path?") {
		t.Fatalf("expected inbound cycle to avoid prompt marker, got %q", got)
	}
	if !strings.Contains(got, "● from architect (chat): can you review the retry path?\n") {
		t.Fatalf("expected inbound cycle line, got %q", got)
	}
}

type buildOptionsProvider struct {
	builds []BuildOptions
}

func (p *buildOptionsProvider) Name() string { return "capture" }

func (p *buildOptionsProvider) BuildCommand(prompt string, opts BuildOptions) ([]string, error) {
	p.builds = append(p.builds, opts)
	return []string{"fake-provider", prompt}, nil
}

func (*buildOptionsProvider) BuildResumeCommand(opts BuildOptions) ([]string, error) {
	return []string{"fake-provider", "resume", opts.SessionID}, nil
}

func (*buildOptionsProvider) BuildResumeHint(opts BuildOptions) ([]string, error) {
	return []string{"fake-provider", "resume", opts.SessionID}, nil
}

func (*buildOptionsProvider) ParseOutput(string) (*Event, error) {
	return &Event{Type: EventDone}, nil
}

func (*buildOptionsProvider) SessionID(*Event) string { return "" }

func TestRunOnceAddsWorktreeGitDirToBuildOptions(t *testing.T) {
	worktree := t.TempDir()
	gitDir := filepath.Join(t.TempDir(), "repo", ".git", "worktrees", "grace")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatalf("mkdir gitdir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(worktree, ".git"), []byte("gitdir: "+gitDir+"\n"), 0o644); err != nil {
		t.Fatalf("write .git: %v", err)
	}

	provider := &buildOptionsProvider{}
	loop := NewLoop(provider, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine("done")
		return nil
	}

	if err := loop.runOnce(context.Background(), LoopOptions{WorkingDir: worktree}, &state{}, "review", nil, []DisplayLine{{Kind: DisplayKindPrompt, Text: "> review"}}, "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}
	if len(provider.builds) != 1 {
		t.Fatalf("expected one BuildCommand call, got %d", len(provider.builds))
	}
	if len(provider.builds[0].AddDirs) != 1 || provider.builds[0].AddDirs[0] != gitDir {
		t.Fatalf("expected worktree gitdir in AddDirs, got %#v", provider.builds[0].AddDirs)
	}
	if provider.builds[0].PromptTransport != PromptTransportStdin {
		t.Fatalf("expected stdin prompt transport, got %q", provider.builds[0].PromptTransport)
	}
}

func TestRunOnceKeepsArgPromptTransportForPTY(t *testing.T) {
	provider := &buildOptionsProvider{}
	loop := NewLoop(provider, &bytes.Buffer{})
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		onLine("done")
		return nil
	}

	if err := loop.runOnce(context.Background(), LoopOptions{ProviderPTY: true}, &state{}, "review", nil, []DisplayLine{{Kind: DisplayKindPrompt, Text: "> review"}}, "review"); err != nil {
		t.Fatalf("runOnce returned error: %v", err)
	}
	if len(provider.builds) != 1 {
		t.Fatalf("expected one BuildCommand call, got %d", len(provider.builds))
	}
	if provider.builds[0].PromptTransport != PromptTransportArg {
		t.Fatalf("expected arg prompt transport for PTY, got %q", provider.builds[0].PromptTransport)
	}
}

func TestHandleRawProviderChunkPTYStartsOnFreshLineWithProviderLabel(t *testing.T) {
	var out bytes.Buffer
	loop := NewLoop(fakeProvider{
		event: &Event{Type: EventText, Text: "Juan"},
	}, &out)
	presenter := &presenterState{}
	st := &state{}

	loop.handleOutputLine("ignored", presenter, st, nil, nil)
	loop.handleRawProviderChunk("provider", "Allow? [y/N]", presenter)

	got := out.String()
	if !strings.Contains(got, "provider: Allow? [y/N]") {
		t.Fatalf("expected PTY output to use provider label, got %q", got)
	}
	if strings.Contains(got, "Juanprovider: Allow? [y/N]") {
		t.Fatalf("expected PTY chunk to start on a fresh line, got %q", got)
	}
	if !strings.Contains(got, "Juan\nprovider: Allow? [y/N]") {
		t.Fatalf("expected PTY chunk to be separated from prior text, got %q", got)
	}
}

func TestRealCommandRunnerStreamsPartialStderrBeforeExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	stderrSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "printf 'approval required' >&2; sleep 1",
		}, func(string) {}, &commandOutputSinks{
			stderrPartial: func(chunk string) {
				select {
				case stderrSeen <- chunk:
				default:
				}
			},
		})
	}()

	select {
	case got := <-stderrSeen:
		if got != "approval required" {
			t.Fatalf("unexpected stderr line %q", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for stderr before process exit")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestRealCommandRunnerStreamsStderrBeforeExitFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	stderrSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "printf 'fatal approval denied\\n' >&2; sleep 1; exit 7",
		}, func(string) {}, &commandOutputSinks{
			stderrLine: func(line string) {
				select {
				case stderrSeen <- line:
				default:
				}
			},
		})
	}()

	select {
	case got := <-stderrSeen:
		if got != "fatal approval denied" {
			t.Fatalf("unexpected stderr line %q", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for stderr before process exit")
	}

	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "fatal approval denied") {
			t.Fatalf("expected exit error to include stderr text, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner failure")
	}
}

func TestRealCommandRunnerStreamsPartialStdoutBeforeExit(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	stdoutSeen := make(chan string, 1)
	done := make(chan error, 1)
	lineSeen := make(chan string, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "printf 'Allow? [y/N]'; sleep 1",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{
			stdoutPartial: func(chunk string) {
				select {
				case stdoutSeen <- chunk:
				default:
				}
			},
		})
	}()

	select {
	case got := <-stdoutSeen:
		if got != "Allow? [y/N]" {
			t.Fatalf("unexpected stdout partial %q", got)
		}
	case <-time.After(300 * time.Millisecond):
		t.Fatal("timed out waiting for stdout partial before process exit")
	}

	select {
	case got := <-lineSeen:
		t.Fatalf("did not expect line callback for partial stdout, got %q", got)
	case <-time.After(200 * time.Millisecond):
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestRealCommandRunnerAcceptsProviderInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	lineSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "read answer; printf '%s\\n' \"$answer\"",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{
			stdinReady: func(w io.WriteCloser) {
				_, _ = io.WriteString(w, "y\n")
			},
		})
	}()

	select {
	case got := <-lineSeen:
		if got != "y" {
			t.Fatalf("unexpected stdout line %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for provider stdin round-trip")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestRealCommandRunnerUsesNullStdinWhenProviderInputIsUnused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX shell")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	lineSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "if read answer; then printf 'data\\n'; else printf 'eof\\n'; fi",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{})
	}()

	select {
	case got := <-lineSeen:
		if got != "eof" {
			t.Fatalf("unexpected stdout line %q", got)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for unused stdin to resolve as EOF")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestRealCommandRunnerWritesInitialPromptToStdin(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 not available")
	}

	const prompt = "mail history:\n```text\nline one\n> quoted\n```\n"
	lineSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"python3", "-c", "import json, sys; print(json.dumps(sys.stdin.read()))",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{
			stdinText: prompt,
		})
	}()

	select {
	case got := <-lineSeen:
		var payload string
		if err := json.Unmarshal([]byte(got), &payload); err != nil {
			t.Fatalf("unmarshal payload %q: %v", got, err)
		}
		if payload != prompt {
			t.Fatalf("unexpected prompt payload %q", payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for prompt payload")
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for RealCommandRunner to finish")
	}
}

func TestLoopRecoversFromMissingFollowUpSessionID(t *testing.T) {
	var out bytes.Buffer
	var commands [][]string
	loop := NewLoop(ClaudeProvider{}, &out)
	callCount := 0
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		callCount++
		commands = append(commands, append([]string(nil), argv...))
		switch callCount {
		case 1:
			onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		case 2:
			onLine(`{"type":"result","duration_ms":1000}`)
		case 3:
			onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-99"}`)
		default:
			t.Fatalf("unexpected runner call %d", callCount)
		}
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{Mission: "persistent mission", WaitSeconds: 1},
			{Mission: "persistent mission", WaitSeconds: 1},
			{Mission: "persistent mission", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     3,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if callCount != 3 {
		t.Fatalf("expected 3 runs, got %d", callCount)
	}
	if !strings.Contains(strings.Join(commands[1], " "), "--continue") {
		t.Fatalf("second run should still attempt continuity, got %q", strings.Join(commands[1], " "))
	}
	if strings.Contains(strings.Join(commands[2], " "), "--continue") {
		t.Fatalf("third run should start fresh after missing session id, got %q", strings.Join(commands[2], " "))
	}
	if !strings.Contains(out.String(), "did not report a session id for follow-up run; starting a fresh session") {
		t.Fatalf("expected continuity warning, got %q", out.String())
	}
}

func TestLoopRecoversFromSessionIDMismatch(t *testing.T) {
	var out bytes.Buffer
	var commands [][]string
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.Runner = func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error {
		commands = append(commands, append([]string(nil), argv...))
		switch len(commands) {
		case 1:
			onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-42"}`)
		case 2:
			onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-bad"}`)
		case 3:
			onLine(`{"type":"result","duration_ms":1000,"session_id":"sess-fresh"}`)
		default:
			t.Fatalf("unexpected runner call %d", len(commands))
		}
		return nil
	}
	loop.Sleep = func(ctx context.Context, d time.Duration) error { return nil }
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{Mission: "persistent mission", WaitSeconds: 1},
			{Mission: "persistent mission", WaitSeconds: 1},
			{Mission: "persistent mission", WaitSeconds: 1},
		},
	}

	err := loop.Run(context.Background(), LoopOptions{
		WaitSeconds: 1,
		MaxRuns:     3,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(commands) != 3 {
		t.Fatalf("expected 3 commands, got %d", len(commands))
	}
	if !strings.Contains(strings.Join(commands[1], " "), "--continue") {
		t.Fatalf("second run should still attempt continuity, got %q", strings.Join(commands[1], " "))
	}
	if strings.Contains(strings.Join(commands[2], " "), "--continue") {
		t.Fatalf("third run should start fresh after mismatch, got %q", strings.Join(commands[2], " "))
	}
	if !strings.Contains(out.String(), "switched sessions unexpectedly") {
		t.Fatalf("expected mismatch warning, got %q", out.String())
	}
}

func TestRealCommandRunnerPTYProvidesTTYAndAcceptsInput(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PTY test uses POSIX shell semantics")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("sh not available")
	}

	partialSeen := make(chan string, 1)
	lineSeen := make(chan string, 1)
	done := make(chan error, 1)

	go func() {
		done <- RealCommandRunner(context.Background(), "", []string{
			"sh", "-c", "test -t 0 || exit 42; printf 'Allow? [y/N]'; read answer; printf '\\n%s\\n' \"$answer\"",
		}, func(line string) {
			select {
			case lineSeen <- line:
			default:
			}
		}, &commandOutputSinks{
			usePTY: true,
			ptyPartial: func(chunk string) {
				select {
				case partialSeen <- chunk:
				default:
				}
			},
			stdinReady: func(w io.WriteCloser) {
				go func() {
					time.Sleep(100 * time.Millisecond)
					_, _ = io.WriteString(w, "y\n")
				}()
			},
		})
	}()

	select {
	case got := <-partialSeen:
		if got != "Allow? [y/N]" {
			t.Fatalf("unexpected PTY partial %q", got)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for PTY partial prompt")
	}

	deadline := time.After(2 * time.Second)
	for {
		select {
		case got := <-lineSeen:
			if got == "" {
				continue
			}
			if got != "y" {
				t.Fatalf("unexpected PTY stdout line %q", got)
			}
			goto ptyDone
		case <-deadline:
			t.Fatal("timed out waiting for PTY input round-trip")
		}
	}

ptyDone:

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("RealCommandRunner returned error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for PTY runner to finish")
	}
}
