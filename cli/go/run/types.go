package run

import (
	"context"
	"time"

	awid "github.com/awebai/aw/awid"
)

type UsageStats struct {
	InputTokens              int
	CacheCreationInputTokens int
	CacheReadInputTokens     int
	OutputTokens             int
}

type RunSummary struct {
	UserPrompt string
	SessionID  string
	AgentText  string
	Failed     bool
}

type ServiceConfig struct {
	Name        string `json:"name"`
	Command     string `json:"command"`
	Description string `json:"description"`
}

func (s UsageStats) TotalInput() int {
	return s.InputTokens + s.CacheCreationInputTokens + s.CacheReadInputTokens
}

type BuildOptions struct {
	SessionID       string
	ContinueSession bool
	AllowedTools    string
	Model           string
	AddDirs         []string
	ProviderArgs    []string
}

type Provider interface {
	Name() string
	BuildCommand(prompt string, opts BuildOptions) ([]string, error)
	BuildResumeCommand(opts BuildOptions) ([]string, error)
	ParseOutput(line string) (*Event, error)
	SessionID(event *Event) string
}

type EventType string

const (
	EventText       EventType = "text"
	EventToolCall   EventType = "tool_call"
	EventToolResult EventType = "tool_result"
	EventDone       EventType = "done"
	EventSystem     EventType = "system"
)

type ToolCall struct {
	Name  string
	Input map[string]any
}

type Event struct {
	Type       EventType
	Text       string
	ToolCalls  []ToolCall
	DurationMS int
	CostUSD    *float64
	Session    string
	IsError    bool
	Usage      *UsageStats
}

type ControlEventType string

const DefaultInputPromptLabel = ">> "

const (
	ControlTypingStarted  ControlEventType = "typing_started"
	ControlBufferUpdated  ControlEventType = "buffer_updated"
	ControlPrompt         ControlEventType = "prompt"
	ControlQuit           ControlEventType = "quit"
	ControlStop           ControlEventType = "stop"
	ControlWait           ControlEventType = "wait"
	ControlResume         ControlEventType = "resume"
	ControlAutofeedOn     ControlEventType = "autofeed_on"
	ControlAutofeedOff    ControlEventType = "autofeed_off"
	ControlProviderInput  ControlEventType = "provider_input"
	ControlStreamError    ControlEventType = "stream_error"
	ControlInterrupt      ControlEventType = "interrupt"
	ControlExitPrompt     ControlEventType = "exit_prompt"
	ControlExitConfirm    ControlEventType = "exit_confirm"
	ControlExitCancel     ControlEventType = "exit_cancel"
	ControlHelp           ControlEventType = "help"
	ControlUnknownCommand ControlEventType = "unknown_command"
)

type ControlEvent struct {
	Type ControlEventType
	Text string
}

type InputController interface {
	Start() error
	Stop() error
	Events() <-chan ControlEvent
	HasPendingInput() bool
}

// UI extends InputController with the optional screen operations the loop uses
// when it is driving an interactive terminal view.
type UI interface {
	InputController
	AppendText(string)
	AppendLine(string)
	SetInputLine(string)
	SetStatusLine(string)
	ClearStatusLine()
	ClearInputLine()
	SetExitConfirmation(bool)
	HasActiveProgram() bool
}

type ServiceSupervisor interface {
	Start(ctx context.Context, services []ServiceConfig, dir string) error
	Stop() error
}

type DispatchDecision struct {
	Mission      string
	CycleContext string
	UserPrompt   string
	WaitSeconds  int
	Skip         bool
}

type Dispatcher interface {
	Next(ctx context.Context, autofeed bool, wakeEvent *awid.AgentEvent) (DispatchDecision, error)
}

type CommandRunner func(ctx context.Context, dir string, argv []string, onLine func(string), stderrSink any) error

type SleepFunc func(ctx context.Context, d time.Duration) error

type LoopOptions struct {
	InitialPrompt   string
	BasePrompt      string
	WaitSeconds     int
	IdleWaitSeconds int
	MaxRuns         int
	Autofeed        bool
	ContinueMode    bool
	WorkingDir      string
	AllowedTools    string
	Model           string
	ClaimedTaskRef  string
	ProviderArgs    []string
	ProviderPTY     bool
	Services        []ServiceConfig
}
