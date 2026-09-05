// Package session is the terminal wake broker's adapter for the OATS
// host-local session contract (docs/terminal-wake-broker.md §5):
//
//	oats session inspect --home /absolute/instance/home --json
//	oats session input   --home /absolute/instance/home --json   (text on stdin)
//
// It is the only package in the broker that knows OATS exists. Everything it
// exports is envelope parsing, the state mapping, and typed-error handling; it
// holds no policy. The policy — what to do with a state — lives in the broker
// (§4), because §5 gives the caller ownership of the `unknown` decision.
package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// OatsBinEnv names the executable the adapter runs. It exists so a test can
// substitute a fake that returns scripted envelopes without a real OATS on
// PATH; production leaves it unset and the adapter execs `oats` from PATH.
const OatsBinEnv = "AW_WAKE_OATS_BIN"

// DefaultOatsBin is the executable name resolved from PATH when neither the
// flag nor OatsBinEnv names one.
const DefaultOatsBin = "oats"

// CodeRuntimeEndpointUnknown is the typed error a home reports before its
// runtime receipt exists. The hook registers after the home is created and
// before the receipt is written, so a *pending* home answers with this rather
// than with present:false (§5). It is tolerated, never concluded from.
const CodeRuntimeEndpointUnknown = "E_RUNTIME_ENDPOINT_UNKNOWN"

// State is the broker's normalised view of what the backend reports.
//
// Herdr reports idle, done, working, blocked, unknown; generic shell, stopped
// and not-launched also occur; tmux always says unknown. `done` maps to idle
// and `working` to busy, and any string the broker does not recognise — a
// vocabulary extension, a typo, an empty field — degrades to StateUnknown, the
// conservative path, rather than to a crash (§4).
//
// Shell is the one addition to the note's set, from the OATS lead's samples:
// startup can briefly report "shell" before the exec begins, and typing into a
// shell is exactly what §5 has `input` refuse ("a fallback shell left by an
// exited harness"). It is therefore its own state that defers, not an
// unrecognised string that would submit.
type State string

const (
	StateIdle    State = "idle"
	StateBusy    State = "busy"
	StateBlocked State = "blocked"
	StateUnknown State = "unknown"
	StateStopped State = "stopped"
	StateShell   State = "shell"
)

// NormalizeState maps a backend-reported state string onto the broker's set.
// It is total: every input has an answer, and the answer for anything
// unrecognised is StateUnknown.
func NormalizeState(raw string) State {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "idle", "done":
		return StateIdle
	case "working":
		return StateBusy
	case "blocked":
		return StateBlocked
	case "stopped", "not-launched":
		return StateStopped
	case "unknown":
		return StateUnknown
	case "shell", "generic shell", "generic-shell":
		return StateShell
	default:
		// Anything a future backend adds lands here.
		return StateUnknown
	}
}

// Inspection is one successful `oats session inspect` observation.
type Inspection struct {
	Home     string
	Backend  string
	Present  bool
	State    State
	RawState string
}

// Error is a typed OATS failure: the {ok:false, error:{code,message}} envelope,
// or a transport failure with no envelope at all.
type Error struct {
	Code     string
	Message  string
	ExitCode int
}

func (e *Error) Error() string {
	code := strings.TrimSpace(e.Code)
	if code == "" {
		code = "E_UNKNOWN"
	}
	msg := strings.TrimSpace(e.Message)
	if msg == "" {
		return code
	}
	return code + ": " + msg
}

// IsRuntimeEndpointUnknown reports whether err is the typed pending-home error.
func IsRuntimeEndpointUnknown(err error) bool {
	var typed *Error
	if errors.As(err, &typed) {
		return strings.EqualFold(strings.TrimSpace(typed.Code), CodeRuntimeEndpointUnknown)
	}
	return false
}

// ErrorCode returns the typed code of err, or "" when err carries none.
func ErrorCode(err error) string {
	var typed *Error
	if errors.As(err, &typed) {
		return strings.TrimSpace(typed.Code)
	}
	return ""
}

// Client is the host-local session surface the broker depends on. Both methods
// are host-local and synchronous; neither carries credentials, SSE, or state.
type Client interface {
	Inspect(ctx context.Context, home string) (Inspection, error)
	// Input types text into the instance's original terminal. It returns nil
	// only when the envelope reported result.submitted:true — which means the
	// bytes reached the target, and nothing more. It is never consumption.
	Input(ctx context.Context, home, text string) error
}

// envelope decodes the OATS convention. Decoding is deliberately lenient about
// fields it does not name — real inspect results carry backend-specific extras
// such as paneId and terminalId — so an added field is ignored, never a
// failure. See testdata/broker-inspect-samples.json for captured real output.
type envelope struct {
	SchemaVersion int  `json:"schemaVersion"`
	OK            bool `json:"ok"`
	Result        struct {
		Home      string `json:"home"`
		Backend   string `json:"backend"`
		Present   bool   `json:"present"`
		State     string `json:"state"`
		Submitted bool   `json:"submitted"`
	} `json:"result"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// ExecClient runs the real `oats` executable.
type ExecClient struct {
	// Bin is the executable to run. Empty means OatsBinEnv, then
	// DefaultOatsBin resolved from PATH.
	Bin string
	// Timeout bounds one command. Zero means DefaultTimeout.
	Timeout time.Duration
}

// DefaultTimeout bounds one `oats session` invocation. An unanswerable backend
// is a typed error to retry, never an absent instance (§6).
const DefaultTimeout = 20 * time.Second

// ResolveBin reports the executable ExecClient will run.
func (c *ExecClient) ResolveBin() string {
	if c != nil && strings.TrimSpace(c.Bin) != "" {
		return strings.TrimSpace(c.Bin)
	}
	if env := strings.TrimSpace(os.Getenv(OatsBinEnv)); env != "" {
		return env
	}
	return DefaultOatsBin
}

func (c *ExecClient) timeout() time.Duration {
	if c != nil && c.Timeout > 0 {
		return c.Timeout
	}
	return DefaultTimeout
}

func (c *ExecClient) run(ctx context.Context, stdin string, args ...string) (envelope, error) {
	ctx, cancel := context.WithTimeout(ctx, c.timeout())
	defer cancel()

	cmd := exec.CommandContext(ctx, c.ResolveBin(), args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	} else {
		cmd.Stdin = strings.NewReader("")
	}

	runErr := cmd.Run()
	exitCode := 0
	var exitErr *exec.ExitError
	if errors.As(runErr, &exitErr) {
		exitCode = exitErr.ExitCode()
	}

	env, parseErr := decodeEnvelope(stdout.Bytes())
	if parseErr != nil {
		// No envelope: a transport failure, not an instance verdict.
		detail := strings.TrimSpace(stderr.String())
		if detail == "" {
			detail = strings.TrimSpace(stdout.String())
		}
		if detail == "" && runErr != nil {
			detail = runErr.Error()
		}
		if detail == "" {
			detail = parseErr.Error()
		}
		return envelope{}, &Error{Code: "E_OATS_UNREACHABLE", Message: truncate(detail, 400), ExitCode: exitCode}
	}
	if !env.OK {
		code := ""
		message := ""
		if env.Error != nil {
			code = env.Error.Code
			message = env.Error.Message
		}
		return env, &Error{Code: code, Message: truncate(message, 400), ExitCode: exitCode}
	}
	if runErr != nil {
		// ok:true with a non-zero exit contradicts the convention; treat the
		// exit status as authoritative rather than believing the payload.
		return env, &Error{Code: "E_OATS_PROTOCOL", Message: fmt.Sprintf("ok:true with exit status %d", exitCode), ExitCode: exitCode}
	}
	return env, nil
}

func decodeEnvelope(raw []byte) (envelope, error) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		return envelope{}, errors.New("empty response")
	}
	var env envelope
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return envelope{}, err
	}
	if env.SchemaVersion != 1 {
		return envelope{}, fmt.Errorf("unsupported schemaVersion %d", env.SchemaVersion)
	}
	return env, nil
}

// Inspect runs `oats session inspect --home <home> --json`.
func (c *ExecClient) Inspect(ctx context.Context, home string) (Inspection, error) {
	env, err := c.run(ctx, "", "session", "inspect", "--home", home, "--json")
	if err != nil {
		return Inspection{}, err
	}
	return Inspection{
		Home:     env.Result.Home,
		Backend:  env.Result.Backend,
		Present:  env.Result.Present,
		State:    NormalizeState(env.Result.State),
		RawState: strings.TrimSpace(env.Result.State),
	}, nil
}

// Input runs `oats session input --home <home> --json` with text on stdin, so
// the content never reaches a shell as an argument.
func (c *ExecClient) Input(ctx context.Context, home, text string) error {
	env, err := c.run(ctx, text, "session", "input", "--home", home, "--json")
	if err != nil {
		return err
	}
	if !env.Result.Submitted {
		return &Error{Code: "E_NOT_SUBMITTED", Message: "input envelope did not report submitted:true"}
	}
	return nil
}

func truncate(s string, max int) string {
	s = strings.TrimSpace(s)
	if len(s) <= max {
		return s
	}
	return s[:max] + "…"
}
