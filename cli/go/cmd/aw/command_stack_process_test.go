package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// stackOperation names a fixture command as it travels on the wire.
type stackOperation string

const (
	stackZone            stackOperation = "zone"
	stackPublicOrigin    stackOperation = "public_origin"
	stackResetRateLimits stackOperation = "reset_rate_limits"
)

// commandStackDeadlines bound each stage of a stack process, so a stack that
// stops answering fails the tests that meet it instead of hanging the package.
type commandStackDeadlines struct {
	Ready   time.Duration
	Command time.Duration
	Stop    time.Duration
}

// commandStackProcess is a fixture process speaking the stack's line
// protocol: one readiness line, then one acknowledgement line per command
// line. It owns the process tree and its stdout pipe.
type commandStackProcess struct {
	deadlines commandStackDeadlines
	command   *exec.Cmd
	input     io.WriteCloser
	output    *os.File
	exited    chan error
	exitErr   error
	// lines carries stdout lines; the reader closes it when it returns,
	// after setting readErr, and then closes readerDone.
	lines      chan string
	readErr    error
	released   chan struct{}
	readerDone chan struct{}
	// mu holds one command and its acknowledgement together.
	mu     sync.Mutex
	nextID int
	// failed is the transport or protocol failure that terminated the
	// process. Later commands return it rather than read an acknowledgement
	// meant for another.
	failed       error
	terminateErr error
	terminated   sync.Once
}

// startCommandStackProcess starts command as a process-tree owner and waits
// for its readiness line.
func startCommandStackProcess(command *exec.Cmd, deadlines commandStackDeadlines) (*commandStackProcess, string, error) {
	ownProcessTree(command)
	input, err := command.StdinPipe()
	if err != nil {
		return nil, "", fmt.Errorf("stack input: %w", err)
	}
	// An owned pipe, so Wait never closes the reader's end underneath it.
	output, writer, err := os.Pipe()
	if err != nil {
		return nil, "", errors.Join(fmt.Errorf("stack output: %w", err), input.Close())
	}
	command.Stdout = writer
	if err := command.Start(); err != nil {
		return nil, "", errors.Join(fmt.Errorf("start stack: %w", err), input.Close(), output.Close(), writer.Close())
	}
	process := &commandStackProcess{
		deadlines: deadlines, command: command, input: input, output: output,
		exited: make(chan error, 1), lines: make(chan string), released: make(chan struct{}),
		readerDone: make(chan struct{}),
	}
	go func() { process.exited <- command.Wait() }()
	go process.read()
	// Only the child holds the writer now, so its exit ends the output.
	if err := writer.Close(); err != nil {
		return nil, "", process.fail(fmt.Errorf("release the stack's output writer: %w", err))
	}
	line, err := process.nextLine(deadlines.Ready)
	if err != nil {
		return nil, "", process.fail(fmt.Errorf("stack readiness: %w", err))
	}
	return process, line, nil
}

func (process *commandStackProcess) read() {
	defer close(process.readerDone)
	defer close(process.lines)
	scanner := bufio.NewScanner(process.output)
	for scanner.Scan() {
		select {
		case process.lines <- scanner.Text():
		case <-process.released:
			return
		}
	}
	process.readErr = scanner.Err()
}

// nextLine waits at most timeout for the next stdout line.
func (process *commandStackProcess) nextLine(timeout time.Duration) (string, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case line, open := <-process.lines:
		if !open {
			return "", fmt.Errorf("output ended (read error: %v)", process.readErr)
		}
		return line, nil
	case <-timer.C:
		return "", fmt.Errorf("no answer within %s", timeout)
	}
}

// send sends one command and waits for its own acknowledgement. A refusal is
// returned as an error and leaves the process serving; a transport or
// protocol failure terminates it.
func (process *commandStackProcess) send(operation stackOperation, value any) error {
	name := string(operation)
	process.mu.Lock()
	defer process.mu.Unlock()
	if process.failed != nil {
		return fmt.Errorf("stack stopped after an earlier failure: %w", process.failed)
	}
	process.nextID++
	id := process.nextID
	line, err := json.Marshal(map[string]any{"id": id, name: value})
	if err != nil {
		return err
	}
	written := make(chan error, 1)
	go func() {
		_, err := process.input.Write(append(line, '\n'))
		written <- err
	}()
	timer := time.NewTimer(process.deadlines.Command)
	defer timer.Stop()
	select {
	case err := <-written:
		if err != nil {
			return process.fail(fmt.Errorf("send %s command %d: %w", name, id, err))
		}
	case <-timer.C:
		return process.fail(fmt.Errorf("send %s command %d: not accepted within %s", name, id, process.deadlines.Command))
	}
	reply, err := process.nextLine(process.deadlines.Command)
	if err != nil {
		return process.fail(fmt.Errorf("%s command %d: %w", name, id, err))
	}
	refusal, err := parseStackAcknowledgement(reply, id)
	if err != nil {
		return process.fail(fmt.Errorf("%s command: %w", name, err))
	}
	if refusal != "" {
		return fmt.Errorf("%s command refused: %s", name, refusal)
	}
	return nil
}

// fail records err as the process's failure and terminates it.
func (process *commandStackProcess) fail(err error) error {
	process.failed = err
	if terminateErr := process.terminate(); terminateErr != nil {
		return errors.Join(err, terminateErr)
	}
	return err
}

// terminate kills the whole process tree, closes both pipes, releases the
// reader and waits a bounded time for the process and the reader to end. It
// runs once; later calls return its result.
func (process *commandStackProcess) terminate() error {
	process.terminated.Do(func() {
		var errs []error
		close(process.released)
		if err := killProcessTree(process.command.Process); err != nil {
			errs = append(errs, fmt.Errorf("kill stack process tree: %w", err))
		}
		if err := process.input.Close(); err != nil && !errors.Is(err, os.ErrClosed) {
			errs = append(errs, fmt.Errorf("close stack input: %w", err))
		}
		if err := process.output.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close stack output: %w", err))
		}
		if process.exited != nil {
			if err := process.awaitExit(); err != nil {
				errs = append(errs, err)
			}
		}
		if err := process.awaitReader(); err != nil {
			errs = append(errs, err)
		}
		process.terminateErr = errors.Join(errs...)
	})
	return process.terminateErr
}

// awaitReader waits a bounded time for the stdout reader to return.
func (process *commandStackProcess) awaitReader() error {
	timer := time.NewTimer(process.deadlines.Stop)
	defer timer.Stop()
	select {
	case <-process.readerDone:
		return nil
	case <-timer.C:
		return fmt.Errorf("stack output reader did not return within %s", process.deadlines.Stop)
	}
}

// awaitExit waits a bounded time for the process to exit.
func (process *commandStackProcess) awaitExit() error {
	timer := time.NewTimer(process.deadlines.Stop)
	defer timer.Stop()
	select {
	case process.exitErr = <-process.exited:
		return nil
	case <-timer.C:
		return fmt.Errorf("stack process %d did not exit within %s", process.command.Process.Pid, process.deadlines.Stop)
	}
}

// stop closes the process's input, which asks it to shut down, and waits a
// bounded time for it to exit; a process that does not is killed. Either
// way its whole tree is killed afterwards, so nothing it started survives.
func (process *commandStackProcess) stop() error {
	if process.failed != nil {
		return errors.Join(fmt.Errorf("stack was stopped by: %w", process.failed), process.terminate())
	}
	var errs []error
	if err := process.input.Close(); err != nil {
		errs = append(errs, fmt.Errorf("close stack input: %w", err))
	}
	timer := time.NewTimer(process.deadlines.Stop)
	defer timer.Stop()
	select {
	case process.exitErr = <-process.exited:
		process.exited = nil
		if process.exitErr != nil {
			errs = append(errs, fmt.Errorf("stack exit: %w", process.exitErr))
		}
	case <-timer.C:
		errs = append(errs, fmt.Errorf("stack did not stop within %s after its input closed; killed", process.deadlines.Stop))
	}
	if err := process.terminate(); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// parseStackAcknowledgement reads an acknowledgement of command id: an object
// holding id and exactly one of "ok": true or a non-empty "error", and nothing
// after it. It returns the refusal ("" for ok), or an error when the line is
// not such an answer.
func parseStackAcknowledgement(line string, id int) (string, error) {
	decoder := json.NewDecoder(bytes.NewReader([]byte(line)))
	var fields map[string]json.RawMessage
	if err := decoder.Decode(&fields); err != nil {
		return "", fmt.Errorf("acknowledgement %q: %w", line, err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return "", fmt.Errorf("acknowledgement %q has content after its object", line)
	}
	var answered int
	if err := json.Unmarshal(fields["id"], &answered); err != nil || answered != id {
		return "", fmt.Errorf("acknowledgement %q does not answer command %d", line, id)
	}
	ok, hasOK := fields["ok"]
	refusal, hasError := fields["error"]
	if len(fields) != 2 || hasOK == hasError {
		return "", fmt.Errorf("acknowledgement %q is not its id and exactly one of ok and error", line)
	}
	if hasOK {
		if string(ok) != "true" {
			return "", fmt.Errorf("acknowledgement %q: ok must be true", line)
		}
		return "", nil
	}
	var reason string
	if err := json.Unmarshal(refusal, &reason); err != nil || reason == "" {
		return "", fmt.Errorf("acknowledgement %q: error must be a non-empty string", line)
	}
	return reason, nil
}

func TestStackAcknowledgementIsExactlyOneAnswerForItsCommand(t *testing.T) {
	const notExactlyOne = "is not its id and exactly one of ok and error"
	for _, test := range []struct {
		name    string
		line    string
		refusal string
		invalid string
	}{
		{name: "ok", line: `{"id": 4, "ok": true}`},
		{name: "refusal", line: `{"id": 4, "error": "zone domain is already published."}`, refusal: "zone domain is already published."},
		{name: "ok and error", line: `{"id": 4, "ok": true, "error": "both"}`, invalid: notExactlyOne},
		{name: "ok and empty error", line: `{"id": 4, "ok": true, "error": ""}`, invalid: notExactlyOne},
		{name: "false ok and error", line: `{"id": 4, "ok": false, "error": "refused"}`, invalid: notExactlyOne},
		{name: "neither", line: `{"id": 4}`, invalid: notExactlyOne},
		{name: "false ok", line: `{"id": 4, "ok": false}`, invalid: "ok must be true"},
		{name: "string ok", line: `{"id": 4, "ok": "true"}`, invalid: "ok must be true"},
		{name: "empty error", line: `{"id": 4, "error": ""}`, invalid: "error must be a non-empty string"},
		{name: "object error", line: `{"id": 4, "error": {"code": "x"}}`, invalid: "error must be a non-empty string"},
		{name: "unknown field", line: `{"id": 4, "ok": true, "warning": "x"}`, invalid: notExactlyOne},
		{name: "another command", line: `{"id": 3, "ok": true}`, invalid: "does not answer command 4"},
		{name: "string id", line: `{"id": "4", "ok": true}`, invalid: "does not answer command 4"},
		{name: "no id", line: `{"ok": true}`, invalid: "does not answer command 4"},
		{name: "second object", line: `{"id": 4, "ok": true} {"id": 5, "ok": true}`, invalid: "has content after its object"},
		{name: "trailing text", line: `{"id": 4, "ok": true}x`, invalid: "has content after its object"},
		{name: "not JSON", line: `ready`, invalid: "invalid character"},
		{name: "not an object", line: `[4]`, invalid: "cannot unmarshal array"},
	} {
		t.Run(test.name, func(t *testing.T) {
			refusal, err := parseStackAcknowledgement(test.line, 4)
			if test.invalid != "" {
				if err == nil || !strings.Contains(err.Error(), test.invalid) {
					t.Fatalf("got refusal %q, err %v; want invalid %q", refusal, err, test.invalid)
				}
				return
			}
			if err != nil || refusal != test.refusal {
				t.Fatalf("got refusal %q, err %v; want refusal %q", refusal, err, test.refusal)
			}
		})
	}
}
