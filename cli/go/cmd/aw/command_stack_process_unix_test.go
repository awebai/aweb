//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// These drive commandStackProcess with small shell stacks instead of the real
// one: the lifecycle under test is the harness's own, and each failure needs a
// stack that misbehaves on cue. Deadlines are chosen per test; a stage under
// test gets a short one, the others room to pass.

const answeringStack = `echo '{"ready":true}'
while IFS= read -r line; do
	id=${line#*\"id\":}; id=${id%%[,\}]*}
	echo "{\"id\":$id,\"ok\":true}"
done`

var roomyStackDeadlines = commandStackDeadlines{Ready: 10 * time.Second, Command: 10 * time.Second, Stop: 10 * time.Second}

// stackWithChild returns a shell stack that first starts a long-lived child
// and records its pid, then runs body.
func stackWithChild(t *testing.T, body string) (*exec.Cmd, string) {
	t.Helper()
	pidFile := filepath.Join(t.TempDir(), "child.pid")
	return exec.Command("sh", "-c", `sleep 300 & echo $! > "$CHILD_PID"`+"\n"+body), pidFile
}

func startStack(t *testing.T, command *exec.Cmd, pidFile string, deadlines commandStackDeadlines) (*commandStackProcess, string, error) {
	t.Helper()
	command.Env = append(os.Environ(), "CHILD_PID="+pidFile)
	// Whatever an assertion concludes, nothing this test started outlives it.
	t.Cleanup(func() {
		if command.Process != nil {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		}
		if data, err := os.ReadFile(pidFile); err == nil {
			if child, err := strconv.Atoi(strings.TrimSpace(string(data))); err == nil {
				_ = syscall.Kill(child, syscall.SIGKILL)
			}
		}
	})
	return startCommandStackProcess(command, deadlines)
}

// requireGone fails unless pid has exited within a bound; a killed process
// is reaped by its parent shortly after the signal, with no event to wait on.
func requireGone(t *testing.T, what string, pid int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if err := syscall.Kill(pid, 0); errors.Is(err, syscall.ESRCH) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s %d still exists after the stack was terminated", what, pid)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func requireTreeGone(t *testing.T, command *exec.Cmd, pidFile string) {
	t.Helper()
	requireGone(t, "stack process", command.Process.Pid)
	data, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatalf("stack did not record its child: %v", err)
	}
	child, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	requireGone(t, "stack child", child)
}

// requireReaderReleased fails unless the stdout reader has returned, read
// from its own done signal rather than from the data it delivers.
func requireReaderReleased(t *testing.T, process *commandStackProcess) {
	t.Helper()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-process.readerDone:
	case <-timer.C:
		t.Fatal("the stack's stdout reader is still running after termination")
	}
}

func TestStackProcessAnswersCommandsAndStopsWhenItsInputCloses(t *testing.T) {
	command, pidFile := stackWithChild(t, answeringStack)
	process, ready, err := startStack(t, command, pidFile, roomyStackDeadlines)
	if err != nil {
		t.Fatal(err)
	}
	if ready != `{"ready":true}` {
		t.Fatalf("readiness line = %q", ready)
	}
	for range 3 {
		if err := process.send(stackZone, commandZone{Domain: "a.test", Controller: "did:key:z"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := process.stop(); err != nil {
		t.Fatalf("a stack that exits at end of input did not stop cleanly: %v", err)
	}
	requireTreeGone(t, command, pidFile)
	requireReaderReleased(t, process)
}

func TestStackProcessSilentAtReadinessIsKilledWithItsChildren(t *testing.T) {
	command, pidFile := stackWithChild(t, `exec sleep 300`)
	deadlines := roomyStackDeadlines
	deadlines.Ready = 200 * time.Millisecond
	_, _, err := startStack(t, command, pidFile, deadlines)
	if err == nil || !strings.Contains(err.Error(), "stack readiness: no answer within 200ms") {
		t.Fatalf("silent stack: got %v", err)
	}
	requireTreeGone(t, command, pidFile)
}

func TestStackProcessWithoutAnAcknowledgementIsKilledAndAnswersNothingMore(t *testing.T) {
	command, pidFile := stackWithChild(t, `echo '{"ready":true}'
cat > /dev/null`)
	deadlines := roomyStackDeadlines
	deadlines.Command = 200 * time.Millisecond
	process, _, err := startStack(t, command, pidFile, deadlines)
	if err != nil {
		t.Fatal(err)
	}
	err = process.send(stackResetRateLimits, map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "reset_rate_limits command 1: no answer within 200ms") {
		t.Fatalf("unanswered command: got %v", err)
	}
	requireTreeGone(t, command, pidFile)
	requireReaderReleased(t, process)
	err = process.send(stackResetRateLimits, map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "stack stopped after an earlier failure") {
		t.Fatalf("a command after the failure was sent: %v", err)
	}
	if err := process.stop(); err == nil || !strings.Contains(err.Error(), "stack was stopped by") {
		t.Fatalf("stop did not report the failure that ended the stack: %v", err)
	}
}

func TestStackProcessThatStopsReadingIsKilledWhenAWriteBlocks(t *testing.T) {
	command, pidFile := stackWithChild(t, `echo '{"ready":true}'
exec sleep 300`)
	deadlines := roomyStackDeadlines
	deadlines.Command = 200 * time.Millisecond
	process, _, err := startStack(t, command, pidFile, deadlines)
	if err != nil {
		t.Fatal(err)
	}
	// Larger than any pipe buffer, so the write cannot complete unread.
	err = process.send(stackPublicOrigin, strings.Repeat("x", 4<<20))
	if err == nil || !strings.Contains(err.Error(), "send public_origin command 1: not accepted within 200ms") {
		t.Fatalf("blocked write: got %v", err)
	}
	requireTreeGone(t, command, pidFile)
	requireReaderReleased(t, process)
}

func TestStackProcessThatRefusesToStopIsKilledWithItsChildren(t *testing.T) {
	command, pidFile := stackWithChild(t, `trap '' TERM HUP INT
echo '{"ready":true}'
cat > /dev/null
while :; do sleep 1; done`)
	deadlines := roomyStackDeadlines
	deadlines.Stop = 300 * time.Millisecond
	process, _, err := startStack(t, command, pidFile, deadlines)
	if err != nil {
		t.Fatal(err)
	}
	err = process.stop()
	if err == nil || !strings.Contains(err.Error(), "stack did not stop within 300ms after its input closed; killed") {
		t.Fatalf("stack that ignores the end of its input: got %v", err)
	}
	requireTreeGone(t, command, pidFile)
	requireReaderReleased(t, process)
}

func TestStackProcessWithAMalformedAcknowledgementIsKilled(t *testing.T) {
	command, pidFile := stackWithChild(t, `echo '{"ready":true}'
read -r line
echo '{"id":1,"ok":true}{"id":2,"ok":true}'
cat > /dev/null`)
	process, _, err := startStack(t, command, pidFile, roomyStackDeadlines)
	if err != nil {
		t.Fatal(err)
	}
	err = process.send(stackResetRateLimits, map[string]any{})
	if err == nil || !strings.Contains(err.Error(), "has content after its object") {
		t.Fatalf("malformed acknowledgement: got %v", err)
	}
	requireTreeGone(t, command, pidFile)
	requireReaderReleased(t, process)
}

func TestStackProcessReleasesItsReaderFromALineNobodyAwaits(t *testing.T) {
	// One acknowledgement, then a line no command asked for, then the stack
	// waits for the end of its input.
	command, pidFile := stackWithChild(t, `echo '{"ready":true}'
read -r line
echo '{"id":1,"ok":true}'
echo '{"id":2,"ok":true}'
cat > /dev/null`)
	process, _, err := startStack(t, command, pidFile, roomyStackDeadlines)
	if err != nil {
		t.Fatal(err)
	}
	if err := process.send(stackResetRateLimits, map[string]any{}); err != nil {
		t.Fatal(err)
	}
	if err := process.stop(); err != nil {
		t.Fatalf("stop: %v", err)
	}
	requireTreeGone(t, command, pidFile)
	requireReaderReleased(t, process)
}
