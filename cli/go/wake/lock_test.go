package wake

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const lockHolderPathEnv = "AW_WAKE_TEST_LOCK_HOLDER_PATH"

// TestLockHolderProcess is the body of the child process the lock tests
// start: it takes the daemon lock, says so, and holds it until its stdin
// closes or it is killed.
func TestLockHolderProcess(t *testing.T) {
	path := os.Getenv(lockHolderPathEnv)
	if path == "" {
		return
	}
	if _, err := AcquireLock(path); err != nil {
		fmt.Printf("refused: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("held")
	_, _ = io.Copy(io.Discard, os.Stdin)
	os.Exit(0)
}

// startLockHolder runs a second process that holds the daemon lock at path
// and returns once it has it.
func startLockHolder(t *testing.T, path string) *exec.Cmd {
	t.Helper()
	holder := exec.Command(os.Args[0], "-test.run=^TestLockHolderProcess$")
	holder.Env = append(os.Environ(), lockHolderPathEnv+"="+path)
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := holder.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = stdin.Close()
		_ = holder.Process.Kill()
		_ = holder.Wait()
	})
	line, err := bufio.NewReader(stdout).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != "held" {
		t.Fatalf("the holder process did not take the lock: %q %v", line, err)
	}
	return holder
}

// recordPIDAsAlive rewrites every record of pid under dir to this process's
// pid, which is what the state looks like once the kernel has given a dead
// holder's pid to an unrelated live process.
func recordPIDAsAlive(t *testing.T, dir string, pid int) int {
	t.Helper()
	rewritten := 0
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || !info.Mode().IsRegular() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(data)) != strconv.Itoa(pid) {
			return nil
		}
		rewritten++
		return os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return rewritten
}

func TestLockLeftByAKilledHolderWhosePIDIsAliveAgainDoesNotBlockAStart(t *testing.T) {
	store := tempStore(t)

	holder := startLockHolder(t, store.LockPath())
	holderPID := holder.Process.Pid
	if err := holder.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = holder.Wait()
	if recordPIDAsAlive(t, store.Dir(), holderPID) == 0 {
		t.Fatal("the killed holder left no record of its pid to reuse")
	}

	lock, err := AcquireLock(store.LockPath())
	if err != nil {
		t.Fatalf("a lock whose holder was killed blocked a start: %v", err)
	}
	if err := lock.Release(); err != nil {
		t.Fatal(err)
	}
}

func TestLockHeldByALiveProcessRefusesNamingItsPID(t *testing.T) {
	store := tempStore(t)

	holder := startLockHolder(t, store.LockPath())

	_, err := AcquireLock(store.LockPath())
	var running *ErrDaemonAlreadyRunning
	if !errors.As(err, &running) {
		t.Fatalf("err=%v want ErrDaemonAlreadyRunning", err)
	}
	if running.PID != holder.Process.Pid {
		t.Errorf("refusal names pid %d, the holder is %d", running.PID, holder.Process.Pid)
	}
	if want := fmt.Sprintf("pid %d", holder.Process.Pid); !strings.Contains(err.Error(), want) {
		t.Errorf("refusal %q does not say %q", err, want)
	}
}

func TestLockReleasedCanBeTakenAgain(t *testing.T) {
	store := tempStore(t)

	first, err := AcquireLock(store.LockPath())
	if err != nil {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	second, err := AcquireLock(store.LockPath())
	if err != nil {
		t.Fatalf("a released lock could not be taken again: %v", err)
	}
	if err := second.Release(); err != nil {
		t.Fatal(err)
	}
}
