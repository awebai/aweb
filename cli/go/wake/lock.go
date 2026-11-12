package wake

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
)

// ErrDaemonAlreadyRunning is returned when the host already has a broker.
type ErrDaemonAlreadyRunning struct {
	PID int
}

func (e *ErrDaemonAlreadyRunning) Error() string {
	return fmt.Sprintf("wake broker is already running (pid %d)", e.PID)
}

// Lock is the one-daemon-per-host lock: an exclusive OS lock on a file, which
// the kernel drops when the holding process exits however it exits. The
// holder's pid is recorded beside the file for display only; whether the lock
// is held is never read from it.
type Lock struct {
	path string
	held io.Closer
}

const (
	// A LockOwner probe holds the lock for an instant, so a refusal is
	// believed only when it repeats.
	lockAcquireAttempts   = 3
	lockAcquireRetryDelay = 20 * time.Millisecond
)

// AcquireLock takes the daemon lock. A lock whose holder no longer exists is
// free, because a broker crash must never make a restart impossible — restart
// is the documented recovery (§6).
func AcquireLock(path string) (*Lock, error) {
	for attempt := 1; ; attempt++ {
		held, err := awconfig.TryLockExclusive(path)
		if err == nil {
			lock := &Lock{path: path, held: held}
			if err := lock.writePID(); err != nil {
				_ = lock.Release()
				return nil, err
			}
			return lock, nil
		}
		if !errors.Is(err, awconfig.ErrLockUnavailable) {
			return nil, err
		}
		if attempt == lockAcquireAttempts {
			// Including this process: a second `aw wake run` is a second
			// process in production, and exempting our own pid would make a
			// same-process second start silently steal the lock.
			pid, _ := readPID(lockPIDPath(path))
			return nil, &ErrDaemonAlreadyRunning{PID: pid}
		}
		time.Sleep(lockAcquireRetryDelay)
	}
}

func lockPIDPath(path string) string { return path + ".pid" }

func (l *Lock) writePID() error {
	return os.WriteFile(lockPIDPath(l.path), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
}

// Release removes the pid record and drops the lock. The lock file stays:
// removing it would let a waiting process lock a file that is no longer at
// the path.
func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	removeErr := os.Remove(lockPIDPath(l.path))
	if os.IsNotExist(removeErr) {
		removeErr = nil
	}
	return errors.Join(removeErr, l.held.Close())
}

// LockOwner reports whether a process holds the lock, and the pid it
// recorded.
func LockOwner(path string) (int, bool) {
	probe, err := awconfig.TryLockExistingExclusive(path)
	if err == nil {
		_ = probe.Close()
		return 0, false
	}
	if !errors.Is(err, awconfig.ErrLockUnavailable) {
		return 0, false
	}
	pid, _ := readPID(lockPIDPath(path))
	return pid, true
}

func readPID(path string) (int, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, false
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil || pid <= 0 {
		return 0, false
	}
	return pid, true
}
