package wake

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// ErrDaemonAlreadyRunning is returned when the host already has a broker.
type ErrDaemonAlreadyRunning struct {
	PID int
}

func (e *ErrDaemonAlreadyRunning) Error() string {
	return fmt.Sprintf("wake broker is already running (pid %d)", e.PID)
}

// Lock is the one-daemon-per-host lock: a directory, whose creation is atomic
// on every filesystem that matters, holding the owner's pid.
type Lock struct {
	dir string
}

// AcquireLock takes the daemon lock. A lock left by a process that no longer
// exists is reclaimed, because a broker crash must never make a restart
// impossible — restart is the documented recovery (§6).
func AcquireLock(dir string) (*Lock, error) {
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	for attempt := 0; attempt < 2; attempt++ {
		err := os.Mkdir(dir, 0o700)
		if err == nil {
			lock := &Lock{dir: dir}
			if err := lock.writePID(); err != nil {
				_ = lock.Release()
				return nil, err
			}
			return lock, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		pid, ok := readPID(filepath.Join(dir, "pid"))
		if ok && processAlive(pid) {
			// Including this process: a second `aw wake run` is a second
			// process in production, and exempting our own pid would make a
			// same-process second start silently steal the lock.
			return nil, &ErrDaemonAlreadyRunning{PID: pid}
		}
		// Stale: the owner is gone (or the pid file never landed).
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
	}
	return nil, errors.New("wake: could not acquire the daemon lock")
}

func (l *Lock) writePID() error {
	return os.WriteFile(filepath.Join(l.dir, "pid"), []byte(strconv.Itoa(os.Getpid())+"\n"), 0o600)
}

// Release removes the lock directory.
func (l *Lock) Release() error {
	if l == nil {
		return nil
	}
	return os.RemoveAll(l.dir)
}

// LockOwner reports the pid holding the lock, and whether it is alive.
func LockOwner(dir string) (int, bool) {
	pid, ok := readPID(filepath.Join(dir, "pid"))
	if !ok {
		return 0, false
	}
	return pid, processAlive(pid)
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
