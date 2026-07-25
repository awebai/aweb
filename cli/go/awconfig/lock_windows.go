//go:build windows

package awconfig

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

type fileLock struct {
	f *os.File
}

func LockExclusive(lockPath string) (*fileLock, error) {
	return lockExclusive(lockPath, false, true)
}

func TryLockExclusive(lockPath string) (*fileLock, error) {
	return lockExclusive(lockPath, true, true)
}

func TryLockExistingExclusive(lockPath string) (*fileLock, error) {
	return lockExclusive(lockPath, true, false)
}

func lockExclusive(lockPath string, nonBlocking, create bool) (*fileLock, error) {
	openFlags := os.O_RDWR
	if create {
		if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
			return nil, err
		}
		openFlags |= os.O_CREATE
	}
	f, err := os.OpenFile(lockPath, openFlags, 0o600)
	if err != nil {
		return nil, err
	}

	handle := windows.Handle(f.Fd())
	var ol windows.Overlapped
	lockFlags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if nonBlocking {
		lockFlags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	// Lock a single byte as a global mutex for this config path.
	if err := windows.LockFileEx(handle, lockFlags, 0, 1, 0, &ol); err != nil {
		_ = f.Close()
		if nonBlocking && err == windows.ERROR_LOCK_VIOLATION {
			return nil, ErrLockUnavailable
		}
		return nil, err
	}
	return &fileLock{f: f}, nil
}

func (l *fileLock) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	handle := windows.Handle(l.f.Fd())
	var ol windows.Overlapped
	_ = windows.UnlockFileEx(handle, 0, 1, 0, &ol)
	return l.f.Close()
}
