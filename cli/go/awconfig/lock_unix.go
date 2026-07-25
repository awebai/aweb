//go:build !windows

package awconfig

import (
	"os"
	"path/filepath"
	"syscall"
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
	flags := os.O_RDWR
	if create {
		if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
			return nil, err
		}
		flags |= os.O_CREATE
	}
	f, err := os.OpenFile(lockPath, flags, 0o600)
	if err != nil {
		return nil, err
	}
	operation := syscall.LOCK_EX
	if nonBlocking {
		operation |= syscall.LOCK_NB
	}
	if err := syscall.Flock(int(f.Fd()), operation); err != nil {
		_ = f.Close()
		if nonBlocking && (err == syscall.EWOULDBLOCK || err == syscall.EAGAIN) {
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
	_ = syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}
