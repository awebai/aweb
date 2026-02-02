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
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}

	handle := windows.Handle(f.Fd())
	var ol windows.Overlapped
	// Lock a single byte as a global mutex for this config path.
	if err := windows.LockFileEx(handle, windows.LOCKFILE_EXCLUSIVE_LOCK, 0, 1, 0, &ol); err != nil {
		_ = f.Close()
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
