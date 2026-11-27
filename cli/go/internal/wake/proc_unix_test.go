//go:build !windows

package wake

import (
	"os"
	"syscall"
)

// processAlive reports whether pid names a live process. Signal 0 performs the
// existence and permission checks without delivering anything.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = proc.Signal(syscall.Signal(0))
	if err == nil {
		return true
	}
	// EPERM means the process exists and belongs to someone else.
	return err == syscall.EPERM
}
