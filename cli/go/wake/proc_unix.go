//go:build !windows

package wake

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

func managedProcessGroupsSupported() bool { return true }
func managedProcessGroupGone(pgid int) (bool, error) {
	if pgid <= 0 {
		return false, fmt.Errorf("invalid owned process group")
	}
	err := syscall.Kill(-pgid, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("owned process group %d confirmation: %w", pgid, err)
	}
	return false, nil
}

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

func configureChildProcess(cmd *exec.Cmd)       { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func terminateChildProcess(cmd *exec.Cmd) error { return cmd.Process.Signal(syscall.SIGTERM) }
func killChildProcessGroup(cmd *exec.Cmd)       { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
