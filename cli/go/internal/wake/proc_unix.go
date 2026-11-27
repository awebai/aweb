//go:build !windows

package wake

import (
	"errors"
	"fmt"
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

func configureChildProcess(cmd *exec.Cmd)       { cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true} }
func terminateChildProcess(cmd *exec.Cmd) error { return cmd.Process.Signal(syscall.SIGTERM) }
func killChildProcessGroup(cmd *exec.Cmd)       { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
