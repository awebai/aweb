//go:build windows

package wake

import (
	"fmt"
	"os/exec"
)

func managedProcessGroupsSupported() bool { return false }
func managedProcessGroupGone(pgid int) (bool, error) {
	return false, fmt.Errorf("owned process-group confirmation unsupported")
}

func configureChildProcess(cmd *exec.Cmd)       {}
func terminateChildProcess(cmd *exec.Cmd) error { return cmd.Process.Kill() }
func killChildProcessGroup(cmd *exec.Cmd)       { _ = cmd.Process.Kill() }
