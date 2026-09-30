//go:build windows

package wake

import (
	"os"
	"os/exec"
)

// processAlive reports whether pid names a live process. On Windows
// os.FindProcess fails for a pid that does not exist.
func processAlive(pid int) bool {
	proc, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	_ = proc.Release()
	return true
}

func configureChildProcess(cmd *exec.Cmd)       {}
func terminateChildProcess(cmd *exec.Cmd) error { return cmd.Process.Kill() }
func killChildProcessGroup(cmd *exec.Cmd)       { _ = cmd.Process.Kill() }
