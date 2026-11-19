//go:build unix

package main

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
)

// ownProcessTree starts command as the leader of its own process group, so
// killProcessTree reaches everything it starts.
func ownProcessTree(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessTree kills process's whole group. A group already gone is not
// an error.
func killProcessTree(process *os.Process) error {
	if err := syscall.Kill(-process.Pid, syscall.SIGKILL); err != nil && !errors.Is(err, syscall.ESRCH) {
		return err
	}
	return nil
}
