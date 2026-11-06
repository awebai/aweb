//go:build !windows

package main

import (
	"os/exec"
	"syscall"
)

func configureHumanInitWithoutTerminal(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
}
