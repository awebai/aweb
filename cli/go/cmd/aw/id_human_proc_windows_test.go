//go:build windows

package main

import (
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

func configureHumanInitWithoutTerminal(cmd *exec.Cmd) {
	// Redirecting stdin alone does not detach the inherited console: the
	// human prompt opens CONIN$ directly.
	cmd.SysProcAttr = &syscall.SysProcAttr{CreationFlags: windows.DETACHED_PROCESS}
}
