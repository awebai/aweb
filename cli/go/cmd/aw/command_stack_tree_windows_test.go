//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
)

// taskkillNotFound is taskkill's exit status when no such process exists.
const taskkillNotFound = 128

// ownProcessTree leaves command as is: killProcessTree walks its descendants.
func ownProcessTree(*exec.Cmd) {}

// killProcessTree kills process and every process it started. A process
// already gone is not an error.
func killProcessTree(process *os.Process) error {
	out, err := exec.Command("taskkill", "/T", "/F", "/PID", strconv.Itoa(process.Pid)).CombinedOutput()
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == taskkillNotFound {
		return nil
	}
	if err != nil {
		return fmt.Errorf("taskkill: %w: %s", err, out)
	}
	return nil
}
