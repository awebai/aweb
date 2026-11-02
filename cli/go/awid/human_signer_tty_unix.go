//go:build !windows

package awid

const (
	controllingTerminalInput  = "/dev/tty"
	controllingTerminalOutput = "/dev/tty"
)
