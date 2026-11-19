package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

type protectedTerminalCode string

const (
	protectedInputUnavailable  protectedTerminalCode = "protected_input_unavailable"
	protectedOutputUnavailable protectedTerminalCode = "protected_output_unavailable"
)

// Runtime markers indicate an agent process; their absence does not prove that
// a human is present. The controlling terminal is required independently.
var agentRuntimeMarkers = []string{"OATS_INSTANCE_HOME", "OATS_INSTANCE", "CLAUDECODE", "CLAUDE_CODE_ENTRYPOINT", "CODEX_THREAD_ID"}

// requireHumanTerminal owns the local accident barrier from
// docs/design/human-confirmation-from-aw.md, "Values" (lines 374–382). It is not
// an authority boundary against another process running as the same OS user.
func requireHumanTerminal(attached func() bool) error {
	for _, name := range agentRuntimeMarkers {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return fmt.Errorf("this command needs a human at a terminal; it refuses inside an agent runtime (%s is set). Run it yourself from an interactive terminal outside the agent runtime", name)
		}
	}
	if !attached() {
		return errors.New("this command needs a human at an interactive terminal. Run it yourself from an interactive terminal outside the agent runtime")
	}
	return nil
}

// protectedTerminal keeps the app's released input/output refusal codes while
// sharing the same human-presence rule as identity commands.
func protectedTerminal(code protectedTerminalCode, attached func() bool) error {
	if err := requireHumanTerminal(attached); err != nil {
		return withErrorCode(string(code), err)
	}
	return nil
}
