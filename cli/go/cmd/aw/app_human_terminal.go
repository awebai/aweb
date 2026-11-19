package main

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// protectedTerminal refuses, with code, a protected value that no human at
// a terminal can type or see: one without a controlling terminal, or one
// inside an agent runtime. It prevents mistakes; it is not a boundary
// against an agent running as the same OS user.
func protectedTerminal(code string, attached func() bool) error {
	for _, name := range agentRuntimeMarkers {
		if strings.TrimSpace(os.Getenv(name)) != "" {
			return withErrorCode(code, fmt.Errorf("this needs a human at a terminal; it refuses inside an agent runtime (%s is set)", name))
		}
	}
	if !attached() {
		return withErrorCode(code, errors.New("this needs a human at an interactive terminal"))
	}
	return nil
}
