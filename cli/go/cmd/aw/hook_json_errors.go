package main

import (
	"errors"
	"fmt"
)

type hookJSONProblem uint8

const (
	invalidHookJSON hookJSONProblem = iota
	duplicateHookJSONKey
	nonObjectHookSettings
	nonObjectHooks
)

type hookJSONError struct {
	Problem hookJSONProblem
	Detail  string
}

func (err *hookJSONError) Error() string { return err.Detail }

// hookSettingsParseError implements docs/runtime-hook-configuration.md:18-20.
// File context belongs at the file boundary; the parser supplies the repair kind.
func hookSettingsParseError(path string, parseErr error) error {
	repair := "Correct the hook structure described above."
	var problem *hookJSONError
	if errors.As(parseErr, &problem) {
		switch problem.Problem {
		case invalidHookJSON:
			repair = "Fix the JSON syntax."
		case duplicateHookJSONKey:
			repair = "Remove the duplicate JSON key."
		case nonObjectHookSettings:
			repair = "Use a JSON object for the settings."
		case nonObjectHooks:
			repair = "Set hooks to a JSON object."
		}
	}
	return fmt.Errorf("%s: %w. %s Save the file and retry the command.", path, parseErr, repair)
}
