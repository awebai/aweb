package main

import (
	"errors"
	"fmt"
)

type cliError struct {
	code int
	msg  string
}

func (e *cliError) Error() string {
	return e.msg
}

func (e *cliError) ExitCode() int {
	if e.code <= 0 {
		return 1
	}
	return e.code
}

func usageError(format string, args ...any) error {
	return &cliError{
		code: 2,
		msg:  fmt.Sprintf(format, args...),
	}
}

func exitCode(err error) int {
	var coder interface{ ExitCode() int }
	if errors.As(err, &coder) {
		return coder.ExitCode()
	}
	return 1
}
