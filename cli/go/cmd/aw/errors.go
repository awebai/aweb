package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/awebai/aw/awid"
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

// codedError names a refusal class for the --json error envelope. The code is
// the stable contract; the message and the exit code are those of err.
type codedError struct {
	code string
	err  error
}

func (e *codedError) Error() string { return e.err.Error() }

func (e *codedError) Unwrap() error { return e.err }

func withErrorCode(code string, err error) error {
	return &codedError{code: code, err: err}
}

// plainRefusal is a refusal by an aweb server or AWID registry told in a
// sentence for people. It wraps the refusal, so --json keeps its code, status
// and detail.
type plainRefusal struct {
	text string
	err  error
}

func (e *plainRefusal) Error() string { return e.text }

func (e *plainRefusal) Unwrap() error { return e.err }

// isAliasConflict reports a refusal because another active member of the team
// holds the name.
func isAliasConflict(err error) bool {
	return awid.DescribeError(err).Code == "alias_conflict"
}

// nameTakenText says that another active member of teamID holds alias, and
// which flag of the command picks another name.
func nameTakenText(alias, teamID, flag string) string {
	return fmt.Sprintf("The name %s is already taken in %s. Pick another with %s.", alias, teamID, flag)
}

// cliErrorEnvelope is what --json prints for a failed command: the error's
// awid.ErrorDetail, with the code of a tagged refusal, and its message.
type cliErrorEnvelope struct {
	Error cliErrorBody `json:"error"`
}

type cliErrorBody struct {
	Code       string `json:"code"`
	Message    string `json:"message"`
	HTTPStatus int    `json:"http_status,omitempty"`
	Detail     string `json:"detail,omitempty"`
	Reason     string `json:"reason,omitempty"`
}

func errorEnvelope(err error, message string) cliErrorEnvelope {
	detail := awid.DescribeError(err)
	var coded *codedError
	if errors.As(err, &coded) {
		detail.Code = coded.code
	}
	return cliErrorEnvelope{Error: cliErrorBody{Code: detail.Code, Message: message, HTTPStatus: detail.HTTPStatus, Detail: detail.Detail, Reason: detail.Reason}}
}

func writeCLIErrorEnvelope(w io.Writer, err error, message string) {
	encoded, _ := json.Marshal(errorEnvelope(err, message))
	fmt.Fprintln(w, string(encoded))
}
