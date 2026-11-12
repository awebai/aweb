// Package handoff is aw's side of the human handoff: the loopback listener,
// the console-header signatures and the requests that start a handoff,
// collect its result and use a console session
// (docs/design/handoff-wire.md).
package handoff

import "errors"

// Error is a handoff failure with a stable code.
type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error { return e.Err }

func coded(code string, err error) error { return &Error{Code: code, Err: err} }

// ErrorCode is err's stable code, or "" when it has none.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
