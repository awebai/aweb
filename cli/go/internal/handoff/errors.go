// Package handoff implements app credential/session handoffs (docs/design/handoff-wire.md).
package handoff

type Error struct {
	Code string
	Err  error
}

func (e *Error) Error() string           { return e.Code + ": " + e.Err.Error() }
func (e *Error) Unwrap() error           { return e.Err }
func coded(code string, err error) error { return &Error{Code: code, Err: err} }
