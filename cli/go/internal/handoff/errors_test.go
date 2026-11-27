package handoff

import "errors"

// ErrorCode is the handoff code an error carries, or "" when it carries none.
func ErrorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}
