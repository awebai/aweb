// Package handoff is aw's side of the human handoff: the loopback listener,
// the console-header signatures and the requests that start a handoff,
// collect its result and use a console session
// (docs/design/handoff-wire.md).
package handoff

import (
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"
)

// Error is a handoff failure with a stable code.
type Error struct {
	Code string
	Err  error
	// RetryAfter is the service's explicit hint, from a 429 or 503 answer's
	// Retry-After, of when the same request may succeed; Hinted says it was
	// given. It never extends an operation's deadline.
	RetryAfter time.Duration
	Hinted     bool
	// Facts, when set, make the error read as the code's sentence for
	// people (Sentence); the code stays the stable contract.
	Facts *Facts
}

func (e *Error) Error() string {
	if e.Facts != nil {
		return Sentence(e.Code, *e.Facts)
	}
	return e.Code + ": " + e.Err.Error()
}

// Retell is err told again with more facts: a sentence-telling refusal
// keeps its code and gains what add sets. Any other error is err.
func Retell(err error, add func(*Facts)) error {
	var e *Error
	if !errors.As(err, &e) || e.Facts == nil {
		return err
	}
	facts := *e.Facts
	add(&facts)
	return &Error{Code: e.Code, Err: err, RetryAfter: e.RetryAfter, Hinted: e.Hinted, Facts: &facts}
}

// told is err as code's sentence, told with facts.
func told(code string, err error, facts Facts) error {
	return &Error{Code: code, Err: err, Facts: &facts}
}
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

// retryHint is the explicit retry hint err carries, if any.
func retryHint(err error) (time.Duration, bool) {
	var e *Error
	if errors.As(err, &e) && e.Hinted {
		return e.RetryAfter, true
	}
	return 0, false
}

// hinted gives err the Retry-After of a 429 or 503 answer. Only delta-seconds
// is a hint; anything else is none. A value too large for a duration is the
// longest one, so it fails a deadline check rather than wrapping around.
func hinted(err error, resp *http.Response) error {
	var e *Error
	if !errors.As(err, &e) || (resp.StatusCode != http.StatusTooManyRequests && resp.StatusCode != http.StatusServiceUnavailable) {
		return err
	}
	value := resp.Header.Get("Retry-After")
	if value == "" || len(value) > 20 {
		return err
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return err
		}
	}
	e.Hinted = true
	seconds, parseErr := strconv.ParseUint(value, 10, 64)
	if parseErr != nil || seconds > uint64(math.MaxInt64/int64(time.Second)) {
		e.RetryAfter = time.Duration(math.MaxInt64)
	} else {
		e.RetryAfter = time.Duration(seconds) * time.Second
	}
	if e.Facts != nil && seconds <= uint64(math.MaxInt64/int64(time.Second)) {
		e.Facts.RetryAt = now().Add(e.RetryAfter)
	}
	return err
}
