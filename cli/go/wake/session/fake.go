package session

import (
	"context"
	"sync"
)

// Scripted is one scripted answer for a single Inspect call.
type Scripted struct {
	Inspection Inspection
	Err        error
}

// Submission records one Input call the fake accepted or refused.
type Submission struct {
	Home string
	Text string
	Err  error
}

// Fake is an in-process Client that returns scripted envelopes. It is the only
// session client the unit tests use: no OATS, no terminal, no network.
//
// It lives in the production package rather than a _test.go file because the
// broker's own tests import it, and Go does not export test files across
// packages. It has no production caller.
type Fake struct {
	mu sync.Mutex

	// Answers is consumed in order; the last one repeats once exhausted.
	Answers []Scripted
	// InputErr, when set, fails every Input.
	InputErr error

	inspects    []string
	submissions []Submission
	next        int
}

// NewFake returns a Fake that always answers with one inspection.
func NewFake(in Inspection) *Fake {
	return &Fake{Answers: []Scripted{{Inspection: in}}}
}

// Script replaces the answer script and rewinds it.
func (f *Fake) Script(answers ...Scripted) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Answers = answers
	f.next = 0
}

func (f *Fake) Inspect(_ context.Context, home string) (Inspection, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.inspects = append(f.inspects, home)
	if len(f.Answers) == 0 {
		return Inspection{}, &Error{Code: "E_OATS_UNREACHABLE", Message: "fake has no scripted answer"}
	}
	idx := f.next
	if idx >= len(f.Answers) {
		idx = len(f.Answers) - 1
	} else {
		f.next++
	}
	answer := f.Answers[idx]
	return answer.Inspection, answer.Err
}

func (f *Fake) Input(_ context.Context, home, text string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	err := f.InputErr
	f.submissions = append(f.submissions, Submission{Home: home, Text: text, Err: err})
	return err
}

// Submissions returns every Input call, in order.
func (f *Fake) Submissions() []Submission {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]Submission, len(f.submissions))
	copy(out, f.submissions)
	return out
}

// Inspects returns every inspected home, in order.
func (f *Fake) Inspects() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]string, len(f.inspects))
	copy(out, f.inspects)
	return out
}
