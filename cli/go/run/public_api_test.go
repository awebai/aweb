package run_test

import (
	"testing"

	awrun "github.com/awebai/aw/run"
)

type fakeUI struct{}

func (f *fakeUI) Start() error                      { return nil }
func (f *fakeUI) Stop() error                       { return nil }
func (f *fakeUI) Events() <-chan awrun.ControlEvent { return nil }
func (f *fakeUI) HasPendingInput() bool             { return false }
func (f *fakeUI) AppendText(string)                 {}
func (f *fakeUI) AppendLine(string)                 {}
func (f *fakeUI) SetInputLine(string)               {}
func (f *fakeUI) SetStatusLine(string)              {}
func (f *fakeUI) ClearStatusLine()                  {}
func (f *fakeUI) ClearInputLine()                   {}
func (f *fakeUI) SetExitConfirmation(bool)          {}
func (f *fakeUI) HasActiveProgram() bool            { return false }

// A type outside the run package implements its public UI and input
// controller interfaces; this file fails to compile if either one gains a
// method an external implementation cannot provide.
var (
	_ awrun.UI              = (*fakeUI)(nil)
	_ awrun.InputController = (*fakeUI)(nil)
)

func TestPublicUICanBeImplementedOutsideRunPackage(t *testing.T) {
	ui := &fakeUI{}
	loop := awrun.Loop{Control: ui}
	if loop.Control != awrun.InputController(ui) {
		t.Fatal("a Loop does not keep the external UI as its control")
	}
}
