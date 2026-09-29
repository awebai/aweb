package wake

import (
	"testing"

	"github.com/awebai/aw/wake/session"
)

// TestStateToActionTable asserts every cell of the table in
// docs/terminal-wake-broker.md §4 — three intents by six states, plus the
// unconfirmed row that overrides all of them.
//
// The unrecognised-string cases go through session.NormalizeState first,
// because that is how an unknown vocabulary actually reaches this function:
// the broker never sees a raw state string here.
func TestStateToActionTable(t *testing.T) {
	intents := []Intent{IntentWake, IntentSteer, IntentAmbient}

	confirmedByIntent := map[Intent]map[session.State]Action{
		IntentWake: {
			session.StateIdle:    ActionSubmit,
			session.StateBusy:    ActionDefer,
			session.StateBlocked: ActionDefer,
			session.StateShell:   ActionDefer,
			session.StateUnknown: ActionSubmit,
			session.StateStopped: ActionInactive,
		},
		IntentSteer: {
			session.StateIdle:    ActionSubmit,
			session.StateBusy:    ActionDefer,
			session.StateBlocked: ActionDefer,
			session.StateShell:   ActionDefer,
			session.StateUnknown: ActionSubmit,
			session.StateStopped: ActionInactive,
		},
		IntentAmbient: {
			session.StateIdle:    ActionDefer,
			session.StateBusy:    ActionDefer,
			session.StateBlocked: ActionDefer,
			session.StateShell:   ActionDefer,
			session.StateUnknown: ActionDefer,
			session.StateStopped: ActionInactive,
		},
	}

	for _, intent := range intents {
		for state, want := range confirmedByIntent[intent] {
			if got := ActionFor(intent, state, true); got != want {
				t.Errorf("confirmed live: ActionFor(%s, %s)=%s want %s", intent, state, got, want)
			}
			// Before the first confirmed live inspect nothing is submitted and
			// nothing is concluded — not even `stopped` means inactive (§4).
			if got := ActionFor(intent, state, false); got != ActionWaitPending {
				t.Errorf("unconfirmed: ActionFor(%s, %s)=%s want %s", intent, state, got, ActionWaitPending)
			}
		}
	}
}

func TestRawStateStringsReachTheirTableCell(t *testing.T) {
	cases := []struct {
		raw  string
		want Action
	}{
		{"idle", ActionSubmit},
		{"done", ActionSubmit},
		{"working", ActionDefer},
		{"blocked", ActionDefer},
		{"shell", ActionDefer},
		{"generic shell", ActionDefer},
		{"unknown", ActionSubmit},
		{"stopped", ActionInactive},
		{"not-launched", ActionInactive},

		// Anything unrecognised degrades to the unknown column, which submits
		// under the coalescing window and rate limit rather than crashing or
		// going deaf.
		{"", ActionSubmit},
		{"vibrating", ActionSubmit},
		{"idle(ish)", ActionSubmit},
	}
	for _, tc := range cases {
		got := ActionFor(IntentWake, session.NormalizeState(tc.raw), true)
		if got != tc.want {
			t.Errorf("raw state %q -> %s, want %s", tc.raw, got, tc.want)
		}
	}
}

// TestWorkingAndBlockedNeverSubmit is the §6 prohibition stated as its own
// test, so a future edit to the table cannot quietly lose it.
func TestAmbientNeverInitiatesModelInput(t *testing.T) {
	for _, state := range []session.State{session.StateIdle, session.StateBusy, session.StateBlocked, session.StateShell, session.StateUnknown} {
		if got := ActionFor(IntentAmbient, state, true); got == ActionSubmit {
			t.Errorf("ActionFor(ambient, %s) submitted without a real wake/steer", state)
		}
	}
}

func TestWorkingAndBlockedAndShellNeverSubmit(t *testing.T) {
	for _, state := range []session.State{session.StateBusy, session.StateBlocked, session.StateShell} {
		for _, intent := range []Intent{IntentWake, IntentSteer, IntentAmbient} {
			for _, confirmed := range []bool{true, false} {
				if got := ActionFor(intent, state, confirmed); got == ActionSubmit {
					t.Errorf("ActionFor(%s, %s, confirmed=%t) submitted into a %s instance", intent, state, confirmed, state)
				}
			}
		}
	}
}
