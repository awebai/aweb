package wake

import "github.com/awebai/aw/wake/session"

// Action is what the broker does with a pending set after one inspect.
type Action int

const (
	// ActionSubmit types now, subject only to the per-instance rate limit.
	ActionSubmit Action = iota
	// ActionDefer holds the hints and re-evaluates on the next inspect poll,
	// with an unbounded wait. An instance that never leaves `working` fills
	// its hint store and reports the backlog and every eviction in status.
	ActionDefer
	// ActionInactive closes the stream's interest in this instance and marks
	// the registration inactive. Removal stays with the retire hook.
	ActionInactive
	// ActionWaitPending tolerates a pending home: no confirmed live inspect
	// has happened yet, so nothing is submitted and nothing is concluded.
	ActionWaitPending
)

func (a Action) String() string {
	switch a {
	case ActionSubmit:
		return "submit"
	case ActionDefer:
		return "defer"
	case ActionInactive:
		return "inactive"
	default:
		return "wait-pending"
	}
}

// ActionFor is the state-to-action table of docs/terminal-wake-broker.md §4.
//
//	| Intent  | idle/done | working | blocked | shell | unknown            | stopped/not-launched |
//	| wake    | type now  | defer   | defer   | defer | coalesce, limited  | inactive after first confirmed live |
//	| steer   | type now  | defer   | defer   | defer | coalesce, limited  | inactive after first confirmed live |
//	| ambient | type now  | defer   | defer   | defer | coalesce, limited  | inactive after first confirmed live |
//
// The shell column is the one addition to the note's table, from the OATS
// lead's samples: startup can briefly report "shell" before the exec begins,
// and §5 already has `input` refuse a fallback shell left by an exited
// harness. Deferring is the same verdict the note reaches for `blocked` — a
// real signal that the target is not the harness — reached one step earlier.
//
// The three intent rows are identical as the note writes them: the annotations
// differ ("defer, coalesce" for ambient) but coalescing is what deferral does
// here — a deferred hint stays in the pending set — so the action is the same
// cell. Intent is still a parameter, because it is a parameter of the note's
// table and every one of the fifteen cells is asserted.
//
// confirmedLive is whether one live inspect (ok, present:true) has been seen
// for this instance. Before that, everything is tolerated and nothing is
// submitted (§4, §6: "Never submit before the first confirmed live inspect").
func ActionFor(intent Intent, state session.State, confirmedLive bool) Action {
	if !confirmedLive {
		return ActionWaitPending
	}
	switch state {
	case session.StateIdle:
		return ActionSubmit
	case session.StateBusy, session.StateBlocked, session.StateShell:
		return ActionDefer
	case session.StateUnknown:
		// tmux always says unknown and carries no readiness promise. No amount
		// of waiting turns that into one, so the policy is the coalescing
		// window plus the rate limit — both applied by the caller — and not a
		// delay (§4).
		return ActionSubmit
	case session.StateStopped:
		return ActionInactive
	default:
		// Unreachable: session.NormalizeState is total. Conservative anyway.
		return ActionDefer
	}
}
