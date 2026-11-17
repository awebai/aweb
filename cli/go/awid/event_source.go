package awid

import "context"

// EventSource is the protocol-layer abstraction for receiving agent events.
// Implementations handle connection management and reconnection internally.
type EventSource interface {
	Next(ctx context.Context) (*AgentEvent, error)
	Close() error
}

// WakeFilter decides whether an agent event should trigger a wake cycle.
// The autofeed parameter indicates whether automatic work dispatch is enabled.
type WakeFilter func(evt AgentEvent, autofeed bool) bool

// IsProtocolEvent returns true for events that belong to the protocol layer:
// communication wake events, control signals, and stream errors.
func IsProtocolEvent(evt AgentEvent) bool {
	switch evt.Type {
	case AgentEventActionableMail, AgentEventActionableChat,
		AgentEventControlPause, AgentEventControlResume, AgentEventControlInterrupt,
		AgentEventError:
		return true
	default:
		return false
	}
}

// IsCoordinationEvent returns true for events that belong to the coordination
// layer: work_available, claim_update, claim_removed.
func IsCoordinationEvent(evt AgentEvent) bool {
	switch evt.Type {
	case AgentEventWorkAvailable, AgentEventClaimUpdate, AgentEventClaimRemoved:
		return true
	default:
		return false
	}
}

// ProtocolWakeFilter wakes on protocol events (communication, control, error).
// Connected events are excluded — they are informational only.
func ProtocolWakeFilter(evt AgentEvent, _ bool) bool {
	return IsProtocolEvent(evt)
}

// CoordinationWakeFilter wakes on coordination events only when autofeed
// is enabled.
func CoordinationWakeFilter(evt AgentEvent, autofeed bool) bool {
	return autofeed && IsCoordinationEvent(evt)
}

// DefaultWakeFilter combines protocol and coordination filters.
// This matches the behavior of the previous hardcoded shouldWakeForEvent.
func DefaultWakeFilter(evt AgentEvent, autofeed bool) bool {
	return ProtocolWakeFilter(evt, autofeed) || CoordinationWakeFilter(evt, autofeed)
}
