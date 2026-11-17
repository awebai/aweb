package awid

import "testing"

func TestIsProtocolEvent(t *testing.T) {
	t.Parallel()

	protocol := []AgentEventType{
		AgentEventActionableMail, AgentEventActionableChat,
		AgentEventControlPause, AgentEventControlResume, AgentEventControlInterrupt,
		AgentEventError,
	}
	for _, typ := range protocol {
		if !IsProtocolEvent(AgentEvent{Type: typ}) {
			t.Errorf("IsProtocolEvent(%q) = false, want true", typ)
		}
	}

	nonProtocol := []AgentEventType{
		AgentEventConnected,
		AgentEventWorkAvailable, AgentEventClaimUpdate, AgentEventClaimRemoved,
	}
	for _, typ := range nonProtocol {
		if IsProtocolEvent(AgentEvent{Type: typ}) {
			t.Errorf("IsProtocolEvent(%q) = true, want false", typ)
		}
	}
}

func TestIsCoordinationEvent(t *testing.T) {
	t.Parallel()

	coordination := []AgentEventType{
		AgentEventWorkAvailable, AgentEventClaimUpdate, AgentEventClaimRemoved,
	}
	for _, typ := range coordination {
		if !IsCoordinationEvent(AgentEvent{Type: typ}) {
			t.Errorf("IsCoordinationEvent(%q) = false, want true", typ)
		}
	}

	nonCoordination := []AgentEventType{
		AgentEventConnected,
		AgentEventControlPause, AgentEventControlResume, AgentEventControlInterrupt,
		AgentEventError,
	}
	for _, typ := range nonCoordination {
		if IsCoordinationEvent(AgentEvent{Type: typ}) {
			t.Errorf("IsCoordinationEvent(%q) = true, want false", typ)
		}
	}
}

func TestDefaultWakeFilterMatchesPreviousBehavior(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		typ      AgentEventType
		autofeed bool
		want     bool
	}{
		{"connected never wakes", AgentEventConnected, false, false},
		{"connected never wakes autofeed", AgentEventConnected, true, false},
		{"actionable mail always wakes", AgentEventActionableMail, false, true},
		{"actionable chat always wakes", AgentEventActionableChat, false, true},
		{"pause always wakes", AgentEventControlPause, false, true},
		{"resume always wakes", AgentEventControlResume, false, true},
		{"interrupt always wakes", AgentEventControlInterrupt, false, true},
		{"error always wakes", AgentEventError, false, true},
		{"work_available needs autofeed", AgentEventWorkAvailable, false, false},
		{"work_available with autofeed", AgentEventWorkAvailable, true, true},
		{"claim_update needs autofeed", AgentEventClaimUpdate, false, false},
		{"claim_update with autofeed", AgentEventClaimUpdate, true, true},
		{"claim_removed needs autofeed", AgentEventClaimRemoved, false, false},
		{"claim_removed with autofeed", AgentEventClaimRemoved, true, true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := DefaultWakeFilter(AgentEvent{Type: tc.typ}, tc.autofeed)
			if got != tc.want {
				t.Errorf("DefaultWakeFilter(%q, autofeed=%v) = %v, want %v",
					tc.typ, tc.autofeed, got, tc.want)
			}
		})
	}
}

func TestProtocolWakeFilterIgnoresAutofeed(t *testing.T) {
	t.Parallel()

	evt := AgentEvent{Type: AgentEventActionableMail}
	if !ProtocolWakeFilter(evt, false) {
		t.Error("ProtocolWakeFilter should wake on mail regardless of autofeed")
	}
	if !ProtocolWakeFilter(evt, true) {
		t.Error("ProtocolWakeFilter should wake on mail regardless of autofeed")
	}
}

func TestCoordinationWakeFilterRequiresAutofeed(t *testing.T) {
	t.Parallel()

	evt := AgentEvent{Type: AgentEventWorkAvailable}
	if CoordinationWakeFilter(evt, false) {
		t.Error("CoordinationWakeFilter should not wake without autofeed")
	}
	if !CoordinationWakeFilter(evt, true) {
		t.Error("CoordinationWakeFilter should wake with autofeed")
	}
}
