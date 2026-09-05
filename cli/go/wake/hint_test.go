package wake

import (
	"testing"

	awid "github.com/awebai/aw/awid"
)

// TestHintFromEventAcceptsBothSpellings: the wire names are actionable_mail and
// actionable_chat; channel-core normalises them to mail_message and
// chat_message. The broker must accept both (§2).
func TestHintFromEventAcceptsBothSpellings(t *testing.T) {
	for _, name := range []string{"actionable_mail", "mail_message"} {
		h, ok := HintFromEvent(awid.AgentEvent{Type: awid.AgentEventType(name), MessageID: "m1"}, at(0))
		if !ok || h.Kind != KindMail || h.Intent != IntentWake {
			t.Errorf("%s -> %#v ok=%t", name, h, ok)
		}
	}
	for _, name := range []string{"actionable_chat", "chat_message"} {
		h, ok := HintFromEvent(awid.AgentEvent{Type: awid.AgentEventType(name), MessageID: "c1"}, at(0))
		if !ok || h.Kind != KindChat || h.Intent != IntentWake {
			t.Errorf("%s -> %#v ok=%t", name, h, ok)
		}
	}
}

func TestHintIntentsMatchTheDeliveryTable(t *testing.T) {
	cases := []struct {
		event  awid.AgentEvent
		kind   Kind
		intent Intent
		ok     bool
	}{
		{awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m"}, KindMail, IntentWake, true},
		{awid.AgentEvent{Type: awid.AgentEventActionableChat, MessageID: "c"}, KindChat, IntentWake, true},
		{awid.AgentEvent{Type: awid.AgentEventActionableChat, MessageID: "c", SenderWaiting: true}, KindChat, IntentSteer, true},
		{awid.AgentEvent{Type: awid.AgentEventControlInterrupt, SignalID: "s"}, KindControl, IntentSteer, true},
		{awid.AgentEvent{Type: awid.AgentEventWorkAvailable, TaskID: "t"}, KindWork, IntentAmbient, true},
		{awid.AgentEvent{Type: awid.AgentEventClaimUpdate, TaskID: "t"}, KindClaim, IntentAmbient, true},
		{awid.AgentEvent{Type: awid.AgentEventClaimRemoved, TaskID: "t"}, KindClaimRemoved, IntentAmbient, true},
		{awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: "e"}, KindApp, IntentAmbient, true},
		{awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: "e", DeliveryIntent: "wake"}, KindApp, IntentWake, true},
		{awid.AgentEvent{Type: awid.AgentEventChannelReconnected}, KindReconnect, IntentWake, true},

		// Informational, and the two control signals that change durable
		// broker state rather than announcing a waiting item.
		{awid.AgentEvent{Type: awid.AgentEventConnected}, "", "", false},
		{awid.AgentEvent{Type: awid.AgentEventError}, "", "", false},
		{awid.AgentEvent{Type: awid.AgentEventControlPause}, "", "", false},
		{awid.AgentEvent{Type: awid.AgentEventControlResume}, "", "", false},
	}
	for _, tc := range cases {
		h, ok := HintFromEvent(tc.event, at(0))
		if ok != tc.ok {
			t.Errorf("%s: ok=%t want %t", tc.event.Type, ok, tc.ok)
			continue
		}
		if !ok {
			continue
		}
		if h.Kind != tc.kind || h.Intent != tc.intent {
			t.Errorf("%s: kind=%s intent=%s want %s/%s", tc.event.Type, h.Kind, h.Intent, tc.kind, tc.intent)
		}
	}
}

// TestControlInterruptIsTransient: a control signal is at-most-once. Persisting
// it would turn a signal lost across an SSE gap into a durable replay it never
// promised (§4).
func TestControlInterruptIsTransient(t *testing.T) {
	h, _ := HintFromEvent(awid.AgentEvent{Type: awid.AgentEventControlInterrupt, SignalID: "s1"}, at(0))
	if !h.Transient {
		t.Fatal("a control signal was marked durable")
	}
	mail, _ := HintFromEvent(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m1"}, at(0))
	if mail.Transient {
		t.Fatal("mail was marked transient")
	}

	state := InstanceState{Home: "/h"}
	state.AddHint(h, DefaultHintCap)
	state.AddHint(mail, DefaultHintCap)
	if len(state.Pending) != 2 {
		t.Fatalf("pending=%d", len(state.Pending))
	}
	durable := state.DurablePending()
	if len(durable) != 1 || durable[0].Kind != KindMail {
		t.Fatalf("durable pending=%#v", durable)
	}
}

// TestPendingSetDedupe: within the pending set, a hint is not queued twice.
// Across time it is not suppressed — that would be a presented mark, and the
// note forbids one (§4).
func TestPendingSetDedupe(t *testing.T) {
	state := InstanceState{Home: "/h"}
	mail := Hint{Kind: KindMail, Intent: IntentWake, MessageID: "m1", ConversationID: "conv-1", From: "alice", At: at(0)}

	if !state.AddHint(mail, DefaultHintCap) {
		t.Fatal("first add was collapsed")
	}
	later := mail
	later.At = at(5)
	if state.AddHint(later, DefaultHintCap) {
		t.Fatal("the same message id queued twice while pending")
	}
	if len(state.Pending) != 1 {
		t.Fatalf("pending=%d", len(state.Pending))
	}
	if !state.Pending[0].At.Equal(at(0)) {
		t.Fatal("collapsing reset the coalescing clock; a burst would then never close its window")
	}

	// A different message id in the same conversation is a different item.
	other := mail
	other.MessageID = "m2"
	if !state.AddHint(other, DefaultHintCap) {
		t.Fatal("a second message in one conversation was collapsed away")
	}
	if len(state.Pending) != 2 {
		t.Fatalf("pending=%d", len(state.Pending))
	}

	// After the pending set is emptied — which a submission attempt does —
	// the same id is accepted again. This is what makes reminders possible.
	state.Pending = nil
	if !state.AddHint(mail, DefaultHintCap) {
		t.Fatal("a still-unread item was suppressed across time; that is a presented mark")
	}
}

// TestSenderWaitingEscalatesACollapsedChatHint: the item is the same, but a
// waiting sender is a stronger signal than the one already pending.
func TestSenderWaitingEscalatesACollapsedChatHint(t *testing.T) {
	state := InstanceState{Home: "/h"}
	state.AddHint(Hint{Kind: KindChat, Intent: IntentWake, MessageID: "c1", At: at(0)}, DefaultHintCap)
	state.AddHint(Hint{Kind: KindChat, Intent: IntentSteer, MessageID: "c1", SenderWaiting: true, At: at(1)}, DefaultHintCap)
	if len(state.Pending) != 1 {
		t.Fatalf("pending=%d", len(state.Pending))
	}
	if !state.Pending[0].SenderWaiting || state.Pending[0].Intent != IntentSteer {
		t.Fatalf("escalation lost: %#v", state.Pending[0])
	}
}

func TestHintCapEvictsOldestAndCountsIt(t *testing.T) {
	state := InstanceState{Home: "/h"}
	for i := 0; i < 10; i++ {
		state.AddHint(Hint{Kind: KindMail, MessageID: string(rune('a' + i)), At: at(i)}, 4)
	}
	if len(state.Pending) != 4 {
		t.Fatalf("pending=%d want 4", len(state.Pending))
	}
	if state.Evicted != 6 {
		t.Fatalf("evicted=%d want 6; eviction must be reported, not silent", state.Evicted)
	}
	if state.Pending[0].MessageID != "g" {
		t.Fatalf("eviction is not oldest-first: %q", state.Pending[0].MessageID)
	}
}

func TestDedupeKeyFallsBackWhenNoIDIsCarried(t *testing.T) {
	a := Hint{Kind: KindReconnect, At: at(0)}
	b := Hint{Kind: KindReconnect, At: at(1)}
	if a.DedupeKey() == b.DedupeKey() {
		t.Fatal("two id-less hints collapsed onto one key by accident")
	}
	c := Hint{Kind: KindWork, TaskID: "t1", At: at(0)}
	d := Hint{Kind: KindWork, TaskID: "t1", At: at(9)}
	if c.DedupeKey() != d.DedupeKey() {
		t.Fatal("a task id did not identify the item")
	}
}
