package run

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/awebai/aw/awid"
)

type recoveryDispatcher struct{ attempts map[string]int }

func (d *recoveryDispatcher) Next(_ context.Context, _ bool, evt *awid.AgentEvent) (DispatchDecision, error) {
	if evt == nil {
		return DispatchDecision{Skip: true}, nil
	}
	d.attempts[evt.MessageID]++
	if evt.MessageID == "first" && d.attempts[evt.MessageID] == 1 {
		return DispatchDecision{}, errors.New("exact read unavailable")
	}
	return DispatchDecision{CycleContext: evt.MessageID}, nil
}
func TestUnresolvedWakeSurvivesAnUnrelatedWake(t *testing.T) {
	loop := NewLoop(fakeProvider{}, io.Discard)
	dispatch := &recoveryDispatcher{attempts: map[string]int{}}
	loop.Dispatch = dispatch
	st := &state{Run: 1, LastWakeEvent: &awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "first"}}
	decision, err := loop.nextPrompt(context.Background(), LoopOptions{}, st)
	if err != nil || !decision.Skip {
		t.Fatalf("first failure=%+v %v", decision, err)
	}
	st.LastWakeEvent = &awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "second"}
	if decision, err = loop.nextPrompt(context.Background(), LoopOptions{}, st); err != nil || decision.CycleContext != "second" {
		t.Fatalf("other wake blocked: %+v %v", decision, err)
	}
	if decision, err = loop.nextPrompt(context.Background(), LoopOptions{}, st); err != nil || decision.CycleContext != "first" {
		t.Fatalf("first sight dedup stranded unresolved message: %+v %v", decision, err)
	}
}
