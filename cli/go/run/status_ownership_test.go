package run

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// The status line has a single owner: the main loop. Background goroutines only
// signal that a repaint is wanted. These tests pin the two properties that
// ownership depends on, because both fail silently — a stale status line and a
// data race are equally invisible to a passing suite (default-aaks).

// A repaint request raised WHILE a render is in progress must survive to the
// next select iteration. If it is dropped, the final state never repaints and
// the status line is permanently stale — with no error and no failing test.
func TestStatusDirtySignalRaisedDuringRenderIsNotLost(t *testing.T) {
	t.Parallel()

	l := &Loop{statusDirty: make(chan struct{}, 1)}

	l.markStatusDirty()
	// The consumer takes the signal and begins rendering.
	select {
	case <-l.statusDirtyC():
	default:
		t.Fatal("markStatusDirty did not deliver a signal")
	}

	// The bus observes a new state mid-render and signals again.
	l.markStatusDirty()

	// That signal must still be pending, so the loop repaints once more.
	select {
	case <-l.statusDirtyC():
	default:
		t.Fatal("signal raised during a render was dropped: the final state would never repaint")
	}
}

// markStatusDirty is called from the EventBus goroutine and must never block,
// even with no consumer ready and a signal already pending.
func TestMarkStatusDirtyNeverBlocks(t *testing.T) {
	t.Parallel()

	l := &Loop{statusDirty: make(chan struct{}, 1)}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for range 100 {
			l.markStatusDirty()
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("markStatusDirty blocked; the event path must never stall on the renderer")
	}
}

// The regression guard for the race itself, and the one that must FAIL under
// -race if the ownership fix is reverted. A flapping EventBus drives connection
// state changes from its own goroutine for the whole run while the main loop
// repaints the status line. Before the fix the bus callback wrote
// state.ConnState and called refreshStatusLine directly — which also WRITES
// st.RunPhase — so these two goroutines wrote the same loop state concurrently
// and the detector fired. Now the bus only signals and the main loop renders.
func TestFlappingEventBusDoesNotRaceStatusLineRendering(t *testing.T) {
	t.Parallel()

	// Every stream attempt fails, so the bus loops setState(ConnReconnecting) ->
	// stream error -> retry, emitting onStateChange transitions continuously.
	bus := NewEventBus(EventBusConfig{
		Stream: func(context.Context, time.Time) (awid.EventSource, error) {
			return nil, &awid.APIError{StatusCode: 500, Body: "flapping"}
		},
	})

	var out bytes.Buffer
	loop := NewLoop(ClaudeProvider{}, &out)
	loop.EventBus = bus
	loop.Sleep = func(context.Context, time.Duration) error { return nil }
	loop.Runner = func(_ context.Context, _ string, _ []string, onLine func(string), _ any) error {
		onLine(`{"type":"result","duration_ms":1,"session_id":"sess-1"}`)
		return nil
	}
	loop.Control = newFakeInputController()
	loop.Dispatch = &fakeDispatcher{
		decisions: []DispatchDecision{
			{Mission: "mission", WaitSeconds: 1},
			{Mission: "mission", WaitSeconds: 1},
			{Mission: "mission", WaitSeconds: 1},
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := loop.Run(ctx, LoopOptions{WaitSeconds: 1, MaxRuns: 3}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
}
