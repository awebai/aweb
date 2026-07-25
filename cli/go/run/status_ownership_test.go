package run

import (
	"bytes"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// The status line has a single owner: the main loop. Background goroutines only
// signal that a repaint is wanted. These tests pin the properties that ownership
// depends on, because each fails silently — a stale status line and a data race
// are equally invisible to a passing suite (default-aaks).

// runLoopWithBus drives the real production wiring and returns the Loop so tests
// can inspect what Run actually built. This matters: a test that supplies its own
// statusDirty channel proves nothing about production, because the invariant IS
// the capacity chosen at the allocation site. Obtaining the channel from a real
// run is what makes an edit there turn these tests red.
func runLoopWithBus(t *testing.T) *Loop {
	t.Helper()

	// Every stream attempt fails, so the bus loops setState(ConnReconnecting) ->
	// stream error -> retry, emitting onStateChange transitions throughout.
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
	t.Cleanup(cancel)
	if err := loop.Run(ctx, LoopOptions{WaitSeconds: 1, MaxRuns: 3}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if loop.statusDirty == nil {
		t.Fatal("Run did not allocate the repaint channel; the wiring under test never executed")
	}
	return loop
}

// The repaint channel must be buffered. With no buffer, markStatusDirty's
// non-blocking send is dropped whenever the loop is not already parked in its
// select — which is most of the time — so repaint requests vanish. Asserting the
// capacity of the channel PRODUCTION allocated is what makes changing that
// allocation a test failure rather than a silent behaviour change.
func TestRunAllocatesBufferedRepaintChannel(t *testing.T) {
	t.Parallel()

	l := runLoopWithBus(t)

	if got := cap(l.statusDirty); got != 1 {
		t.Fatalf("production allocated a repaint channel with capacity %d, want 1: "+
			"an unbuffered channel drops mid-render repaint requests", got)
	}
}

// A repaint request raised WHILE a render is in progress must survive to the next
// select iteration. If it is dropped, the final state never repaints and the
// status line is permanently stale — with no error and no failing test. Exercised
// on the channel production built, not a fixture, so an unbuffered allocation
// fails here too.
func TestStatusDirtySignalRaisedDuringRenderIsNotLost(t *testing.T) {
	t.Parallel()

	l := runLoopWithBus(t)
	// Start from a known-empty channel: the run above may have left a signal
	// pending, and this test is about what happens to the NEXT one.
	drainStatusDirty(l)

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

	l := runLoopWithBus(t)
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

func drainStatusDirty(l *Loop) {
	for {
		select {
		case <-l.statusDirty:
		default:
			return
		}
	}
}

// The regression guard for the race itself, and the one that must FAIL under
// -race if the ownership fix is reverted. A flapping EventBus drives connection
// state changes from its own goroutine for the whole run while the main loop
// repaints the status line. Before the fix the bus callback wrote
// state.ConnState and called refreshStatusLine directly — which also WRITES
// st.RunPhase — so these two goroutines wrote the same loop state concurrently
// and the detector fired. Now the bus only signals and the main loop renders.
func TestProviderOutputAndControlRenderingHaveSingleOwner(t *testing.T) {
	const iterations = 2000

	cost := 0.01
	ui := newRecordingUI()
	started := make(chan struct{})
	controlsQueued := make(chan struct{})
	loop := NewLoop(&fakeProvider{event: &Event{Type: EventDone, CostUSD: &cost}}, io.Discard)
	loop.Control = ui
	emitted := 0
	loop.Runner = func(_ context.Context, _ string, _ []string, onLine func(string), _ any) error {
		close(started)
		for range iterations {
			onLine("cost")
			emitted++
		}
		<-controlsQueued
		return nil
	}

	go func() {
		<-started
		defer close(controlsQueued)
		for i := range iterations {
			eventType := ControlAutofeedOff
			if i%2 == 0 {
				eventType = ControlAutofeedOn
			}
			ui.events <- ControlEvent{Type: eventType}
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := loop.Run(ctx, LoopOptions{InitialPrompt: "exercise concurrent ownership", MaxRuns: 1}); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if emitted != iterations {
		t.Fatalf("provider output path emitted %d lines, want %d", emitted, iterations)
	}
	ui.statusMu.Lock()
	defer ui.statusMu.Unlock()
	controlRenders := 0
	finalCostRendered := false
	for _, status := range ui.statuses {
		if status == "autofeed on" || status == "autofeed off" {
			controlRenders++
		}
		if strings.Contains(status, "$20.00") {
			finalCostRendered = true
		}
	}
	if controlRenders != iterations {
		t.Fatalf("main-loop control path rendered %d updates, want %d", controlRenders, iterations)
	}
	if !finalCostRendered {
		t.Fatal("provider output path did not render the final cumulative cost")
	}
}

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
