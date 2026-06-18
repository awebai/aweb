package run

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

// --- Priority Queue tests ---

func TestPriorityQueueOrdersByPriority(t *testing.T) {
	q := NewPriorityQueue()
	q.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable}})
	q.Push(BusEvent{Priority: PriorityInterrupt, Event: awid.AgentEvent{Type: awid.AgentEventControlInterrupt}})
	q.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventActionableMail}})

	evt, ok := q.Pop()
	if !ok || evt.Priority != PriorityInterrupt {
		t.Fatalf("expected interrupt first, got priority=%d ok=%v", evt.Priority, ok)
	}
	evt, ok = q.Pop()
	if !ok || evt.Priority != PriorityCommunication {
		t.Fatalf("expected communication second, got priority=%d", evt.Priority)
	}
	evt, ok = q.Pop()
	if !ok || evt.Priority != PriorityCoordination {
		t.Fatalf("expected coordination third, got priority=%d", evt.Priority)
	}
	_, ok = q.Pop()
	if ok {
		t.Fatal("expected empty queue")
	}
}

func TestPriorityQueueFIFOWithinSamePriority(t *testing.T) {
	q := NewPriorityQueue()
	q.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "first"}})
	q.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventActionableChat, FromAlias: "second"}})

	evt, _ := q.Pop()
	if evt.Event.FromAlias != "first" {
		t.Fatalf("expected FIFO order, got %q first", evt.Event.FromAlias)
	}
	evt, _ = q.Pop()
	if evt.Event.FromAlias != "second" {
		t.Fatalf("expected FIFO order, got %q second", evt.Event.FromAlias)
	}
}

func TestPriorityQueueDrain(t *testing.T) {
	q := NewPriorityQueue()
	q.Push(BusEvent{Priority: PriorityCommunication})
	q.Push(BusEvent{Priority: PriorityCoordination})

	items := q.Drain()
	if len(items) != 2 {
		t.Fatalf("expected 2 items, got %d", len(items))
	}
	if q.Len() != 0 {
		t.Fatal("queue should be empty after drain")
	}
}

func TestPriorityQueueReadySignal(t *testing.T) {
	q := NewPriorityQueue()

	// Ready should fire when pushing to empty queue.
	go func() {
		time.Sleep(10 * time.Millisecond)
		q.Push(BusEvent{Priority: PriorityCommunication})
	}()

	select {
	case <-q.Ready():
		// expected
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for ready signal")
	}
}

func TestPriorityQueueLen(t *testing.T) {
	q := NewPriorityQueue()
	if q.Len() != 0 {
		t.Fatalf("expected 0, got %d", q.Len())
	}
	q.Push(BusEvent{Priority: PriorityCommunication})
	q.Push(BusEvent{Priority: PriorityCoordination})
	if q.Len() != 2 {
		t.Fatalf("expected 2, got %d", q.Len())
	}
}

// --- Event classification tests ---

func TestClassifyInterruptEvents(t *testing.T) {
	for _, typ := range []awid.AgentEventType{awid.AgentEventControlInterrupt, awid.AgentEventControlPause} {
		pri, ok := classifyAgentEvent(awid.AgentEvent{Type: typ})
		if !ok {
			t.Fatalf("%s should be queued", typ)
		}
		if pri != PriorityInterrupt {
			t.Fatalf("%s should be interrupt priority, got %d", typ, pri)
		}
	}
}

func TestClassifyActionableCommunicationEvents(t *testing.T) {
	for _, typ := range []awid.AgentEventType{awid.AgentEventActionableMail, awid.AgentEventActionableChat} {
		pri, ok := classifyAgentEvent(awid.AgentEvent{Type: typ, WakeMode: "prompt"})
		if !ok {
			t.Fatalf("%s should be queued", typ)
		}
		if pri != PriorityCommunication {
			t.Fatalf("%s should be communication priority, got %d", typ, pri)
		}
	}
}

func TestClassifyInterruptWakeEventsAsCommunication(t *testing.T) {
	for _, typ := range []awid.AgentEventType{awid.AgentEventActionableMail, awid.AgentEventActionableChat} {
		pri, ok := classifyAgentEvent(awid.AgentEvent{Type: typ, WakeMode: "interrupt"})
		if !ok {
			t.Fatalf("%s should be queued", typ)
		}
		if pri != PriorityCommunication {
			t.Fatalf("%s interrupt wake should remain communication priority, got %d", typ, pri)
		}
	}
}

func TestClassifyAppEventWakeOnly(t *testing.T) {
	pri, ok := classifyAgentEvent(awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: "evt-1", DeliveryIntent: "wake"})
	if !ok {
		t.Fatal("app_event with event_id and delivery_intent=wake should be queued")
	}
	if pri != PriorityCommunication {
		t.Fatalf("app_event wake should be communication priority, got %d", pri)
	}
	if _, ok := classifyAgentEvent(awid.AgentEvent{Type: awid.AgentEventAppEvent, DeliveryIntent: "wake"}); ok {
		t.Fatal("app_event without event_id should not wake aw run")
	}
	if _, ok := classifyAgentEvent(awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: " \t", DeliveryIntent: "wake"}); ok {
		t.Fatal("app_event with blank event_id should not wake aw run")
	}
	for _, intent := range []string{"ambient", "steer", ""} {
		if _, ok := classifyAgentEvent(awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: "evt-1", DeliveryIntent: intent}); ok {
			t.Fatalf("app_event with delivery_intent=%q should not wake aw run", intent)
		}
	}
}

func TestClassifyCoordinationEvents(t *testing.T) {
	for _, typ := range []awid.AgentEventType{awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved} {
		pri, ok := classifyAgentEvent(awid.AgentEvent{Type: typ})
		if !ok {
			t.Fatalf("%s should be queued", typ)
		}
		if pri != PriorityCoordination {
			t.Fatalf("%s should be coordination priority, got %d", typ, pri)
		}
	}
}

func TestClassifyResumeAsInterrupt(t *testing.T) {
	pri, ok := classifyAgentEvent(awid.AgentEvent{Type: awid.AgentEventControlResume})
	if !ok {
		t.Fatal("control_resume should be queued")
	}
	if pri != PriorityInterrupt {
		t.Fatalf("control_resume should be interrupt priority, got %d", pri)
	}
}

func TestClassifyInformationalEventsNotQueued(t *testing.T) {
	for _, typ := range []awid.AgentEventType{awid.AgentEventConnected, awid.AgentEventError} {
		_, ok := classifyAgentEvent(awid.AgentEvent{Type: typ})
		if ok {
			t.Fatalf("%s should not be queued", typ)
		}
	}
}

// --- Connection state tests ---

func TestConnectionStateStrings(t *testing.T) {
	tests := []struct {
		state ConnectionState
		want  string
	}{
		{ConnDisconnected, "disconnected"},
		{ConnReconnecting, "reconnecting"},
		{ConnStreaming, "streaming"},
	}
	for _, tt := range tests {
		if got := tt.state.String(); got != tt.want {
			t.Errorf("ConnectionState(%d).String() = %q, want %q", tt.state, got, tt.want)
		}
	}
}

// --- EventBus tests ---

// fakeEventSource delivers pre-loaded events, then returns io.EOF.
type fakeEventSource struct {
	mu     sync.Mutex
	events []awid.AgentEvent
	index  int
	closed bool
}

func newFakeEventSource(events ...awid.AgentEvent) *fakeEventSource {
	return &fakeEventSource{events: events}
}

func (f *fakeEventSource) Next(_ context.Context) (*awid.AgentEvent, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.closed {
		return nil, errors.New("closed")
	}
	if f.index >= len(f.events) {
		return nil, io.EOF
	}
	ev := f.events[f.index]
	f.index++
	return &ev, nil
}

func (f *fakeEventSource) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return nil
}

func TestEventBusDeliversInterruptsToChannel(t *testing.T) {
	source := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventControlInterrupt},
	)
	called := false
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				// Block until context cancelled to prevent busy-loop.
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case evt := <-bus.Interrupts():
		if evt.Event.Type != awid.AgentEventControlInterrupt {
			t.Fatalf("expected control_interrupt, got %s", evt.Event.Type)
		}
		if evt.Priority != PriorityInterrupt {
			t.Fatalf("expected interrupt priority, got %d", evt.Priority)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for interrupt")
	}

	cancel()
	bus.Stop()
}

func TestEventBusQueuesInterruptWakeCommunicationEvents(t *testing.T) {
	source := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventActionableChat, WakeMode: "interrupt", FromAlias: "mia"},
	)
	called := false
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case evt := <-bus.Interrupts():
		t.Fatalf("did not expect communication wake on interrupts channel: %+v", evt)
	case <-time.After(150 * time.Millisecond):
	}

	select {
	case <-bus.Queue().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for queued communication wake")
	}
	evt, ok := bus.Queue().Pop()
	if !ok {
		t.Fatal("expected queued communication wake")
	}
	if evt.Event.Type != awid.AgentEventActionableChat {
		t.Fatalf("expected actionable_chat, got %s", evt.Event.Type)
	}
	if evt.Priority != PriorityCommunication {
		t.Fatalf("expected communication priority, got %d", evt.Priority)
	}

	cancel()
	bus.Stop()
}

func TestEventBusQueuesCommunicationEvents(t *testing.T) {
	source := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "alice"},
		awid.AgentEvent{Type: awid.AgentEventActionableChat, FromAlias: "bob"},
	)
	called := false
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	// Wait for events to be queued.
	select {
	case <-bus.Queue().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for queue ready")
	}

	// Give a moment for the second event to be processed.
	time.Sleep(50 * time.Millisecond)

	if bus.Queue().Len() < 1 {
		t.Fatal("expected at least 1 event in queue")
	}

	evt, ok := bus.Queue().Pop()
	if !ok {
		t.Fatal("expected event")
	}
	if evt.Event.FromAlias != "alice" {
		t.Fatalf("expected alice first, got %s", evt.Event.FromAlias)
	}

	cancel()
	bus.Stop()
}

func TestEventBusSkipsInformationalEvents(t *testing.T) {
	source := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventConnected},
		awid.AgentEvent{Type: awid.AgentEventControlResume},
		awid.AgentEvent{Type: awid.AgentEventError, Text: "some error"},
		awid.AgentEvent{Type: awid.AgentEventActionableMail, FromAlias: "marker"},
	)
	called := false
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out")
	}
	time.Sleep(50 * time.Millisecond)

	// Only the mail message should be queued.
	if bus.Queue().Len() != 1 {
		t.Fatalf("expected 1 queued event (mail only), got %d", bus.Queue().Len())
	}
	evt, _ := bus.Queue().Pop()
	if evt.Event.FromAlias != "marker" {
		t.Fatalf("expected marker mail, got %s", evt.Event.FromAlias)
	}

	cancel()
	bus.Stop()
}

func TestEventBusConnectionStateTransitions(t *testing.T) {
	var states []ConnectionState
	var mu sync.Mutex

	source := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventConnected},
	)
	called := false
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
		OnStateChange: func(s ConnectionState) {
			mu.Lock()
			states = append(states, s)
			mu.Unlock()
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	bus.Start(ctx)

	// Wait for the stream to process and close.
	time.Sleep(100 * time.Millisecond)
	cancel()
	bus.Stop()

	mu.Lock()
	defer mu.Unlock()

	// Expect: reconnecting → streaming → reconnecting (on stream close) → ... → disconnected
	if len(states) < 2 {
		t.Fatalf("expected at least 2 state transitions, got %d: %v", len(states), states)
	}
	if states[0] != ConnReconnecting {
		t.Fatalf("first state should be reconnecting, got %s", states[0])
	}
	if states[1] != ConnStreaming {
		t.Fatalf("second state should be streaming, got %s", states[1])
	}
	// Last state after cancel should be disconnected.
	if states[len(states)-1] != ConnDisconnected {
		t.Fatalf("last state should be disconnected, got %s", states[len(states)-1])
	}
}

func TestEventBusDisconnectsOnClientError(t *testing.T) {
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			return nil, &awid.APIError{StatusCode: 404, Body: "not found"}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	// Wait for goroutine to exit.
	select {
	case <-bus.done:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for bus to stop on 404")
	}

	if bus.State() != ConnDisconnected {
		t.Fatalf("expected disconnected after 404, got %s", bus.State())
	}
}

func TestEventBusInjectAutofeed(t *testing.T) {
	q := NewPriorityQueue()
	bus := &EventBus{queue: q, done: make(chan struct{})}

	bus.InjectAutofeed()
	if q.Len() != 1 {
		t.Fatalf("expected 1, got %d", q.Len())
	}
	evt, _ := q.Pop()
	if evt.Priority != PriorityAutofeed {
		t.Fatalf("expected autofeed priority, got %d", evt.Priority)
	}
}

func TestEventBusQueuesAppEventWakeAndDedupesByEventID(t *testing.T) {
	first := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: "evt-1", AppID: "folio", AppEventType: "folio/doc.changed", ResourceRef: "pitch", DeliveryIntent: "wake"},
	)
	second := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: "evt-1", AppID: "folio", AppEventType: "folio/doc.changed", ResourceRef: "pitch", DeliveryIntent: "wake"},
	)

	streamCalls := 0
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			streamCalls++
			switch streamCalls {
			case 1:
				return first, nil
			case 2:
				return second, nil
			default:
				<-ctx.Done()
				return nil, ctx.Err()
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for app_event wake")
	}
	time.Sleep(150 * time.Millisecond)

	if got := bus.Queue().Len(); got != 1 {
		t.Fatalf("expected exactly 1 app_event after replay, got %d", got)
	}
	evt, ok := bus.Queue().Pop()
	if !ok {
		t.Fatal("expected queued app_event")
	}
	if evt.Event.Type != awid.AgentEventAppEvent || evt.Event.EventID != "evt-1" || evt.Event.DeliveryIntent != "wake" {
		t.Fatalf("unexpected app_event wake: %#v", evt.Event)
	}

	cancel()
	bus.Stop()
}

func TestEventBusSkipsAppEventWakeWithoutEventID(t *testing.T) {
	source := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventAppEvent, AppID: "folio", AppEventType: "folio/doc.changed", DeliveryIntent: "wake"},
		awid.AgentEvent{Type: awid.AgentEventAppEvent, EventID: " \t", AppID: "folio", AppEventType: "folio/doc.changed", DeliveryIntent: "wake"},
		awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m-1", FromAlias: "marker"},
	)
	called := false
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for marker mail")
	}
	time.Sleep(50 * time.Millisecond)

	if got := bus.Queue().Len(); got != 1 {
		t.Fatalf("expected only marker mail queued, got %d", got)
	}
	evt, ok := bus.Queue().Pop()
	if !ok {
		t.Fatal("expected queued marker mail")
	}
	if evt.Event.Type != awid.AgentEventActionableMail || evt.Event.FromAlias != "marker" {
		t.Fatalf("unexpected queued event: %#v", evt.Event)
	}

	cancel()
	bus.Stop()
}

func TestEventBusDedupesReplayByMessageIDAcrossReconnects(t *testing.T) {
	first := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventActionableChat, MessageID: "m-1", FromAlias: "henry", WakeMode: "prompt"},
	)
	second := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventActionableChat, MessageID: "m-1", FromAlias: "henry", WakeMode: "prompt"},
	)

	streamCalls := 0
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			streamCalls++
			switch streamCalls {
			case 1:
				return first, nil
			case 2:
				return second, nil
			default:
				<-ctx.Done()
				return nil, ctx.Err()
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for queue ready")
	}

	time.Sleep(150 * time.Millisecond)

	if got := bus.Queue().Len(); got != 1 {
		t.Fatalf("expected exactly 1 queued event after replay, got %d", got)
	}

	cancel()
	bus.Stop()
}

type blockingEventSource struct{}

func (blockingEventSource) Next(ctx context.Context) (*awid.AgentEvent, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func (blockingEventSource) Close() error { return nil }

func TestEventBusReconnectsWhenStreamDeadlineExpiresLocally(t *testing.T) {
	second := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m-2", FromAlias: "alice"},
	)

	var calls atomic.Int32
	bus := NewEventBus(EventBusConfig{
		StreamTTL: 50 * time.Millisecond,
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			switch calls.Add(1) {
			case 1:
				return blockingEventSource{}, nil
			case 2:
				return second, nil
			default:
				<-ctx.Done()
				return nil, ctx.Err()
			}
		},
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case <-bus.Queue().Ready():
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for post-deadline reconnect event")
	}

	evt, ok := bus.Queue().Pop()
	if !ok {
		t.Fatal("expected queued event after reconnect")
	}
	if evt.Event.Type != awid.AgentEventActionableMail || evt.Event.FromAlias != "alice" {
		t.Fatalf("unexpected event after reconnect: %#v", evt.Event)
	}
	if calls.Load() < 2 {
		t.Fatalf("expected at least 2 stream attempts, got %d", calls.Load())
	}

	cancel()
	bus.Stop()
}

func TestRecentEventDeduperKeepsOnlyBoundedRecentKeys(t *testing.T) {
	d := newRecentEventDeduper(2)

	if d.Seen(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m1"}) {
		t.Fatal("first event should not be seen")
	}
	if d.Seen(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m2"}) {
		t.Fatal("second event should not be seen")
	}
	if !d.Seen(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m1"}) {
		t.Fatal("replayed event should be seen")
	}
	if d.Seen(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m3"}) {
		t.Fatal("third distinct event should not be seen")
	}
	if d.Seen(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m1"}) {
		t.Fatal("oldest key should have been evicted")
	}
}

func TestEventBusStopWithoutStartDoesNotDeadlock(t *testing.T) {
	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			return nil, errors.New("should not be called")
		},
	})
	// Stop without Start should return immediately.
	done := make(chan struct{})
	go func() {
		bus.Stop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Stop() deadlocked without Start()")
	}
}

func TestPriorityQueueAutofeedIsLowestPriority(t *testing.T) {
	q := NewPriorityQueue()
	q.Push(BusEvent{Priority: PriorityAutofeed, Event: awid.AgentEvent{Type: "autofeed"}})
	q.Push(BusEvent{Priority: PriorityCoordination, Event: awid.AgentEvent{Type: awid.AgentEventWorkAvailable}})
	q.Push(BusEvent{Priority: PriorityCommunication, Event: awid.AgentEvent{Type: awid.AgentEventActionableMail}})

	evt, _ := q.Pop()
	if evt.Priority != PriorityCommunication {
		t.Fatalf("expected communication first, got %d", evt.Priority)
	}
	evt, _ = q.Pop()
	if evt.Priority != PriorityCoordination {
		t.Fatalf("expected coordination second, got %d", evt.Priority)
	}
	evt, _ = q.Pop()
	if evt.Priority != PriorityAutofeed {
		t.Fatalf("expected autofeed last, got %d", evt.Priority)
	}
}

func TestEventBusCallsOnErrorForErrorEvents(t *testing.T) {
	source := newFakeEventSource(
		awid.AgentEvent{Type: awid.AgentEventError, Text: "server restarting"},
	)
	called := false
	errCh := make(chan string, 1)

	bus := NewEventBus(EventBusConfig{
		Stream: func(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
			if called {
				<-ctx.Done()
				return nil, ctx.Err()
			}
			called = true
			return source, nil
		},
	})
	bus.onError = func(ev awid.AgentEvent) {
		errCh <- ev.Text
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	bus.Start(ctx)

	select {
	case text := <-errCh:
		if text != "server restarting" {
			t.Fatalf("error text=%q, want 'server restarting'", text)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for OnError callback")
	}

	cancel()
	bus.Stop()
}
