package run

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	awid "github.com/awebai/aw/awid"
)

// ConnectionState tracks the SSE connection lifecycle.
type ConnectionState int32

const (
	ConnDisconnected ConnectionState = iota
	ConnReconnecting
	ConnStreaming
)

func (s ConnectionState) String() string {
	switch s {
	case ConnStreaming:
		return "streaming"
	case ConnReconnecting:
		return "reconnecting"
	case ConnDisconnected:
		return "disconnected"
	default:
		return "unknown"
	}
}

// EventPriority determines processing order. Lower number = higher priority.
type EventPriority int

const (
	PriorityInterrupt EventPriority = iota
	PriorityCommunication
	PriorityCoordination
	PriorityAutofeed
)

// BusEvent wraps an agent event with its classified priority.
type BusEvent struct {
	Event    awid.AgentEvent
	Priority EventPriority
}

// classifyAgentEvent assigns a priority to an agent event.
// Returns the priority and whether the event should be queued at all.
// Informational events (connected, error) return false.
func classifyAgentEvent(evt awid.AgentEvent) (EventPriority, bool) {
	switch evt.Type {
	case awid.AgentEventControlInterrupt, awid.AgentEventControlPause, awid.AgentEventControlResume:
		return PriorityInterrupt, true
	case awid.AgentEventActionableMail, awid.AgentEventActionableChat:
		return PriorityCommunication, true
	case awid.AgentEventWorkAvailable, awid.AgentEventClaimUpdate, awid.AgentEventClaimRemoved:
		return PriorityCoordination, true
	case awid.AgentEventAppEvent:
		if evt.DeliveryIntent == "wake" && strings.TrimSpace(evt.EventID) != "" {
			return PriorityCommunication, true
		}
		return 0, false
	default:
		// connected, error — informational, not queued
		return 0, false
	}
}

// PriorityQueue holds BusEvents sorted by priority, FIFO within same priority.
type PriorityQueue struct {
	mu     sync.Mutex
	items  []BusEvent
	notify chan struct{}
}

func NewPriorityQueue() *PriorityQueue {
	return &PriorityQueue{
		notify: make(chan struct{}, 1),
	}
}

// Push adds an event in priority order (stable within same priority).
func (q *PriorityQueue) Push(evt BusEvent) {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Find insertion point: after all items with same or higher priority.
	pos := len(q.items)
	for i, item := range q.items {
		if item.Priority > evt.Priority {
			pos = i
			break
		}
	}
	q.items = append(q.items, BusEvent{})
	copy(q.items[pos+1:], q.items[pos:])
	q.items[pos] = evt

	// Signal waiters if this is the first item.
	select {
	case q.notify <- struct{}{}:
	default:
	}
}

// Pop removes and returns the highest-priority (lowest number) event.
func (q *PriorityQueue) Pop() (BusEvent, bool) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return BusEvent{}, false
	}
	evt := q.items[0]
	q.items = q.items[1:]
	return evt, true
}

// Drain removes and returns all queued events.
func (q *PriorityQueue) Drain() []BusEvent {
	q.mu.Lock()
	defer q.mu.Unlock()
	if len(q.items) == 0 {
		return nil
	}
	result := q.items
	q.items = nil
	return result
}

// Len returns the number of queued events.
func (q *PriorityQueue) Len() int {
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.items)
}

// Ready returns a channel that receives when items are added to an empty queue.
func (q *PriorityQueue) Ready() <-chan struct{} {
	return q.notify
}

// EventBus maintains a persistent SSE connection and delivers events
// through an interrupt channel (for high-priority) and a priority queue
// (for deferred events).
type EventBus struct {
	stream EventStreamOpener
	now    func() time.Time

	interrupts chan BusEvent
	queue      *PriorityQueue
	deduper    *recentEventDeduper
	streamTTL  time.Duration

	connState     atomic.Int32
	onStateChange func(ConnectionState)
	onError       func(awid.AgentEvent)

	cancel context.CancelFunc
	done   chan struct{}
}

// EventBusConfig holds construction parameters for an EventBus.
type EventBusConfig struct {
	Stream        EventStreamOpener
	Now           func() time.Time
	OnStateChange func(ConnectionState)
	StreamTTL     time.Duration
}

func NewEventBus(cfg EventBusConfig) *EventBus {
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	b := &EventBus{
		stream:        cfg.Stream,
		now:           nowFn,
		interrupts:    make(chan BusEvent, 8),
		queue:         NewPriorityQueue(),
		deduper:       newRecentEventDeduper(256),
		streamTTL:     cfg.StreamTTL,
		onStateChange: cfg.OnStateChange,
		done:          make(chan struct{}),
	}
	if b.streamTTL <= 0 {
		b.streamTTL = streamDeadline
	}
	b.connState.Store(int32(ConnDisconnected))
	return b
}

// Start opens the persistent SSE connection in a background goroutine.
func (b *EventBus) Start(ctx context.Context) {
	ctx, b.cancel = context.WithCancel(ctx)
	go b.run(ctx)
}

// Stop closes the SSE connection and waits for the goroutine to exit.
// Safe to call even if Start was never called.
func (b *EventBus) Stop() {
	if b.cancel == nil {
		return
	}
	b.cancel()
	<-b.done
}

// Interrupts returns the channel for interrupt-priority events.
func (b *EventBus) Interrupts() <-chan BusEvent {
	return b.interrupts
}

// Queue returns the priority queue for deferred events.
func (b *EventBus) Queue() *PriorityQueue {
	return b.queue
}

// State returns the current connection state.
func (b *EventBus) State() ConnectionState {
	return ConnectionState(b.connState.Load())
}

func (b *EventBus) setState(s ConnectionState) {
	old := ConnectionState(b.connState.Swap(int32(s)))
	if old != s && b.onStateChange != nil {
		b.onStateChange(s)
	}
}

// InjectAutofeed adds a synthetic lowest-priority event to the queue.
func (b *EventBus) InjectAutofeed() {
	b.queue.Push(BusEvent{
		Priority: PriorityAutofeed,
		Event:    awid.AgentEvent{Type: "autofeed"},
	})
}

const streamDeadline = 10 * time.Minute

func (b *EventBus) run(ctx context.Context) {
	defer close(b.done)
	defer b.setState(ConnDisconnected)

	delay := 250 * time.Millisecond
	maxDelay := 2 * time.Second

	for ctx.Err() == nil {
		b.setState(ConnReconnecting)

		deadline := b.now().Add(b.streamTTL)
		streamCtx, cancel := context.WithDeadline(ctx, deadline)
		source, err := b.stream(streamCtx, deadline)
		if err != nil {
			cancel()
			if code, ok := awid.HTTPStatusCode(err); ok && code >= 400 && code < 500 {
				b.setState(ConnDisconnected)
				return
			}
			if !sleepForRetry(ctx, b.now, deadline, delay) {
				return
			}
			delay = nextRetryDelay(delay, maxDelay)
			continue
		}

		// Connection successful — reset backoff.
		delay = 250 * time.Millisecond
		b.setState(ConnStreaming)

		b.consumeStream(streamCtx, source)
		_ = source.Close()
		cancel()
	}
}

func (b *EventBus) consumeStream(ctx context.Context, source awid.EventSource) {
	for ctx.Err() == nil {
		ev, err := source.Next(ctx)
		if err != nil {
			return
		}

		if ev.Type == awid.AgentEventConnected {
			continue
		}
		if ev.Type == awid.AgentEventError {
			if b.onError != nil {
				b.onError(*ev)
			}
			continue
		}

		priority, shouldQueue := classifyAgentEvent(*ev)
		if !shouldQueue {
			continue
		}
		if b.deduper != nil && b.deduper.Seen(*ev) {
			continue
		}

		busEvt := BusEvent{Event: *ev, Priority: priority}
		if priority == PriorityInterrupt {
			select {
			case b.interrupts <- busEvt:
			case <-ctx.Done():
				return
			}
		} else {
			b.queue.Push(busEvt)
		}
	}
}

type recentEventDeduper struct {
	limit int
	order []string
	seen  map[string]struct{}
}

func newRecentEventDeduper(limit int) *recentEventDeduper {
	if limit <= 0 {
		limit = 1
	}
	return &recentEventDeduper{
		limit: limit,
		order: make([]string, 0, limit),
		seen:  make(map[string]struct{}, limit),
	}
}

func (d *recentEventDeduper) Seen(evt awid.AgentEvent) bool {
	if d == nil {
		return false
	}
	key := dedupeEventKey(evt)
	if key == "" {
		return false
	}
	if _, ok := d.seen[key]; ok {
		return true
	}
	if len(d.order) >= d.limit {
		oldest := d.order[0]
		d.order = d.order[1:]
		delete(d.seen, oldest)
	}
	d.order = append(d.order, key)
	d.seen[key] = struct{}{}
	return false
}

func dedupeEventKey(evt awid.AgentEvent) string {
	switch {
	case evt.MessageID != "":
		return string(evt.Type) + ":message:" + evt.MessageID
	case evt.SignalID != "":
		return string(evt.Type) + ":signal:" + evt.SignalID
	case evt.EventID != "":
		return string(evt.Type) + ":event:" + evt.EventID
	default:
		// Coordination events intentionally bypass dedupe for now. Their
		// task_id/status combinations do not yet form a stable replay key,
		// and dropping them risks hiding a real coordination state change.
		return ""
	}
}
