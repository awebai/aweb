package run

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	awid "github.com/awebai/aw/awid"
)

// ConnectionState tracks the SSE connection lifecycle. While the bus runs it
// is one of the three states of docs/event-stream-client-policy.md §8:
// streaming, retrying (ConnReconnecting) or refused. ConnDisconnected is a
// bus that is not running.
type ConnectionState int32

const (
	ConnDisconnected ConnectionState = iota
	ConnReconnecting
	ConnStreaming
	ConnRefused
)

func (s ConnectionState) String() string {
	switch s {
	case ConnStreaming:
		return "streaming"
	case ConnReconnecting:
		return "reconnecting"
	case ConnRefused:
		return "refused"
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
	case awid.AgentEventActionableMail, awid.AgentEventActionableChat, awid.AgentEventChannelReconnected:
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
	policy *StreamPolicy

	interrupts chan BusEvent
	queue      *PriorityQueue
	deduper    *recentEventDeduper

	connState          atomic.Int32
	onStateChange      func(ConnectionState)
	onConnectionNotice func(string)
	onError            func(awid.AgentEvent)

	cancel context.CancelFunc
	done   chan struct{}
}

// EventBusConfig holds construction parameters for an EventBus.
type EventBusConfig struct {
	Stream EventStreamOpener
	// Reload reads the credentials again from where they are kept and
	// returns the opener that uses them. The bus calls it before each retry
	// of a refused stream, in a context that ends when the bus stops.
	// Without it a retry uses Stream.
	Reload        StreamReload
	Now           func() time.Time
	OnStateChange func(ConnectionState)
	// Policy supplies the reconnect policy's timer and random source; its
	// clock defaults to Now.
	Policy StreamPolicyConfig
}

func NewEventBus(cfg EventBusConfig) *EventBus {
	nowFn := cfg.Now
	if nowFn == nil {
		nowFn = time.Now
	}
	policyCfg := cfg.Policy
	if policyCfg.Now == nil {
		policyCfg.Now = nowFn
	}
	b := &EventBus{
		policy:        NewStreamPolicy(cfg.Stream, cfg.Reload, policyCfg),
		interrupts:    make(chan BusEvent, 8),
		queue:         NewPriorityQueue(),
		deduper:       newRecentEventDeduper(256),
		onStateChange: cfg.OnStateChange,
		done:          make(chan struct{}),
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

// run keeps the stream open for the life of the bus. When a connection
// closes, what its end means and how long to wait are decided by the event
// stream client policy (streampolicy.go); this loop reports the state.
func (b *EventBus) run(ctx context.Context) {
	defer close(b.done)
	defer b.setState(ConnDisconnected)

	outageReported := false
	b.setState(ConnReconnecting)

	for ctx.Err() == nil {
		// Opening the HTTP response is not proof that the event stream is live:
		// a proxy can return 200 and immediately close the body. Confirm health
		// only after the stream produces an event or a heartbeat. This prevents
		// early-EOF flaps from oscillating recovery/down and queueing false
		// catch-up wakes.
		conn := b.policy.Connect(ctx, func(endedRefusal string) {
			outageReported = false
			b.setState(ConnStreaming)
			if endedRefusal != "" {
				b.connectionNotice(formatStreamAcceptedNotice(endedRefusal))
			}
			// Transport recovery is observable through connection state and
			// diagnostics, but it is not communication. The fresh stream snapshot
			// is the only catch-up source for real actionable events.
		})
		source, err := conn.Open()
		if err == nil {
			err = b.consumeStream(conn, source)
			_ = source.Close()
		}
		end := conn.End(err)
		switch end.Kind {
		case StreamEndStopped:
			return
		case StreamEndPlannedClose:
			// Not an outage: the state stays as it is and nothing is reported.
		case StreamEndTransient:
			b.setState(ConnReconnecting)
			if !outageReported {
				outageReported = true
				b.connectionNotice(formatStreamDisconnectNotice(end.Err, end.Wait))
			}
		case StreamEndRefused:
			// Reported once on entering the quarantine; a retry that is refused
			// again moves the next attempt and says nothing.
			b.setState(ConnRefused)
			if end.EnteredRefused {
				b.connectionNotice(formatStreamRefusedNotice(end.Cause, end.NextAttempt))
			}
		}
		if !b.policy.Wait(ctx, end) {
			return
		}
	}
}

func (b *EventBus) connectionNotice(message string) {
	if b.onConnectionNotice != nil {
		b.onConnectionNotice(message)
	}
}

func formatStreamRefusedNotice(cause string, nextAttempt time.Time) string {
	return "aweb: event stream refused: " + cause + ", next try " + nextAttempt.Local().Format("15:04")
}

func formatStreamAcceptedNotice(endedRefusal string) string {
	return "aweb: event stream accepted again (was refused: " + endedRefusal + ")"
}

func formatStreamDisconnectNotice(err error, delay time.Duration) string {
	cause := "connection failed"
	text := ""
	if err != nil {
		text = strings.ToLower(strings.TrimSpace(err.Error()))
	}
	switch {
	case strings.Contains(text, "connection refused"):
		cause = "connection refused"
	case strings.Contains(text, "no such host"), strings.Contains(text, "dns"), strings.Contains(text, "lookup"):
		cause = "DNS lookup failed"
	case strings.Contains(text, "timeout"), strings.Contains(text, "timed out"):
		cause = "connection timed out"
	case strings.Contains(text, "certificate"), strings.Contains(text, "tls"):
		cause = "TLS connection failed"
	case strings.Contains(text, "fetch"), strings.Contains(text, "network"), strings.Contains(text, "503"):
		cause = "network unavailable"
	}
	return "aweb: event stream disconnected (" + cause + ") — retrying in " + delay.Round(100*time.Millisecond).String()
}

func (b *EventBus) consumeStream(conn *StreamConnection, source awid.EventSource) error {
	ctx := conn.Context()
	for ctx.Err() == nil {
		ev, err := source.Next(ctx)
		if err != nil {
			return err
		}
		conn.Event()

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
				return ctx.Err()
			}
		} else {
			b.queue.Push(busEvt)
		}
	}
	return ctx.Err()
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
