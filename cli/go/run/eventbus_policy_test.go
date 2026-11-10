package run

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/manualclock"
	"github.com/awebai/aw/internal/streamtest"
)

// `aw run` on the event stream client policy
// (docs/event-stream-client-policy.md), with a clock the tests advance.

// fastStreamPolicy runs the policy's waits a hundred times faster, for tests
// that reconnect over real connections and bound themselves in real time.
func fastStreamPolicy() StreamPolicyConfig {
	return StreamPolicyConfig{Timer: streamtest.ScaledTimer(100)}
}

type busRecord struct {
	mu      sync.Mutex
	notices []string
	states  []ConnectionState
}

func (r *busRecord) notice(message string) {
	r.mu.Lock()
	r.notices = append(r.notices, message)
	r.mu.Unlock()
}

func (r *busRecord) state(state ConnectionState) {
	r.mu.Lock()
	r.states = append(r.states, state)
	r.mu.Unlock()
}

func (r *busRecord) allNotices() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.notices...)
}

func (r *busRecord) allStates() []ConnectionState {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]ConnectionState(nil), r.states...)
}

func startManualBus(t *testing.T, clock *manualclock.Clock, stream EventStreamOpener, reload StreamReload) (*EventBus, *busRecord) {
	t.Helper()
	record := &busRecord{}
	bus := NewEventBus(EventBusConfig{
		Stream:        stream,
		Reload:        reload,
		Now:           clock.Now,
		OnStateChange: record.state,
		Policy:        StreamPolicyConfig{Timer: clock.Timer, Rand: clock.Random},
	})
	bus.onConnectionNotice = record.notice
	ctx, cancel := context.WithCancel(context.Background())
	bus.Start(ctx)
	t.Cleanup(func() {
		cancel()
		bus.Stop()
	})
	return bus, record
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

func busStopped(bus *EventBus) bool {
	select {
	case <-bus.done:
		return true
	default:
		return false
	}
}

// awaitRetryWait waits for the bus to be sleeping before a retry. started is
// how many timers the bus has started by then: one for each connection's
// planned close, one for the silence watch of each connection that opened,
// and one for each wait between attempts. Only the wait is still running.
func awaitRetryWait(t *testing.T, clock *manualclock.Clock, started int) {
	t.Helper()
	if !clock.AwaitStarted(started, 1) {
		t.Fatalf("timers started=%d waiting=%d, want %d started and the retry wait running", clock.Started(), clock.Timers(), started)
	}
}

// advanceToNextAttempt waits for the bus to be sleeping before a retry and
// moves the clock to the end of that sleep. It returns how long the sleep was.
func advanceToNextAttempt(t *testing.T, clock *manualclock.Clock, started int) time.Duration {
	t.Helper()
	awaitRetryWait(t, clock, started)
	wait, _ := clock.NextTimer()
	clock.Advance(wait)
	return wait
}

func popQueued(t *testing.T, bus *EventBus) BusEvent {
	t.Helper()
	var event BusEvent
	eventually(t, "a queued event", func() bool {
		popped, ok := bus.Queue().Pop()
		event = popped
		return ok
	})
	return event
}

// The defect the policy exists for: one 429 while opening the stream left an
// `aw run` agent deaf until it was restarted (§1, §3).
func TestEventBusRetriesAfter429AndDeliversEvents(t *testing.T) {
	clock := manualclock.New(policyStart)
	source := streamtest.NewSource()
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(streamtest.HTTPFailure(429)), streamtest.Opens(source))
	bus, record := startManualBus(t, clock, opener.Open, nil)

	awaitRetryWait(t, clock, 2)
	if busStopped(bus) {
		t.Fatal("a 429 stopped the event stream")
	}
	if bus.State() != ConnReconnecting {
		t.Fatalf("state after a 429 = %s, want reconnecting", bus.State())
	}
	if wait := advanceToNextAttempt(t, clock, 2); wait != time.Second/2 {
		t.Fatalf("waited %s after a 429, want the transient delay", wait)
	}
	eventually(t, "the second open", func() bool { return opener.Opens() == 2 })
	source.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
	if bus.State() != ConnStreaming {
		t.Fatalf("state after the stream is confirmed = %s", bus.State())
	}
	source.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m-1", FromAlias: "alice"}})
	if event := popQueued(t, bus); event.Event.MessageID != "m-1" {
		t.Fatalf("delivered %+v", event.Event)
	}
	notices := record.allNotices()
	if len(notices) != 1 || !strings.HasPrefix(notices[0], "aweb: event stream disconnected (") || !strings.HasSuffix(notices[0], "retrying in 500ms") {
		t.Fatalf("notices=%q, want one disconnect", notices)
	}
}

// Retry-After on a rate limit is a minimum wait (§3).
func TestEventBusHonoursRetryAfter(t *testing.T) {
	clock := manualclock.New(policyStart)
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(streamtest.HTTPFailureRetryAfter(429, "90")), streamtest.Opens(streamtest.NewSource()))
	startManualBus(t, clock, opener.Open, nil)
	if wait := advanceToNextAttempt(t, clock, 2); wait != 90*time.Second+time.Second/2 {
		t.Fatalf("waited %s, want Retry-After plus the jittered delay", wait)
	}
	eventually(t, "the second open", func() bool { return opener.Opens() == 2 })
}

// A 401 on open quarantines the stream instead of ending it: the bus says so
// once, tries again a minute later and says once that it is back (§1, §4, §8).
func TestEventBusRetriesAMinuteAfter401(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requests.Add(1) == 1 {
			http.Error(w, `{"detail":"unauthorized"}`, http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("event: connected\ndata: {\"agent_id\":\"a\",\"team_id\":\"t\"}\n\nevent: actionable_mail\ndata: {\"message_id\":\"m2\",\"from_alias\":\"alice\",\"subject\":\"test\",\"wake_mode\":\"prompt\",\"unread_count\":1}\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)
	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	clock := manualclock.New(policyStart)
	clock.SetRandom(almostOne)
	bus, record := startManualBus(t, clock, NewEventStreamOpener(client), nil)

	awaitRetryWait(t, clock, 2)
	if busStopped(bus) {
		t.Fatal("a 401 stopped the event stream")
	}
	if bus.State() != ConnRefused {
		t.Fatalf("state after a 401 = %s, want refused", bus.State())
	}
	wait, _ := clock.NextTimer()
	if wait >= time.Minute || wait < time.Minute-time.Microsecond {
		t.Fatalf("next attempt in %s, want just under a minute for the highest draw", wait)
	}
	refused := "aweb: event stream refused: 401, next try " + policyStart.Add(wait).Local().Format("15:04")
	if notices := record.allNotices(); len(notices) != 1 || notices[0] != refused {
		t.Fatalf("notices=%q, want %q", notices, refused)
	}

	clock.Advance(59 * time.Second)
	time.Sleep(20 * time.Millisecond)
	if got := requests.Load(); got != 1 {
		t.Fatalf("%d requests 59 seconds after a refusal, want 1", got)
	}
	clock.Advance(time.Second)
	if event := popQueued(t, bus); event.Event.MessageID != "m2" {
		t.Fatalf("delivered %+v", event.Event)
	}
	if bus.State() != ConnStreaming {
		t.Fatalf("state after the stream is confirmed = %s", bus.State())
	}
	want := []string{refused, "aweb: event stream accepted again (was refused: 401)"}
	if notices := record.allNotices(); fmt.Sprint(notices) != fmt.Sprint(want) {
		t.Fatalf("notices=%q, want %q", notices, want)
	}
}

// A client error does not end the bus: it stays refused with a retry
// scheduled until its owner stops it (§1).
func TestEventBusStaysAliveOnClientError(t *testing.T) {
	clock := manualclock.New(policyStart)
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(&awid.APIError{StatusCode: 404, Body: "not found"}))
	bus, _ := startManualBus(t, clock, opener.Open, nil)

	for attempt := 1; attempt <= 3; attempt++ {
		awaitRetryWait(t, clock, 2*attempt)
		if busStopped(bus) {
			t.Fatalf("the bus stopped after %d refusals", attempt)
		}
		if bus.State() != ConnRefused {
			t.Fatalf("state after %d refusals = %s, want refused", attempt, bus.State())
		}
		advanceToNextAttempt(t, clock, 2*attempt)
		eventually(t, "the next attempt", func() bool { return opener.Opens() == attempt+1 })
	}
}

// refused is reported once on the way in and once on the way out, never once
// per retry (§8).
func TestEventBusReportsRefusalOncePerTransition(t *testing.T) {
	clock := manualclock.New(policyStart)
	source := streamtest.NewSource()
	opener := streamtest.NewOpener(clock.Now,
		streamtest.Fails(streamtest.HTTPFailure(401)),
		streamtest.Fails(streamtest.HTTPFailure(401)),
		streamtest.Fails(streamtest.HTTPFailure(403)),
		streamtest.Fails(streamtest.HTTPFailure(503)),
		streamtest.Fails(streamtest.HTTPFailure(401)),
		streamtest.Opens(source),
	)
	bus, record := startManualBus(t, clock, opener.Open, nil)

	var waits []time.Duration
	for attempt := 1; attempt <= 5; attempt++ {
		waits = append(waits, advanceToNextAttempt(t, clock, 2*attempt))
		eventually(t, "the next attempt", func() bool { return opener.Opens() == attempt+1 })
	}
	// The lowest draw is half of each delay: 1, 2, 4, 8 and 15 minutes.
	wantWaits := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 7*time.Minute + 30*time.Second}
	if fmt.Sprint(waits) != fmt.Sprint(wantWaits) {
		t.Fatalf("waits=%v, want %v", waits, wantWaits)
	}
	source.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
	if bus.State() != ConnStreaming {
		t.Fatalf("state=%s after the stream is confirmed", bus.State())
	}

	want := []string{
		"aweb: event stream refused: 401, next try " + policyStart.Add(30*time.Second).Local().Format("15:04"),
		"aweb: event stream accepted again (was refused: 401)",
	}
	if notices := record.allNotices(); fmt.Sprint(notices) != fmt.Sprint(want) {
		t.Fatalf("notices=%q, want one on entry and one on exit: %q", notices, want)
	}
	wantStates := []ConnectionState{ConnReconnecting, ConnRefused, ConnStreaming}
	if states := record.allStates(); fmt.Sprint(states) != fmt.Sprint(wantStates) {
		t.Fatalf("states=%v, want %v", states, wantStates)
	}
}

// A grant terminal event on an open stream is a refusal (§4).
func TestEventBusQuarantinesOnAGrantTerminalEvent(t *testing.T) {
	clock := manualclock.New(policyStart)
	source := streamtest.NewSource()
	opener := streamtest.NewOpener(clock.Now, streamtest.Opens(source), streamtest.Fails(streamtest.HTTPFailure(403)))
	bus, record := startManualBus(t, clock, opener.Open, nil)
	eventually(t, "the first open", func() bool { return opener.Opens() == 1 })
	source.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
	source.Feed(streamtest.Item{Err: &awid.AgentEventStreamClosedError{Event: "grant_revoked", Detail: "identity grant revoked"}})

	// Planned close, silence watch, and the wait after the refusal.
	awaitRetryWait(t, clock, 3)
	if bus.State() != ConnRefused {
		t.Fatalf("state=%s, want refused", bus.State())
	}
	want := "aweb: event stream refused: grant_revoked, next try " + policyStart.Add(30*time.Second).Local().Format("15:04")
	if notices := record.allNotices(); len(notices) != 1 || notices[0] != want {
		t.Fatalf("notices=%q, want %q", notices, want)
	}
}

// The planned close is drawn between 3 min 30 s and 4 min; the bus reconnects
// at once, stays streaming and reports nothing (§2, §8).
func TestEventBusReconnectsAtItsPlannedCloseWithoutANotice(t *testing.T) {
	clock := manualclock.New(policyStart)
	clock.SetRandom(0.5)
	first, second := streamtest.NewSource(), streamtest.NewSource()
	opener := streamtest.NewOpener(clock.Now, streamtest.Opens(first), streamtest.Opens(second))
	bus, record := startManualBus(t, clock, opener.Open, nil)

	eventually(t, "the first open", func() bool { return opener.Opens() == 1 })
	planned := 3*time.Minute + 45*time.Second
	if got := opener.LastDeadline().Sub(policyStart); got != planned {
		t.Fatalf("asked the server to close after %s, want %s for the middle draw", got, planned)
	}
	first.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
	elapsed := time.Duration(0)
	for planned-elapsed > 30*time.Second {
		awaitTimers(t, clock, 2)
		clock.Advance(30 * time.Second)
		elapsed += 30 * time.Second
		first.Feed(streamtest.Item{Comment: true})
	}
	awaitTimers(t, clock, 2)
	if opener.Opens() != 1 {
		t.Fatal("reconnected before the planned close")
	}
	clock.Advance(planned - elapsed)

	// No wait: the second open happens without the clock moving again.
	eventually(t, "the reconnect", func() bool { return opener.Opens() == 2 })
	if at := opener.OpenTimes()[1]; !at.Equal(policyStart.Add(planned)) {
		t.Fatalf("reconnected at %s, want at the planned close %s", at, policyStart.Add(planned))
	}
	second.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m-2", FromAlias: "alice"}})
	if event := popQueued(t, bus); event.Event.MessageID != "m-2" {
		t.Fatalf("delivered %+v", event.Event)
	}
	if notices := record.allNotices(); len(notices) != 0 {
		t.Fatalf("a planned close was reported: %q", notices)
	}
	wantStates := []ConnectionState{ConnReconnecting, ConnStreaming}
	if states := record.allStates(); fmt.Sprint(states) != fmt.Sprint(wantStates) {
		t.Fatalf("states=%v, want %v: a planned close does not leave streaming", states, wantStates)
	}
}

// An open stream that delivers nothing for 75 seconds is closed and retried
// as a transient failure (§6).
func TestEventBusReconnectsAfterSilence(t *testing.T) {
	clock := manualclock.New(policyStart)
	first, second := streamtest.NewSource(), streamtest.NewSource()
	opener := streamtest.NewOpener(clock.Now, streamtest.Opens(first), streamtest.Opens(second))
	bus, record := startManualBus(t, clock, opener.Open, nil)
	eventually(t, "the first open", func() bool { return opener.Opens() == 1 })
	first.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
	awaitTimers(t, clock, 2)
	clock.Advance(75 * time.Second)

	// Planned close, silence watch, and the wait after the silence.
	if wait := advanceToNextAttempt(t, clock, 3); wait != time.Second/2 {
		t.Fatalf("waited %s after silence, want the transient delay", wait)
	}
	eventually(t, "the reconnect", func() bool { return opener.Opens() == 2 })
	if bus.State() != ConnReconnecting {
		t.Fatalf("state=%s, want reconnecting", bus.State())
	}
	if notices := record.allNotices(); len(notices) != 1 || !strings.Contains(notices[0], "disconnected") {
		t.Fatalf("notices=%q, want one disconnect", notices)
	}
}

// Before each retry of a refused stream the credentials are read again; a
// transient retry uses what the bus holds (§4).
func TestEventBusReloadsCredentialsBetweenRefusedAttempts(t *testing.T) {
	clock := manualclock.New(policyStart)
	var mu sync.Mutex
	stored := "expired"
	var used []string
	reloads := 0
	source := streamtest.NewSource()
	openerWith := func(credential string) EventStreamOpener {
		return func(context.Context, time.Time) (awid.EventSource, error) {
			mu.Lock()
			used = append(used, credential)
			mu.Unlock()
			if credential == "renewed" {
				return source, nil
			}
			return nil, streamtest.HTTPFailure(401)
		}
	}
	reload := func(context.Context) (EventStreamOpener, error) {
		mu.Lock()
		defer mu.Unlock()
		reloads++
		return openerWith(stored), nil
	}
	attempts := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(used)
	}
	bus, _ := startManualBus(t, clock, openerWith("held at start"), reload)

	advanceToNextAttempt(t, clock, 2)
	eventually(t, "the second attempt", func() bool { return attempts() == 2 })
	mu.Lock()
	stored = "renewed"
	mu.Unlock()
	advanceToNextAttempt(t, clock, 4)
	eventually(t, "the third attempt", func() bool { return attempts() == 3 })
	source.Feed(streamtest.Item{Event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
	if bus.State() != ConnStreaming {
		t.Fatalf("state=%s with the renewed credential", bus.State())
	}

	mu.Lock()
	defer mu.Unlock()
	if want := []string{"held at start", "expired", "renewed"}; fmt.Sprint(used) != fmt.Sprint(want) {
		t.Fatalf("attempts used %v, want %v", used, want)
	}
	if reloads != 2 {
		t.Fatalf("credentials read %d times, want once before each refused retry", reloads)
	}
}

// Stopping the bus does not wait for a reload: the reload is given the bus's
// context and ends with it.
func TestEventBusStopDoesNotWaitOnAReload(t *testing.T) {
	clock := manualclock.New(policyStart)
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(streamtest.HTTPFailure(401)))
	entered := make(chan struct{})
	reload := func(ctx context.Context) (EventStreamOpener, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	bus := NewEventBus(EventBusConfig{
		Stream: opener.Open,
		Reload: reload,
		Now:    clock.Now,
		Policy: StreamPolicyConfig{Timer: clock.Timer, Rand: clock.Random},
	})
	bus.Start(context.Background())
	advanceToNextAttempt(t, clock, 2)
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the refused retry did not read the credentials again")
	}

	stopped := make(chan struct{})
	go func() {
		bus.Stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stopping the bus waited on the reload")
	}
	if opener.Opens() != 1 {
		t.Fatalf("opened %d times; the stopped attempt must not go out", opener.Opens())
	}
}

// A server that accepts the open, sends its heartbeat and then a grant
// terminal event, every time: each cycle is one "accepted again" and one
// "refused" notice, at an interval that grows to the 15-minute ceiling.
func TestEventBusReportsAHeartbeatThenRefusalFlapAtAGrowingInterval(t *testing.T) {
	clock := manualclock.New(policyStart)
	sources := make(chan *streamtest.Source, 1)
	open := func(context.Context, time.Time) (awid.EventSource, error) {
		source := streamtest.NewSource()
		sources <- source
		return source, nil
	}
	_, record := startManualBus(t, clock, open, nil)

	var waits []time.Duration
	started := 0
	for cycle := 0; cycle < 6; cycle++ {
		source := <-sources
		source.Feed(streamtest.Item{Comment: true})
		source.Feed(streamtest.Item{Err: &awid.AgentEventStreamClosedError{Event: "grant_revoked", Detail: "identity grant revoked"}})
		// Planned close, silence watch, and the wait after the refusal.
		started += 3
		waits = append(waits, advanceToNextAttempt(t, clock, started))
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 7*time.Minute + 30*time.Second, 7*time.Minute + 30*time.Second}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Fatalf("waits=%v, want %v", waits, want)
	}
	notices := record.allNotices()
	// Six entries into refused, and an exit before each but the first.
	if len(notices) != 11 {
		t.Fatalf("%d notices, want 11: %q", len(notices), notices)
	}
	for i, notice := range notices {
		wantPrefix := "aweb: event stream refused: grant_revoked, next try "
		if i%2 == 1 {
			wantPrefix = "aweb: event stream accepted again (was refused: grant_revoked)"
		}
		if !strings.HasPrefix(notice, wantPrefix) {
			t.Fatalf("notice %d = %q, want it to start %q", i, notice, wantPrefix)
		}
	}
}

// The same flap as today's server produces it: heartbeat, the opening
// connected event, then the grant terminal event. The connected event does
// not return the refused delay to 1 minute.
func TestEventBusFlapWithTheConnectedEventGrowsTheRefusedDelay(t *testing.T) {
	clock := manualclock.New(policyStart)
	sources := make(chan *streamtest.Source, 1)
	open := func(context.Context, time.Time) (awid.EventSource, error) {
		source := streamtest.NewSource()
		sources <- source
		return source, nil
	}
	bus, _ := startManualBus(t, clock, open, nil)

	var waits []time.Duration
	started := 0
	for cycle := 0; cycle < 6; cycle++ {
		source := <-sources
		source.Feed(streamtest.Item{Comment: true})
		source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected, AgentID: "a"})
		if bus.State() != ConnStreaming {
			t.Fatalf("cycle %d: state=%s after the connected event, want streaming", cycle, bus.State())
		}
		source.Feed(streamtest.Item{Err: &awid.AgentEventStreamClosedError{Event: "grant_revoked", Detail: "identity grant revoked"}})
		// Planned close, silence watch, and the wait after the refusal.
		started += 3
		waits = append(waits, advanceToNextAttempt(t, clock, started))
	}
	want := []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 7*time.Minute + 30*time.Second, 7*time.Minute + 30*time.Second}
	if fmt.Sprint(waits) != fmt.Sprint(want) {
		t.Fatalf("waits=%v, want %v", waits, want)
	}

	// Any other event is the server serving this caller: the delay starts over.
	source := <-sources
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected, AgentID: "a"})
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: "m-1", FromAlias: "alice"})
	source.Feed(streamtest.Item{Err: &awid.AgentEventStreamClosedError{Event: "grant_revoked", Detail: "identity grant revoked"}})
	if wait := advanceToNextAttempt(t, clock, started+3); wait != 30*time.Second {
		t.Fatalf("refused after a mail event waits %s, want half of 1 minute", wait)
	}
}
