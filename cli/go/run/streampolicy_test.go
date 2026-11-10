package run

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/manualclock"
)

// These tests state docs/event-stream-client-policy.md one rule at a time.

var policyStart = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// almostOne is the largest value a uniform random source in [0, 1) returns.
var almostOne = math.Nextafter(1, 0)

func policyConfig(clock *manualclock.Clock) StreamPolicyConfig {
	return StreamPolicyConfig{Now: clock.Now, Timer: clock.Timer, Rand: clock.Random}
}

type streamAttempt func(ctx context.Context, deadline time.Time) (awid.EventSource, error)

func attemptFails(err error) streamAttempt {
	return func(context.Context, time.Time) (awid.EventSource, error) { return nil, err }
}

func attemptOpens(source awid.EventSource) streamAttempt {
	return func(context.Context, time.Time) (awid.EventSource, error) { return source, nil }
}

func httpFailure(status int) error {
	return &awid.APIError{StatusCode: status}
}

func httpFailureRetryAfter(status int, retryAfter string) error {
	return &awid.APIError{StatusCode: status, RetryAfter: retryAfter}
}

// scriptedOpener plays its attempts in order and repeats the last one. It
// records when each attempt was made and the deadline it was given.
type scriptedOpener struct {
	clock *manualclock.Clock

	mu        sync.Mutex
	attempts  []streamAttempt
	openedAt  []time.Time
	deadlines []time.Time
}

func newScriptedOpener(clock *manualclock.Clock, attempts ...streamAttempt) *scriptedOpener {
	return &scriptedOpener{clock: clock, attempts: attempts}
}

func (o *scriptedOpener) open(ctx context.Context, deadline time.Time) (awid.EventSource, error) {
	o.mu.Lock()
	index := len(o.openedAt)
	if index >= len(o.attempts) {
		index = len(o.attempts) - 1
	}
	attempt := o.attempts[index]
	o.openedAt = append(o.openedAt, o.clock.Now())
	o.deadlines = append(o.deadlines, deadline)
	o.mu.Unlock()
	return attempt(ctx, deadline)
}

func (o *scriptedOpener) opens() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.openedAt)
}

func (o *scriptedOpener) openTimes() []time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]time.Time(nil), o.openedAt...)
}

func (o *scriptedOpener) lastDeadline() time.Time {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.deadlines[len(o.deadlines)-1]
}

// rawItem is one thing a rawSource reads: a heartbeat comment, bytes that
// complete no line, an event, or the end of the stream.
type rawItem struct {
	comment bool
	partial bool
	event   *awid.AgentEvent
	err     error
}

// rawSource is an event source whose reads the test feeds one at a time. Like
// the real stream it reports every read, and every comment, to its observers
// from the goroutine that calls Next.
type rawSource struct {
	items     chan rawItem
	handled   chan struct{}
	onRead    func()
	onComment func()
}

func newRawSource() *rawSource {
	return &rawSource{items: make(chan rawItem), handled: make(chan struct{})}
}

func (s *rawSource) OnRead(f func())    { s.onRead = f }
func (s *rawSource) OnComment(f func()) { s.onComment = f }
func (s *rawSource) Close() error       { return nil }

func (s *rawSource) Next(ctx context.Context) (*awid.AgentEvent, error) {
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case item := <-s.items:
			if item.err != nil {
				s.handled <- struct{}{}
				return nil, item.err
			}
			if s.onRead != nil {
				s.onRead()
			}
			if item.comment && s.onComment != nil {
				s.onComment()
			}
			s.handled <- struct{}{}
			if item.event != nil {
				return item.event, nil
			}
		}
	}
}

// feed hands the source one read and returns once the source has reported it.
func (s *rawSource) feed(item rawItem) {
	s.items <- item
	<-s.handled
}

// consumeConnection reads a source the way a client does: every event read
// is reported to the connection.
func consumeConnection(conn *StreamConnection, source awid.EventSource) error {
	defer source.Close()
	for {
		if _, err := source.Next(conn.Context()); err != nil {
			return err
		}
		conn.Event()
	}
}

// attemptOnce makes one connection attempt and reports how it ended.
func attemptOnce(policy *StreamPolicy) StreamEnd {
	conn := policy.Connect(context.Background(), nil)
	source, err := conn.Open()
	if err == nil {
		err = consumeConnection(conn, source)
	}
	return conn.End(err)
}

func confirmedEvent() awid.AgentEvent {
	return awid.AgentEvent{Type: awid.AgentEventConnected}
}

func awaitTimers(t *testing.T, clock *manualclock.Clock, n int) {
	t.Helper()
	if !clock.AwaitTimers(n) {
		t.Fatalf("timers waiting=%d, want %d", clock.Timers(), n)
	}
}

func isTransientStatus(status int) bool {
	return status == 408 || status == 409 || status == 425 || status == 429
}

// Sections 3 and 4, and decision 2: 408, 409, 425 and 429 and every 5xx are
// transient; every other 4xx is a refusal; the four grant terminal events are
// refusals and verification_unavailable is transient.
func TestStreamPolicyClassifiesEveryAnswer(t *testing.T) {
	type classification struct {
		name  string
		err   error
		kind  StreamEndKind
		cause string
	}
	var cases []classification
	for status := 400; status <= 499; status++ {
		kind := StreamEndRefused
		if isTransientStatus(status) {
			kind = StreamEndTransient
		}
		cases = append(cases, classification{name: fmt.Sprintf("http %d", status), err: httpFailure(status), kind: kind, cause: strconv.Itoa(status)})
	}
	for status := 500; status <= 599; status++ {
		cases = append(cases, classification{name: fmt.Sprintf("http %d", status), err: httpFailure(status), kind: StreamEndTransient, cause: strconv.Itoa(status)})
	}
	for _, event := range []string{"grant_expired", "grant_revoked", "grant_subject_inactive", "grant_issuer_revoked"} {
		cases = append(cases, classification{name: event, err: &awid.AgentEventStreamClosedError{Event: event, Detail: event}, kind: StreamEndRefused, cause: event})
	}
	cases = append(cases,
		classification{name: "the named refusals 401", err: httpFailure(401), kind: StreamEndRefused, cause: "401"},
		classification{name: "the named refusals 403", err: httpFailure(403), kind: StreamEndRefused, cause: "403"},
		classification{name: "the named refusals 404", err: httpFailure(404), kind: StreamEndRefused, cause: "404"},
		classification{name: "the named refusals 422", err: httpFailure(422), kind: StreamEndRefused, cause: "422"},
		classification{name: "other 4xx 400", err: httpFailure(400), kind: StreamEndRefused, cause: "400"},
		classification{name: "other 4xx 405", err: httpFailure(405), kind: StreamEndRefused, cause: "405"},
		classification{name: "other 4xx 410", err: httpFailure(410), kind: StreamEndRefused, cause: "410"},
		classification{name: "other 4xx 451", err: httpFailure(451), kind: StreamEndRefused, cause: "451"},
		classification{name: "moment 408", err: httpFailure(408), kind: StreamEndTransient, cause: "408"},
		classification{name: "moment 409", err: httpFailure(409), kind: StreamEndTransient, cause: "409"},
		classification{name: "moment 425", err: httpFailure(425), kind: StreamEndTransient, cause: "425"},
		classification{name: "moment 429", err: httpFailure(429), kind: StreamEndTransient, cause: "429"},
		classification{name: "wrapped refusal", err: fmt.Errorf("open: %w", httpFailure(401)), kind: StreamEndRefused, cause: "401"},
		classification{name: "redirect answer", err: httpFailure(302), kind: StreamEndTransient, cause: "302"},
		classification{name: "verification_unavailable", err: &awid.AgentEventStreamClosedError{Event: "verification_unavailable"}, kind: StreamEndTransient, cause: "verification_unavailable"},
		classification{name: "early end", err: io.EOF, kind: StreamEndTransient},
		classification{name: "read error", err: io.ErrUnexpectedEOF, kind: StreamEndTransient},
		classification{name: "failure to open", err: &net.OpError{Op: "dial", Err: errors.New("connection refused")}, kind: StreamEndTransient},
		classification{name: "undecodable frame", err: &awid.AgentEventDecodeError{Event: "actionable_mail", Err: errors.New("bad json")}, kind: StreamEndTransient},
		classification{name: "end without an error", err: nil, kind: StreamEndTransient},
	)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			kind, cause := ClassifyStreamFailure(tc.err)
			if kind != tc.kind || cause != tc.cause {
				t.Fatalf("ClassifyStreamFailure(%v) = %v, %q; want %v, %q", tc.err, kind, cause, tc.kind, tc.cause)
			}
		})
	}
}

// Sections 3 and 4: each wait is drawn uniformly between half of the delay and
// all of it, on both ladders.
func TestStreamPolicyJitterBounds(t *testing.T) {
	ladders := []struct {
		name  string
		err   error
		delay time.Duration
	}{
		{"transient", httpFailure(503), time.Second},
		{"refused", httpFailure(401), time.Minute},
	}
	draws := []struct {
		name   string
		random float64
		check  func(delay, wait time.Duration) bool
	}{
		{"lowest draw is half the delay", 0, func(delay, wait time.Duration) bool { return wait == delay/2 }},
		{"middle draw is three quarters", 0.5, func(delay, wait time.Duration) bool { return wait == delay*3/4 }},
		{"highest draw is just under the delay", almostOne, func(delay, wait time.Duration) bool {
			return wait < delay && wait >= delay-time.Microsecond
		}},
	}
	for _, ladder := range ladders {
		for _, draw := range draws {
			t.Run(ladder.name+"/"+draw.name, func(t *testing.T) {
				clock := manualclock.New(policyStart)
				clock.SetRandom(draw.random)
				opener := newScriptedOpener(clock, attemptFails(ladder.err))
				policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
				end := attemptOnce(policy)
				if !draw.check(ladder.delay, end.Wait) {
					t.Fatalf("wait=%s for a delay of %s with draw %v", end.Wait, ladder.delay, draw.random)
				}
				if want := policyStart.Add(end.Wait); !end.NextAttempt.Equal(want) {
					t.Fatalf("next attempt=%s, want %s", end.NextAttempt, want)
				}
			})
		}
	}
}

// Section 3: 1 second doubling to 15 seconds. Section 4: 1 minute doubling to
// 15 minutes.
func TestStreamPolicyLaddersGrowToTheirCeilings(t *testing.T) {
	ladders := []struct {
		name string
		err  error
		kind StreamEndKind
		want []time.Duration
	}{
		{"transient", httpFailure(503), StreamEndTransient, []time.Duration{
			time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second, 15 * time.Second, 15 * time.Second, 15 * time.Second,
		}},
		{"refused", httpFailure(403), StreamEndRefused, []time.Duration{
			time.Minute, 2 * time.Minute, 4 * time.Minute, 8 * time.Minute, 15 * time.Minute, 15 * time.Minute, 15 * time.Minute,
		}},
	}
	for _, ladder := range ladders {
		t.Run(ladder.name, func(t *testing.T) {
			clock := manualclock.New(policyStart)
			opener := newScriptedOpener(clock, attemptFails(ladder.err))
			policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
			for step, delay := range ladder.want {
				end := attemptOnce(policy)
				if end.Kind != ladder.kind {
					t.Fatalf("step %d kind=%v, want %v", step, end.Kind, ladder.kind)
				}
				// The lowest draw is half of the delay.
				if end.Wait != delay/2 {
					t.Fatalf("step %d wait=%s, want half of %s", step, end.Wait, delay)
				}
			}
		})
	}
}

// Section 3: the delay returns to 1 second only once a stream is confirmed
// live. An open that returns 200 and then closes does not reset it.
func TestStreamPolicyResetsOnlyOnAConfirmedStream(t *testing.T) {
	t.Run("an open that closes without an event does not reset", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock,
			attemptFails(httpFailure(503)),
			attemptFails(httpFailure(503)),
			attemptOpens(newFakeEventSource()),
			attemptFails(httpFailure(503)),
		)
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		want := []time.Duration{time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second}
		for step, delay := range want {
			if end := attemptOnce(policy); end.Kind != StreamEndTransient || end.Wait != delay/2 {
				t.Fatalf("step %d: kind=%v wait=%s, want transient and half of %s", step, end.Kind, end.Wait, delay)
			}
		}
	})

	t.Run("the first event resets", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock,
			attemptFails(httpFailure(503)),
			attemptFails(httpFailure(503)),
			attemptOpens(newFakeEventSource(confirmedEvent())),
			attemptFails(httpFailure(503)),
		)
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		want := []time.Duration{time.Second, 2 * time.Second, time.Second, 2 * time.Second}
		for step, delay := range want {
			if end := attemptOnce(policy); end.Kind != StreamEndTransient || end.Wait != delay/2 {
				t.Fatalf("step %d: kind=%v wait=%s, want transient and half of %s", step, end.Kind, end.Wait, delay)
			}
		}
	})

	t.Run("the first heartbeat resets", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		source := newRawSource()
		opener := newScriptedOpener(clock,
			attemptFails(httpFailure(503)),
			attemptFails(httpFailure(503)),
			attemptOpens(source),
			attemptFails(httpFailure(503)),
		)
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)
		attemptOnce(policy)

		confirmed := 0
		conn := policy.Connect(context.Background(), func(string) { confirmed++ })
		opened, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- consumeConnection(conn, opened) }()
		source.feed(rawItem{partial: true})
		source.feed(rawItem{comment: true})
		source.feed(rawItem{comment: true})
		source.feed(rawItem{err: io.EOF})
		end := conn.End(<-ended)
		if confirmed != 1 {
			t.Fatalf("confirmed %d times, want once for the first heartbeat", confirmed)
		}
		if end.Kind != StreamEndTransient || end.Wait != time.Second/2 {
			t.Fatalf("after a heartbeat: kind=%v wait=%s, want transient from 1s", end.Kind, end.Wait)
		}
	})

	t.Run("bytes that are neither an event nor a heartbeat do not reset", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		source := newRawSource()
		opener := newScriptedOpener(clock, attemptFails(httpFailure(503)), attemptOpens(source))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)

		conn := policy.Connect(context.Background(), func(string) { t.Error("confirmed without an event or heartbeat") })
		opened, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- consumeConnection(conn, opened) }()
		source.feed(rawItem{partial: true})
		source.feed(rawItem{err: io.EOF})
		if end := conn.End(<-ended); end.Kind != StreamEndTransient || end.Wait != time.Second {
			t.Fatalf("kind=%v wait=%s, want transient and half of 2s", end.Kind, end.Wait)
		}
	})
}

// Section 3: Retry-After is a minimum wait up to 5 minutes; a larger or
// unparsable value is treated as 5 minutes; the jitter is added to it.
func TestStreamPolicyHonoursRetryAfter(t *testing.T) {
	httpDate := func(offset time.Duration) string {
		return policyStart.Add(offset).UTC().Format(http.TimeFormat)
	}
	cases := []struct {
		name   string
		header string
		want   time.Duration
	}{
		{"absent", "", 0},
		{"zero seconds", "0", 0},
		{"seconds below the cap", "120", 2 * time.Minute},
		{"seconds just below the cap", "299", 299 * time.Second},
		{"seconds at the cap", "300", 5 * time.Minute},
		{"seconds above the cap", "301", 5 * time.Minute},
		{"seconds far above the cap", "86400", 5 * time.Minute},
		{"seconds beyond any integer", "99999999999999999999999", 5 * time.Minute},
		{"padded seconds", " 7 ", 7 * time.Second},
		{"date below the cap", httpDate(90 * time.Second), 90 * time.Second},
		{"date at the cap", httpDate(5 * time.Minute), 5 * time.Minute},
		{"date above the cap", httpDate(time.Hour), 5 * time.Minute},
		{"date in the past", httpDate(-time.Hour), 0},
		{"unparsable", "soon", 5 * time.Minute},
		{"negative seconds", "-5", 5 * time.Minute},
		{"fractional seconds", "1.5", 5 * time.Minute},
	}
	answers := []struct {
		name   string
		status int
		delay  time.Duration
	}{
		{"429", 429, time.Second},
		{"503", 503, time.Second},
		// Section 4 gives a refusal the same jitter; a Retry-After on a
		// refusal is a minimum in the same way.
		{"403", 403, time.Minute},
	}
	for _, answer := range answers {
		for _, tc := range cases {
			for _, random := range []float64{0, 0.5} {
				t.Run(fmt.Sprintf("%s/%s/draw %v", answer.name, tc.name, random), func(t *testing.T) {
					clock := manualclock.New(policyStart)
					clock.SetRandom(random)
					opener := newScriptedOpener(clock, attemptFails(httpFailureRetryAfter(answer.status, tc.header)))
					policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
					end := attemptOnce(policy)
					jitter := answer.delay/2 + time.Duration(random*float64(answer.delay/2))
					if end.Wait != tc.want+jitter {
						t.Fatalf("Retry-After %q: wait=%s, want %s plus jitter %s", tc.header, end.Wait, tc.want, jitter)
					}
				})
			}
		}
	}

	t.Run("an answer without the header does not carry one over", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailureRetryAfter(429, "120")), attemptFails(httpFailure(429)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)
		if end := attemptOnce(policy); end.Wait != time.Second {
			t.Fatalf("wait=%s, want half of 2s with no Retry-After", end.Wait)
		}
	})
}

// Section 2: each connection's planned close is drawn uniformly between
// 3 minutes 30 seconds and 4 minutes, and it is not a failure.
func TestStreamPolicyPlannedClose(t *testing.T) {
	draws := []struct {
		name   string
		random float64
		check  func(time.Duration) bool
	}{
		{"lowest draw", 0, func(d time.Duration) bool { return d == 3*time.Minute+30*time.Second }},
		{"middle draw", 0.5, func(d time.Duration) bool { return d == 3*time.Minute+45*time.Second }},
		{"highest draw", almostOne, func(d time.Duration) bool { return d < 4*time.Minute && d >= 4*time.Minute-time.Microsecond }},
	}
	for _, draw := range draws {
		t.Run(draw.name, func(t *testing.T) {
			clock := manualclock.New(policyStart)
			clock.SetRandom(draw.random)
			source := newRawSource()
			opener := newScriptedOpener(clock, attemptOpens(source))
			policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))

			conn := policy.Connect(context.Background(), nil)
			opened, err := conn.Open()
			if err != nil {
				t.Fatal(err)
			}
			planned := opener.lastDeadline().Sub(policyStart)
			if !draw.check(planned) {
				t.Fatalf("planned close after %s with draw %v", planned, draw.random)
			}
			ended := make(chan error, 1)
			go func() { ended <- consumeConnection(conn, opened) }()
			source.feed(rawItem{event: &awid.AgentEvent{Type: awid.AgentEventConnected}})

			// Heartbeats keep the stream from being silent up to its close.
			elapsed := time.Duration(0)
			for planned-elapsed > 30*time.Second {
				awaitTimers(t, clock, 2)
				clock.Advance(30 * time.Second)
				elapsed += 30 * time.Second
				source.feed(rawItem{comment: true})
			}
			awaitTimers(t, clock, 2)
			if conn.Context().Err() != nil {
				t.Fatalf("connection closed %s before its planned close", planned-elapsed)
			}
			clock.Advance(planned - elapsed)
			end := conn.End(<-ended)
			if end.Kind != StreamEndPlannedClose || end.Wait != 0 {
				t.Fatalf("end=%+v, want a planned close with no wait", end)
			}
			if !policy.Wait(context.Background(), end) {
				t.Fatal("a planned close did not reconnect at once")
			}
			if clock.Timers() != 0 {
				t.Fatalf("%d timers left after the connection ended", clock.Timers())
			}
		})
	}

	t.Run("a draw is made for each connection", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(503)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)
		first := opener.lastDeadline()
		clock.SetRandom(0.5)
		attemptOnce(policy)
		if second := opener.lastDeadline(); second.Sub(first) != 15*time.Second {
			t.Fatalf("deadlines %s then %s; want each connection to draw its own", first, second)
		}
	})

	t.Run("a planned close does not move the transient delay", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		blocking := attemptOpens(blockingEventSource{})
		opener := newScriptedOpener(clock, attemptFails(httpFailure(503)), blocking, attemptFails(httpFailure(503)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)

		conn := policy.Connect(context.Background(), nil)
		opened, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- consumeConnection(conn, opened) }()
		conn.Reopen()
		if end := conn.End(<-ended); end.Kind != StreamEndPlannedClose {
			t.Fatalf("a reopen the client asked for ended as %v", end.Kind)
		}
		if end := attemptOnce(policy); end.Wait != time.Second {
			t.Fatalf("wait=%s, want half of 2s: a planned close is neither a failure nor a confirmation", end.Wait)
		}
	})

	t.Run("the server closing at the deadline it was asked for is the planned close", func(t *testing.T) {
		// The deadline travels as whole seconds, so the server may close up
		// to a second before the client's own timer.
		clock := manualclock.New(policyStart.Add(400 * time.Millisecond))
		source := newRawSource()
		opener := newScriptedOpener(clock, attemptOpens(source))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		conn := policy.Connect(context.Background(), nil)
		opened, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- consumeConnection(conn, opened) }()
		source.feed(rawItem{event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
		for i := 0; i < 6; i++ {
			awaitTimers(t, clock, 2)
			clock.Advance(30 * time.Second)
			source.feed(rawItem{comment: true})
		}
		awaitTimers(t, clock, 2)
		clock.Advance(29*time.Second + 600*time.Millisecond)
		source.feed(rawItem{err: io.EOF})
		if end := conn.End(<-ended); end.Kind != StreamEndPlannedClose {
			t.Fatalf("server close at the requested deadline ended as %v", end.Kind)
		}
	})

	t.Run("the server closing before the deadline is an early end", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptOpens(newFakeEventSource(confirmedEvent())))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		if end := attemptOnce(policy); end.Kind != StreamEndTransient {
			t.Fatalf("early end classified as %v", end.Kind)
		}
	})
}

// Section 6: nothing read for 75 seconds closes the connection and is a
// transient failure. Every byte counts, including comments.
func TestStreamPolicySilence(t *testing.T) {
	open := func(t *testing.T) (*manualclock.Clock, *rawSource, *StreamConnection, chan error) {
		t.Helper()
		clock := manualclock.New(policyStart)
		source := newRawSource()
		opener := newScriptedOpener(clock, attemptOpens(source))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		conn := policy.Connect(context.Background(), nil)
		opened, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- consumeConnection(conn, opened) }()
		awaitTimers(t, clock, 2)
		return clock, source, conn, ended
	}

	t.Run("75 seconds of silence closes the connection", func(t *testing.T) {
		clock, _, conn, ended := open(t)
		clock.Advance(75*time.Second - time.Nanosecond)
		if conn.Context().Err() != nil {
			t.Fatal("closed before 75 seconds of silence")
		}
		clock.Advance(time.Nanosecond)
		end := conn.End(<-ended)
		if end.Kind != StreamEndTransient || end.Cause != "silence" || !errors.Is(end.Err, ErrStreamSilent) {
			t.Fatalf("end=%+v, want a transient failure caused by silence", end)
		}
		if end.Wait != time.Second/2 {
			t.Fatalf("wait=%s, want the transient delay", end.Wait)
		}
	})

	reads := []struct {
		name string
		item rawItem
	}{
		{"a comment-only read", rawItem{comment: true}},
		{"bytes that complete no line", rawItem{partial: true}},
		{"an event", rawItem{event: &awid.AgentEvent{Type: awid.AgentEventConnected}}},
	}
	for _, read := range reads {
		t.Run(read.name+" resets the deadline", func(t *testing.T) {
			clock, source, conn, ended := open(t)
			clock.Advance(60 * time.Second)
			source.feed(read.item)
			clock.Advance(15 * time.Second)
			// The watchdog looked at 75 seconds, found a read 15 seconds
			// old, and waits out the rest.
			awaitTimers(t, clock, 2)
			if conn.Context().Err() != nil {
				t.Fatal("closed 15 seconds after a read")
			}
			clock.Advance(60*time.Second - time.Nanosecond)
			if conn.Context().Err() != nil {
				t.Fatal("closed before 75 seconds had passed since the read")
			}
			clock.Advance(time.Nanosecond)
			if end := conn.End(<-ended); end.Kind != StreamEndTransient || end.Cause != "silence" {
				t.Fatalf("end=%+v, want silence 75 seconds after the last read", end)
			}
		})
	}

	t.Run("a source that reports events only is watched by its events", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptOpens(blockingEventSource{}))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		conn := policy.Connect(context.Background(), nil)
		opened, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- consumeConnection(conn, opened) }()
		awaitTimers(t, clock, 2)
		clock.Advance(75 * time.Second)
		if end := conn.End(<-ended); end.Cause != "silence" {
			t.Fatalf("end=%+v, want silence", end)
		}
	})
}

// The stream source in awid reports raw reads: a heartbeat comment, which no
// consumer of events ever sees, keeps the connection from being silent.
func TestStreamPolicySilenceIsResetByAHeartbeatOnTheWire(t *testing.T) {
	writes := make(chan string)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher := w.(http.Flusher)
		flusher.Flush()
		for {
			select {
			case <-r.Context().Done():
				return
			case payload := <-writes:
				_, _ = io.WriteString(w, payload)
				flusher.Flush()
			}
		}
	}))
	t.Cleanup(server.Close)
	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}

	clock := manualclock.New(policyStart)
	policy := NewStreamPolicy(NewEventStreamOpener(client), nil, policyConfig(clock))
	confirmed := make(chan struct{}, 1)
	conn := policy.Connect(context.Background(), func(string) { confirmed <- struct{}{} })
	source, err := conn.Open()
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- consumeConnection(conn, source) }()
	awaitTimers(t, clock, 2)

	clock.Advance(74 * time.Second)
	writes <- ": keepalive\n\n"
	select {
	case <-confirmed:
	case <-time.After(5 * time.Second):
		t.Fatal("the heartbeat comment was not read")
	}
	clock.Advance(time.Second)
	awaitTimers(t, clock, 2)
	if conn.Context().Err() != nil {
		t.Fatal("closed one second after a heartbeat")
	}
	clock.Advance(74*time.Second - time.Nanosecond)
	if conn.Context().Err() != nil {
		t.Fatal("closed before 75 seconds had passed since the heartbeat")
	}
	clock.Advance(time.Nanosecond)
	if end := conn.End(<-ended); end.Kind != StreamEndTransient || end.Cause != "silence" {
		t.Fatalf("end=%+v, want silence 75 seconds after the heartbeat", end)
	}
}

// Section 4: a refused stream is quarantined.
func TestStreamPolicyQuarantine(t *testing.T) {
	t.Run("a refusal is reported once, on entry", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(401)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		first := attemptOnce(policy)
		if first.Kind != StreamEndRefused || first.Cause != "401" || !first.EnteredRefused {
			t.Fatalf("first refusal %+v", first)
		}
		for i := 0; i < 3; i++ {
			if again := attemptOnce(policy); again.Kind != StreamEndRefused || again.EnteredRefused {
				t.Fatalf("refused again %+v; want refused without a transition", again)
			}
		}
	})

	t.Run("a grant terminal event on an open stream quarantines it", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		source := newRawSource()
		opener := newScriptedOpener(clock, attemptOpens(source))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		conn := policy.Connect(context.Background(), nil)
		opened, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		ended := make(chan error, 1)
		go func() { ended <- consumeConnection(conn, opened) }()
		source.feed(rawItem{event: &awid.AgentEvent{Type: awid.AgentEventConnected}})
		source.feed(rawItem{err: &awid.AgentEventStreamClosedError{Event: "grant_revoked", Detail: "identity grant revoked"}})
		end := conn.End(<-ended)
		if end.Kind != StreamEndRefused || end.Cause != "grant_revoked" || !end.EnteredRefused || end.Wait != 30*time.Second {
			t.Fatalf("end=%+v, want a refusal by grant_revoked waiting from 1 minute", end)
		}
	})

	t.Run("the first confirmed stream ends it and names what it ended", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock,
			attemptFails(httpFailure(401)),
			attemptFails(httpFailure(403)),
			attemptOpens(newFakeEventSource()),
			attemptOpens(newFakeEventSource(confirmedEvent())),
			attemptFails(httpFailure(401)),
		)
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)
		attemptOnce(policy)
		if !policy.Refused() {
			t.Fatal("not refused after two refusals")
		}

		// An open that returns 200 and closes is not a confirmed stream.
		var ended []string
		unconfirmed := policy.Connect(context.Background(), func(cause string) { ended = append(ended, cause) })
		source, err := unconfirmed.Open()
		if err != nil {
			t.Fatal(err)
		}
		end := unconfirmed.End(consumeConnection(unconfirmed, source))
		if end.Kind != StreamEndRefused || end.EnteredRefused || end.Cause != "403" || end.Wait != 2*time.Minute {
			t.Fatalf("unconfirmed open in quarantine %+v; want still refused by 403, waiting half of 4 minutes", end)
		}
		if len(ended) != 0 || !policy.Refused() {
			t.Fatalf("quarantine ended by an unconfirmed open: %v", ended)
		}

		confirmed := policy.Connect(context.Background(), func(cause string) { ended = append(ended, cause) })
		source, err = confirmed.Open()
		if err != nil {
			t.Fatal(err)
		}
		end = confirmed.End(consumeConnection(confirmed, source))
		if len(ended) != 1 || ended[0] != "403" {
			t.Fatalf("confirmation reported the end of %v; want the last refusal, 403", ended)
		}
		if policy.Refused() {
			t.Fatal("still refused after a confirmed stream")
		}
		if end.Kind != StreamEndTransient || end.Wait != time.Second/2 {
			t.Fatalf("early end after the quarantine %+v; want transient from 1 second", end)
		}
		// Both ladders start over.
		if again := attemptOnce(policy); again.Kind != StreamEndRefused || !again.EnteredRefused || again.Wait != 30*time.Second {
			t.Fatalf("refusal after the quarantine ended %+v; want a transition waiting from 1 minute", again)
		}
	})

	t.Run("a confirmation outside a quarantine names none", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptOpens(newFakeEventSource(confirmedEvent())))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		var ended []string
		conn := policy.Connect(context.Background(), func(cause string) { ended = append(ended, cause) })
		source, err := conn.Open()
		if err != nil {
			t.Fatal(err)
		}
		conn.End(consumeConnection(conn, source))
		if len(ended) != 1 || ended[0] != "" {
			t.Fatalf("confirmation reported %q", ended)
		}
	})

	t.Run("a transient failure does not end it", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(401)), attemptFails(httpFailure(503)), attemptFails(io.EOF))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)
		for step, delay := range []time.Duration{2 * time.Minute, 4 * time.Minute} {
			end := attemptOnce(policy)
			if end.Kind != StreamEndRefused || end.EnteredRefused || end.Cause != "401" || end.Wait != delay/2 {
				t.Fatalf("step %d in quarantine %+v; want still refused by 401 at the quarantine pace", step, end)
			}
		}
	})

	t.Run("waits a minute by the clock", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		clock.SetRandom(almostOne)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(401)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		end := attemptOnce(policy)
		waited := make(chan bool, 1)
		go func() { waited <- policy.Wait(context.Background(), end) }()
		awaitTimers(t, clock, 1)
		clock.Advance(end.Wait - time.Nanosecond)
		select {
		case <-waited:
			t.Fatal("retried before the wait was over")
		case <-time.After(20 * time.Millisecond):
		}
		clock.Advance(time.Nanosecond)
		if !<-waited {
			t.Fatal("wait reported the stream stopped")
		}
	})

	t.Run("an explicit request retries at once and continues from 1 minute", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(401)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)
		attemptOnce(policy)
		end := attemptOnce(policy)
		if end.Wait != 2*time.Minute {
			t.Fatalf("third refusal waits %s, want half of 4 minutes", end.Wait)
		}
		waited := make(chan bool, 1)
		go func() { waited <- policy.Wait(context.Background(), end) }()
		awaitTimers(t, clock, 1)
		policy.Request()
		select {
		case ok := <-waited:
			if !ok {
				t.Fatal("wait reported the stream stopped")
			}
		case <-time.After(5 * time.Second):
			t.Fatal("an explicit request did not end the wait")
		}
		if clock.Timers() != 0 {
			t.Fatal("the wait's timer was left behind")
		}
		if again := attemptOnce(policy); again.Kind != StreamEndRefused || again.EnteredRefused || again.Wait != 30*time.Second {
			t.Fatalf("refused after an explicit request %+v; want the 1-minute delay and no transition", again)
		}
		if next := attemptOnce(policy); next.Wait != time.Minute {
			t.Fatalf("the following refusal waits %s, want half of 2 minutes", next.Wait)
		}
	})

	t.Run("a request made while an attempt is in flight is kept", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(401)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		attemptOnce(policy)
		policy.Request()
		end := attemptOnce(policy)
		if !policy.Wait(context.Background(), end) {
			t.Fatal("wait reported the stream stopped")
		}
		if clock.Timers() != 0 {
			t.Fatal("the wait's timer was left behind")
		}
	})

	t.Run("a request outside a quarantine changes nothing", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(503)), attemptFails(httpFailure(503)), attemptFails(httpFailure(401)))
		policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
		policy.Request()
		end := attemptOnce(policy)
		waited := make(chan bool, 1)
		go func() { waited <- policy.Wait(context.Background(), end) }()
		awaitTimers(t, clock, 1)
		policy.Request()
		select {
		case <-waited:
			t.Fatal("a request cut a transient wait short")
		case <-time.After(20 * time.Millisecond):
		}
		clock.Advance(end.Wait)
		<-waited
		attemptOnce(policy)
		// The earlier requests do not shorten a quarantine that starts later.
		refused := attemptOnce(policy)
		go func() { waited <- policy.Wait(context.Background(), refused) }()
		awaitTimers(t, clock, 1)
		select {
		case <-waited:
			t.Fatal("a request made before the quarantine ended its first wait")
		case <-time.After(20 * time.Millisecond):
		}
		clock.Advance(refused.Wait)
		<-waited
	})
}

// Section 4: before each retry of a refused stream the credentials are read
// again from where they are kept.
func TestStreamPolicyReloadsCredentialsBeforeEachRefusedRetry(t *testing.T) {
	t.Run("reloads before every retry in quarantine and not otherwise", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		var stored atomic.Value
		stored.Store("first")
		var used []string
		var reloads int
		openerWith := func(credential string) EventStreamOpener {
			return func(context.Context, time.Time) (awid.EventSource, error) {
				used = append(used, credential)
				switch credential {
				case "first":
					return nil, httpFailure(503)
				case "expired":
					return nil, httpFailure(401)
				default:
					return newFakeEventSource(confirmedEvent()), nil
				}
			}
		}
		reload := func() (EventStreamOpener, error) {
			reloads++
			return openerWith(stored.Load().(string)), nil
		}
		policy := NewStreamPolicy(openerWith("first"), reload, policyConfig(clock))

		// Transient failures retry with what the client holds.
		attemptOnce(policy)
		attemptOnce(policy)
		if reloads != 0 {
			t.Fatalf("reloaded %d times on transient failures", reloads)
		}

		policy = NewStreamPolicy(openerWith("expired"), reload, policyConfig(clock))
		used = nil
		attemptOnce(policy)
		stored.Store("expired")
		attemptOnce(policy)
		stored.Store("renewed")
		attemptOnce(policy)
		if reloads != 2 {
			t.Fatalf("reloaded %d times, want once before each of the two retries", reloads)
		}
		if want := []string{"expired", "expired", "renewed"}; fmt.Sprint(used) != fmt.Sprint(want) {
			t.Fatalf("attempts used %v, want %v", used, want)
		}
		if policy.Refused() {
			t.Fatal("still refused after the renewed credential was accepted")
		}
		// Streaming again: the next attempt does not reload.
		attemptOnce(policy)
		if reloads != 2 {
			t.Fatalf("reloaded %d times after the quarantine ended", reloads)
		}
	})

	t.Run("credentials that cannot be read fail the attempt without opening", func(t *testing.T) {
		clock := manualclock.New(policyStart)
		opener := newScriptedOpener(clock, attemptFails(httpFailure(401)))
		unreadable := errors.New("certificate unreadable")
		policy := NewStreamPolicy(opener.open, func() (EventStreamOpener, error) { return nil, unreadable }, policyConfig(clock))
		attemptOnce(policy)
		end := attemptOnce(policy)
		if opener.opens() != 1 {
			t.Fatalf("opened %d times; the retry must not go out with credentials that were not read again", opener.opens())
		}
		if end.Kind != StreamEndRefused || end.EnteredRefused || !errors.Is(end.Err, unreadable) || end.Wait != time.Minute {
			t.Fatalf("end=%+v, want still refused, at the quarantine pace, carrying the read error", end)
		}
	})
}

// Section 1: only the owner stops a stream.
func TestStreamPolicyStopsOnlyWhenItsOwnerDoes(t *testing.T) {
	clock := manualclock.New(policyStart)
	opener := newScriptedOpener(clock, attemptOpens(blockingEventSource{}))
	policy := NewStreamPolicy(opener.open, nil, policyConfig(clock))
	ctx, cancel := context.WithCancel(context.Background())
	conn := policy.Connect(ctx, nil)
	source, err := conn.Open()
	if err != nil {
		t.Fatal(err)
	}
	ended := make(chan error, 1)
	go func() { ended <- consumeConnection(conn, source) }()
	cancel()
	end := conn.End(<-ended)
	if end.Kind != StreamEndStopped {
		t.Fatalf("end=%+v, want stopped", end)
	}
	if policy.Wait(ctx, end) {
		t.Fatal("wait after the owner stopped asked for another attempt")
	}
	if clock.Timers() != 0 {
		t.Fatalf("%d timers left after the owner stopped", clock.Timers())
	}

	refused := attemptOnce(NewStreamPolicy(newScriptedOpener(clock, attemptFails(httpFailure(401))).open, nil, policyConfig(clock)))
	stopped, stop := context.WithCancel(context.Background())
	stop()
	if policy.Wait(stopped, refused) {
		t.Fatal("wait went on after its owner stopped")
	}
}

// The defaults are the real clock, timer and random source.
func TestStreamPolicyDefaults(t *testing.T) {
	policy := NewStreamPolicy(EventStreamOpener(attemptFails(httpFailure(503))), nil, StreamPolicyConfig{})
	before := time.Now()
	end := attemptOnce(policy)
	if end.Wait < time.Second/2 || end.Wait > time.Second {
		t.Fatalf("wait=%s, want between half a second and a second", end.Wait)
	}
	if end.NextAttempt.Before(before.Add(end.Wait)) {
		t.Fatalf("next attempt %s is before now plus the wait", end.NextAttempt)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if policy.Wait(ctx, end) {
		t.Fatal("wait went on after its owner stopped")
	}
}
