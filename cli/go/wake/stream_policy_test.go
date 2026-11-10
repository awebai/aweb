package wake

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/manualclock"
	"github.com/awebai/aw/internal/streamtest"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

// The broker's streams on the event stream client policy
// (docs/event-stream-client-policy.md), with a clock the tests advance.

var streamPolicyStart = time.Date(2026, 3, 1, 12, 0, 0, 0, time.UTC)

// policyBroker starts a broker whose streams run on clock and open through
// openStream, and registers one home with it.
func policyBroker(t *testing.T, clock *manualclock.Clock, openStream func(ctx context.Context, identityHome, teamID string) (run.EventStreamOpener, error)) (*Broker, *logCapture, Registration) {
	t.Helper()
	store := tempStore(t)
	home := tempHome(t, "instance")
	logs := &logCapture{}
	broker, _ := liveBroker(t, Config{
		Store:        store,
		Session:      session.NewFake(session.Inspection{Home: home, Present: true, State: session.StateIdle, RawState: "idle"}),
		Log:          logs.log,
		StreamPolicy: run.StreamPolicyConfig{Now: clock.Now, Timer: clock.Timer, Rand: clock.Random},
		OpenStream:   openStream,
	})
	reg := Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession}
	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	return broker, logs, reg
}

func sameOpener(opener *streamtest.Opener) func(context.Context, string, string) (run.EventStreamOpener, error) {
	return func(context.Context, string, string) (run.EventStreamOpener, error) { return opener.Open, nil }
}

// awaitStreamRetryWait waits for the one stream to be sleeping before a
// retry. started is how many timers it has started by then: one for each
// connection's planned close, one for the silence watch of each connection
// that opened, and one for each wait between attempts.
func awaitStreamRetryWait(t *testing.T, clock *manualclock.Clock, started int) time.Duration {
	t.Helper()
	if !clock.AwaitStarted(started, 1) {
		t.Fatalf("timers started=%d waiting=%d, want %d started and the retry wait running", clock.Started(), clock.Timers(), started)
	}
	wait, _ := clock.NextTimer()
	return wait
}

func onlyStream(t *testing.T, broker *Broker) StreamStatus {
	t.Helper()
	streams := broker.Status().Streams
	if len(streams) != 1 {
		t.Fatalf("streams=%+v, want one", streams)
	}
	return streams[0]
}

func onlyInstance(t *testing.T, broker *Broker) InstanceStatus {
	t.Helper()
	instances := broker.Status().Instances
	if len(instances) != 1 || len(instances[0].ReceiveIdentities) != 1 {
		t.Fatalf("instances=%+v, want one with one receive identity", instances)
	}
	return instances[0]
}

func countLines(logs *logCapture, text string) int {
	return strings.Count(logs.all(), text)
}

// The defect the policy exists for: one 401, for example while the host clock
// was briefly wrong, left the stream stopped until the daemon restarted while
// the broker went on reporting the identity as admitted. A refused stream is
// reported as refused, with the status and the next attempt, never as
// admitted; a later attempt succeeds and it is streaming again (§1, §4, §8).
func TestRefusedStreamIsReportedRefusedAndRecovers(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	source := streamtest.NewSource()
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(streamtest.HTTPFailure(401)), streamtest.Opens(source))
	broker, logs, _ := policyBroker(t, clock, sameOpener(opener))

	if wait := awaitStreamRetryWait(t, clock, 2); wait != 30*time.Second {
		t.Fatalf("retry in %s after a 401, want half of the 1-minute delay", wait)
	}
	nextAttempt := streamPolicyStart.Add(30 * time.Second)
	stream := onlyStream(t, broker)
	if stream.Phase != string(StreamRefused) || stream.Cause != "401" || !stream.NextAttemptAt.Equal(nextAttempt) {
		t.Fatalf("stream %+v, want refused by 401 with the next attempt at %s", stream, nextAttempt)
	}
	if stream.Admitted {
		t.Fatal("a refused identity is shown as admitted")
	}
	if stream.LastErrorDetail == nil || stream.LastErrorDetail.HTTPStatus != 401 {
		t.Fatalf("refused stream error detail %+v", stream.LastErrorDetail)
	}
	instance := onlyInstance(t, broker)
	receive := instance.ReceiveIdentities[0]
	if receive.StreamAdmitted || instance.StreamAdmitted {
		t.Fatalf("registration shows a refused identity as admitted: instance=%t receive=%t", instance.StreamAdmitted, receive.StreamAdmitted)
	}
	if receive.StreamPhase != string(StreamRefused) || receive.StreamCause != "401" || !receive.StreamNextAttemptAt.Equal(nextAttempt) {
		t.Fatalf("receive identity %+v, want refused by 401 with the next attempt", receive)
	}
	binding := ReceiveIdentity{IdentityHome: receive.IdentityHome, TeamID: receive.TeamID}
	if broker.ensureStream(binding) {
		t.Fatal("ensureStream reports a refused identity as admitted")
	}
	runner, ok := broker.instanceRunner(instance.Home)
	if !ok {
		t.Fatal("no runner for the registered home")
	}
	waitFor(t, "the registration to stop counting the stream as admitted", func() bool { return !runner.allStreamsAdmitted() })

	clock.Advance(30 * time.Second)
	waitFor(t, "the retry", func() bool { return opener.Opens() == 2 })
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected})

	stream = onlyStream(t, broker)
	if stream.Phase != string(StreamLive) || !stream.Admitted || stream.Cause != "" || !stream.NextAttemptAt.IsZero() || stream.LastError != "" {
		t.Fatalf("stream after a confirmed attempt %+v, want streaming and admitted", stream)
	}
	if !broker.ensureStream(binding) {
		t.Fatal("ensureStream does not report a streaming identity as admitted")
	}
	waitFor(t, "the registration to count the stream as admitted", func() bool {
		instance := onlyInstance(t, broker)
		return instance.StreamAdmitted && instance.ReceiveIdentities[0].StreamAdmitted && runner.allStreamsAdmitted()
	})
	if entered, left := countLines(logs, "stream quarantined "), countLines(logs, "stream quarantine ended "); entered != 1 || left != 1 {
		t.Fatalf("quarantine logged %d times on entry and %d on exit, want once each:\n%s", entered, left, logs.all())
	}
	if !strings.Contains(logs.all(), "stream quarantined identity_home="+receive.IdentityHome+" cause=401 next_attempt="+nextAttempt.Format(time.RFC3339)) {
		t.Fatalf("the quarantine was not logged with its cause and next attempt:\n%s", logs.all())
	}
}

// refused is reported once per transition: several refused retries log one
// entry, move the next attempt in status without a word, and one exit (§8).
func TestRefusedRetriesAreReportedOncePerTransition(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	source := streamtest.NewSource()
	refused := streamtest.Fails(streamtest.HTTPFailure(403))
	opener := streamtest.NewOpener(clock.Now, refused, refused, streamtest.Fails(streamtest.HTTPFailure(503)), refused, streamtest.Opens(source))
	broker, logs, _ := policyBroker(t, clock, sameOpener(opener))

	// The lowest draw is half of each delay: 1, 2, 4 and 8 minutes.
	elapsed := time.Duration(0)
	for attempt, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute} {
		wait := awaitStreamRetryWait(t, clock, 2*(attempt+1))
		if wait != want {
			t.Fatalf("attempt %d: retry in %s, want %s", attempt+1, wait, want)
		}
		stream := onlyStream(t, broker)
		if stream.Phase != string(StreamRefused) || stream.Admitted || stream.Cause != "403" {
			t.Fatalf("attempt %d: stream %+v, want refused by 403", attempt+1, stream)
		}
		if next := streamPolicyStart.Add(elapsed + wait); !stream.NextAttemptAt.Equal(next) {
			t.Fatalf("attempt %d: next attempt %s, want %s", attempt+1, stream.NextAttemptAt, next)
		}
		clock.Advance(wait)
		elapsed += wait
		waitFor(t, "the next attempt", func() bool { return opener.Opens() == attempt+2 })
	}
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected})
	if stream := onlyStream(t, broker); stream.Phase != string(StreamLive) || !stream.Admitted {
		t.Fatalf("stream %+v, want streaming", stream)
	}
	if entered, left := countLines(logs, "stream quarantined "), countLines(logs, "stream quarantine ended "); entered != 1 || left != 1 {
		t.Fatalf("quarantine logged %d times on entry and %d on exit across four refused attempts, want once each:\n%s", entered, left, logs.all())
	}
	if strings.Contains(logs.all(), "stream outage") {
		t.Fatalf("a failure inside the quarantine was reported as an outage:\n%s", logs.all())
	}
}

// An explicit request for the stream — a registration — retries a quarantined
// stream at once and, if refused again, continues from the 1-minute delay.
// The broker's own reconcile pass is not a request (§4).
func TestRegistrationRetriesARefusedStreamAtOnce(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(streamtest.HTTPFailure(401)))
	broker, logs, reg := policyBroker(t, clock, sameOpener(opener))

	clock.Advance(awaitStreamRetryWait(t, clock, 2))
	if wait := awaitStreamRetryWait(t, clock, 4); wait != time.Minute {
		t.Fatalf("second refusal waits %s, want half of 2 minutes", wait)
	}

	// Several reconcile passes go by; each calls ensureStream for the binding.
	binding := ReceiveIdentity{IdentityHome: onlyInstance(t, broker).ReceiveIdentities[0].IdentityHome, TeamID: onlyInstance(t, broker).ReceiveIdentities[0].TeamID}
	time.Sleep(100 * time.Millisecond)
	broker.ensureStream(binding)
	time.Sleep(20 * time.Millisecond)
	if opener.Opens() != 2 || clock.Started() != 4 {
		t.Fatalf("opens=%d timers started=%d: a reconcile pass retried a quarantined stream", opener.Opens(), clock.Started())
	}

	if err := broker.Register(reg); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the retry a registration asks for", func() bool { return opener.Opens() == 3 })
	if at := opener.OpenTimes()[2]; !at.Equal(clock.Now()) {
		t.Fatalf("retried at %s; the clock has not moved from %s", at, clock.Now())
	}
	if wait := awaitStreamRetryWait(t, clock, 6); wait != 30*time.Second {
		t.Fatalf("refused again after a registration: retry in %s, want half of the 1-minute delay", wait)
	}
	if stream := onlyStream(t, broker); stream.Phase != string(StreamRefused) || stream.Admitted || !stream.NextAttemptAt.Equal(clock.Now().Add(30*time.Second)) {
		t.Fatalf("stream %+v, want still refused with the next attempt half a minute on", stream)
	}
	if entered := countLines(logs, "stream quarantined "); entered != 1 {
		t.Fatalf("quarantine logged %d times, want once:\n%s", entered, logs.all())
	}
}

// Before each retry of a refused stream the broker reads the identity's
// credentials again from its home, through OpenStream (§4).
func TestRefusedStreamReadsCredentialsAgainBeforeEachRetry(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	source := streamtest.NewSource()
	var mu sync.Mutex
	stored := "expired"
	var read, used []string
	openStream := func(_ context.Context, identityHome, teamID string) (run.EventStreamOpener, error) {
		mu.Lock()
		defer mu.Unlock()
		credential := stored
		read = append(read, credential)
		return func(context.Context, time.Time) (awid.EventSource, error) {
			mu.Lock()
			used = append(used, credential)
			mu.Unlock()
			if credential != "renewed" {
				return nil, streamtest.HTTPFailure(401)
			}
			return source, nil
		}, nil
	}
	attempts := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(used)
	}
	broker, _, _ := policyBroker(t, clock, openStream)

	clock.Advance(awaitStreamRetryWait(t, clock, 2))
	waitFor(t, "the second attempt", func() bool { return attempts() == 2 })
	mu.Lock()
	stored = "renewed"
	mu.Unlock()
	clock.Advance(awaitStreamRetryWait(t, clock, 4))
	waitFor(t, "the third attempt", func() bool { return attempts() == 3 })
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected})
	if stream := onlyStream(t, broker); stream.Phase != string(StreamLive) {
		t.Fatalf("stream %+v, want streaming with the renewed credential", stream)
	}

	mu.Lock()
	defer mu.Unlock()
	want := []string{"expired", "expired", "renewed"}
	if fmt.Sprint(used) != fmt.Sprint(want) {
		t.Fatalf("attempts used %v, want %v", used, want)
	}
	if fmt.Sprint(read) != fmt.Sprint(want) {
		t.Fatalf("credentials read %v, want once at registration and once before each retry: %v", read, want)
	}
}

// A rate limit is a moment, not a refusal: the stream is retrying, still
// admitted, waits at least Retry-After, and streams again (§3).
func TestRateLimitedStreamRetriesAndStreams(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	source := streamtest.NewSource()
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(streamtest.HTTPFailureRetryAfter(429, "20")), streamtest.Opens(source))
	broker, logs, _ := policyBroker(t, clock, sameOpener(opener))

	wait := awaitStreamRetryWait(t, clock, 2)
	if wait != 20*time.Second+time.Second/2 {
		t.Fatalf("retry in %s, want Retry-After plus the jittered delay", wait)
	}
	stream := onlyStream(t, broker)
	if stream.Phase != string(StreamRetrying) || !stream.Admitted || stream.Cause != "429" || !stream.NextAttemptAt.Equal(streamPolicyStart.Add(wait)) {
		t.Fatalf("stream %+v, want retrying after a 429 and still admitted", stream)
	}
	clock.Advance(wait)
	waitFor(t, "the retry", func() bool { return opener.Opens() == 2 })
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected})
	if stream := onlyStream(t, broker); stream.Phase != string(StreamLive) || !stream.Admitted || !stream.NextAttemptAt.IsZero() {
		t.Fatalf("stream %+v, want streaming", stream)
	}
	if strings.Contains(logs.all(), "stream quarantined") {
		t.Fatalf("a rate limit quarantined the stream:\n%s", logs.all())
	}
	if outages, recoveries := countLines(logs, "stream outage "), countLines(logs, "stream reconnected "); outages != 1 || recoveries != 1 {
		t.Fatalf("outage logged %d times and recovery %d, want once each:\n%s", outages, recoveries, logs.all())
	}
}

// A grant terminal event on an open stream is a refusal, reported by the
// event's name; a stream that goes silent for 75 seconds is retried (§4, §6).
func TestOpenStreamEndsAreClassified(t *testing.T) {
	t.Run("grant terminal event", func(t *testing.T) {
		clock := manualclock.New(streamPolicyStart)
		source := streamtest.NewSource()
		opener := streamtest.NewOpener(clock.Now, streamtest.Opens(source), streamtest.Fails(streamtest.HTTPFailure(403)))
		broker, _, _ := policyBroker(t, clock, sameOpener(opener))
		waitFor(t, "the stream to open", func() bool { return opener.Opens() == 1 })
		source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected})
		source.Feed(streamtest.Item{Err: &awid.AgentEventStreamClosedError{Event: "grant_revoked", Detail: "identity grant revoked"}})

		// Planned close, silence watch, and the wait after the refusal.
		if wait := awaitStreamRetryWait(t, clock, 3); wait != 30*time.Second {
			t.Fatalf("retry in %s, want half of the 1-minute delay", wait)
		}
		if stream := onlyStream(t, broker); stream.Phase != string(StreamRefused) || stream.Admitted || stream.Cause != "grant_revoked" {
			t.Fatalf("stream %+v, want refused by grant_revoked", stream)
		}
	})

	t.Run("silence", func(t *testing.T) {
		clock := manualclock.New(streamPolicyStart)
		source := streamtest.NewSource()
		opener := streamtest.NewOpener(clock.Now, streamtest.Opens(source), streamtest.Opens(streamtest.NewSource()))
		broker, _, _ := policyBroker(t, clock, sameOpener(opener))
		waitFor(t, "the stream to open", func() bool { return opener.Opens() == 1 })
		source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected})
		if !clock.AwaitTimers(2) {
			t.Fatal("the stream is not watched for silence")
		}
		clock.Advance(60 * time.Second)
		source.Feed(streamtest.Item{Comment: true})
		clock.Advance(15 * time.Second)
		// 75 seconds after opening, 15 after a heartbeat: the watch goes on.
		if !clock.AwaitStarted(3, 2) {
			t.Fatal("the silence watch did not wait out the rest of its 75 seconds")
		}
		if stream := onlyStream(t, broker); stream.Phase != string(StreamLive) {
			t.Fatalf("stream %+v 15 seconds after a heartbeat, want streaming", stream)
		}
		clock.Advance(60 * time.Second)
		if wait := awaitStreamRetryWait(t, clock, 4); wait != time.Second/2 {
			t.Fatalf("retry in %s after silence, want the transient delay", wait)
		}
		if stream := onlyStream(t, broker); stream.Phase != string(StreamRetrying) || stream.Cause != "silence" || !stream.Admitted {
			t.Fatalf("stream %+v, want retrying after silence", stream)
		}
	})
}

// Stopping a stream does not wait for its credentials to be read again: the
// reload is given the stream's context and ends with it.
func TestStreamStopDoesNotWaitOnAReload(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	opener := streamtest.NewOpener(clock.Now, streamtest.Fails(streamtest.HTTPFailure(401)))
	entered := make(chan struct{})
	reload := func(ctx context.Context) (run.EventStreamOpener, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	stream := newStreamRunner("key", "/identity", "team", opener.Open, reload, func(awid.AgentEvent) {}, func(string, ...any) {}, clock.Now, run.StreamPolicyConfig{Timer: clock.Timer, Rand: clock.Random})
	stream.start(context.Background())
	clock.Advance(awaitStreamRetryWait(t, clock, 2))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the refused retry did not read the credentials again")
	}

	stopped := make(chan struct{})
	go func() {
		stream.stop()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("stopping the stream waited on the reload")
	}
	if opener.Opens() != 1 {
		t.Fatalf("opened %d times; the stopped attempt must not go out", opener.Opens())
	}
}

// The broker hands OpenStream the stream's context when it reads the
// credentials again, so a daemon shutting down does not wait on it.
func TestBrokerReloadsThroughOpenStreamWithTheStreamContext(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	var mu sync.Mutex
	calls := 0
	entered := make(chan struct{})
	ended := make(chan error, 1)
	openStream := func(ctx context.Context, identityHome, teamID string) (run.EventStreamOpener, error) {
		mu.Lock()
		calls++
		first := calls == 1
		mu.Unlock()
		if first {
			return func(context.Context, time.Time) (awid.EventSource, error) { return nil, streamtest.HTTPFailure(401) }, nil
		}
		close(entered)
		<-ctx.Done()
		ended <- ctx.Err()
		return nil, ctx.Err()
	}
	store := tempStore(t)
	home := tempHome(t, "instance")
	broker, cancel := liveBroker(t, Config{
		Store:        store,
		Session:      session.NewFake(session.Inspection{Home: home, Present: true, State: session.StateIdle, RawState: "idle"}),
		StreamPolicy: run.StreamPolicyConfig{Now: clock.Now, Timer: clock.Timer, Rand: clock.Random},
		OpenStream:   openStream,
	})
	if err := broker.Register(Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}
	clock.Advance(awaitStreamRetryWait(t, clock, 2))
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("the refused retry did not call OpenStream again")
	}
	cancel()
	select {
	case err := <-ended:
		if err == nil {
			t.Fatal("the reload's context was not cancelled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutting the broker down did not end the reload")
	}
}

// The flap as today's server produces it: heartbeat, the opening connected
// event, then a grant terminal event, every time. The connected event
// confirms the stream but does not return the refused delay to 1 minute.
func TestStreamFlapWithTheConnectedEventGrowsTheRefusedDelay(t *testing.T) {
	clock := manualclock.New(streamPolicyStart)
	sources := make(chan *streamtest.Source, 1)
	open := func(context.Context, time.Time) (awid.EventSource, error) {
		source := streamtest.NewSource()
		sources <- source
		return source, nil
	}
	broker, _, _ := policyBroker(t, clock, func(context.Context, string, string) (run.EventStreamOpener, error) { return open, nil })

	revoked := streamtest.Item{Err: &awid.AgentEventStreamClosedError{Event: "grant_revoked", Detail: "identity grant revoked"}}
	started := 0
	for cycle, want := range []time.Duration{30 * time.Second, time.Minute, 2 * time.Minute, 4 * time.Minute, 7*time.Minute + 30*time.Second, 7*time.Minute + 30*time.Second} {
		source := <-sources
		source.Feed(streamtest.Item{Comment: true})
		source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected, AgentID: "a"})
		if stream := onlyStream(t, broker); stream.Phase != string(StreamLive) || !stream.Admitted {
			t.Fatalf("cycle %d: stream %+v after the connected event, want streaming", cycle, stream)
		}
		source.Feed(revoked)
		// Planned close, silence watch, and the wait after the refusal.
		started += 3
		wait := awaitStreamRetryWait(t, clock, started)
		if wait != want {
			t.Fatalf("cycle %d: retry in %s, want %s", cycle, wait, want)
		}
		clock.Advance(wait)
	}

	// Any other event is the server serving this caller: the delay starts over.
	source := <-sources
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventConnected, AgentID: "a"})
	source.FeedEvent(awid.AgentEvent{Type: awid.AgentEventWorkAvailable, TaskID: "t1", Title: "x"})
	source.Feed(revoked)
	if wait := awaitStreamRetryWait(t, clock, started+3); wait != 30*time.Second {
		t.Fatalf("refused after a work event: retry in %s, want half of 1 minute", wait)
	}
}
