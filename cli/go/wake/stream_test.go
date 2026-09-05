package wake

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
	"github.com/awebai/aw/run"
	"github.com/awebai/aw/wake/session"
)

// recordingServer is a stand-in aweb server that serves the event stream and
// records the path of every request it receives.
type recordingServer struct {
	*httptest.Server

	mu     sync.Mutex
	paths  []string
	opens  int
	events []string
	status int
}

func newRecordingServer(t *testing.T, events ...string) *recordingServer {
	t.Helper()
	rs := &recordingServer{events: events, status: http.StatusOK}
	rs.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rs.mu.Lock()
		rs.paths = append(rs.paths, r.URL.Path)
		status := rs.status
		payloads := append([]string(nil), rs.events...)
		if r.URL.Path == "/v1/events/stream" {
			rs.opens++
		}
		rs.mu.Unlock()

		if r.URL.Path != "/v1/events/stream" {
			http.Error(w, "unexpected request", http.StatusNotFound)
			return
		}
		if status != http.StatusOK {
			http.Error(w, "refused", status)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		flusher, _ := w.(http.Flusher)
		for _, payload := range payloads {
			fmt.Fprint(w, payload)
			if flusher != nil {
				flusher.Flush()
			}
		}
		// Hold the connection until the broker's own deadline closes it, the
		// way a real stream does inside the server's five-minute cap.
		<-r.Context().Done()
	}))
	t.Cleanup(rs.Close)
	return rs
}

func (rs *recordingServer) seenPaths() []string {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return append([]string(nil), rs.paths...)
}

func (rs *recordingServer) openCount() int {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.opens
}

func sseEvent(name, data string) string {
	return "event: " + name + "\ndata: " + data + "\n\n"
}

func openerFor(t *testing.T, baseURL string) run.EventStreamOpener {
	t.Helper()
	client, err := awid.New(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return run.NewEventStreamOpener(client)
}

// liveBroker starts a real broker with real goroutines and short timings.
func liveBroker(t *testing.T, cfg Config) (*Broker, context.CancelFunc) {
	t.Helper()
	if cfg.Coalesce == 0 {
		cfg.Coalesce = 20 * time.Millisecond
	}
	if cfg.RateLimit == 0 {
		cfg.RateLimit = 50 * time.Millisecond
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 10 * time.Millisecond
	}
	if cfg.IdleProbe == 0 {
		cfg.IdleProbe = 50 * time.Millisecond
	}
	if cfg.Reconcile == 0 {
		cfg.Reconcile = 20 * time.Millisecond
	}
	broker, err := NewBroker(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = broker.Run(ctx)
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("broker did not shut down")
		}
	})
	return broker, cancel
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestBrokerNeverAcknowledgesAnything is the §6 prohibition proved at the wire.
//
// A real client streams from a stand-in server which records every request path
// it sees. A mail event arrives, the broker types a wake — and the server has
// still seen nothing but the event stream: no inbox fetch, no ack, no chat read
// mark. Asserting the *whole* request set rather than the absence of one path
// is what makes this hold against a future addition nobody thought to forbid.
func TestBrokerNeverAcknowledgesAnything(t *testing.T) {
	server := newRecordingServer(t,
		sseEvent("actionable_mail", `{"message_id":"m1","conversation_id":"conv-1","from_alias":"alice","subject":"secret","unread_count":3}`),
		sseEvent("actionable_chat", `{"message_id":"c1","session_id":"s1","from_alias":"bob","sender_waiting":true}`),
	)
	store := tempStore(t)
	home := tempHome(t, "instance")
	oats := session.NewFake(session.Inspection{Home: home, Backend: "tmux", Present: true, State: session.StateUnknown, RawState: "unknown"})
	logs := &logCapture{}

	broker, _ := liveBroker(t, Config{
		Store:   store,
		Session: oats,
		Log:     logs.log,
		// A window wide enough that two events arriving together are one wake,
		// which is the behaviour under test.
		Coalesce: 250 * time.Millisecond,
		OpenStream: func(identityHome string) (run.EventStreamOpener, error) {
			return openerFor(t, server.URL), nil
		},
	})
	if err := broker.Register(Registration{
		Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession, Backend: "tmux",
	}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "a wake to be typed", func() bool { return len(oats.Submissions()) > 0 })

	text := oats.Submissions()[0].Text
	if strings.Contains(text, "secret") {
		t.Fatalf("a subject reached the terminal:\n%s", text)
	}
	if !strings.Contains(text, "mail from alice") || !strings.Contains(text, "chat from bob — sender waiting") {
		t.Fatalf("the wake did not summarise what arrived:\n%s", text)
	}

	for _, path := range server.seenPaths() {
		if path != "/v1/events/stream" {
			t.Fatalf("the broker called %s; it streams and nothing else — no fetch, no ack, no read mark", path)
		}
	}

	// The identity's unread count is reported so a backlog is visible.
	waitFor(t, "the unread count to reach status", func() bool {
		for _, stream := range broker.Status().Streams {
			if stream.UnreadCount == 3 {
				return true
			}
		}
		return false
	})
}

// TestPlannedCloseIsNotReportedAsAnOutage: the broker closes at its own TTL
// inside the server's cap, so the close is never a server EOF it has to
// classify, and the reopen must not look like a recovery.
func TestPlannedCloseIsNotReportedAsAnOutage(t *testing.T) {
	server := newRecordingServer(t, sseEvent("work_available", `{"task_id":"t1","title":"x"}`))
	store := tempStore(t)
	home := tempHome(t, "instance")
	logs := &logCapture{}

	broker, _ := liveBroker(t, Config{
		Store:     store,
		Session:   session.NewFake(session.Inspection{Home: home, Present: true, State: session.StateBusy, RawState: "working"}),
		Log:       logs.log,
		StreamTTL: 80 * time.Millisecond,
		OpenStream: func(string) (run.EventStreamOpener, error) {
			return openerFor(t, server.URL), nil
		},
	})
	if err := broker.Register(Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the stream to be reopened after its planned close", func() bool { return server.openCount() >= 3 })
	captured := logs.all()
	if strings.Contains(captured, "stream outage") || strings.Contains(captured, "stream reconnected") {
		t.Fatalf("a planned close was reported as an outage:\n%s", captured)
	}
	if DefaultStreamTTL != 4*time.Minute {
		t.Fatalf("DefaultStreamTTL=%s; the note fixes four minutes inside the server's five-minute cap", DefaultStreamTTL)
	}
}

// TestFourXXQuarantinesOneIdentityAndLeavesOthersStreaming (§4).
func TestFourXXQuarantinesOneIdentityAndLeavesOthersStreaming(t *testing.T) {
	good := newRecordingServer(t, sseEvent("actionable_mail", `{"message_id":"m1","from_alias":"alice"}`))
	bad := newRecordingServer(t)
	bad.mu.Lock()
	bad.status = http.StatusUnauthorized
	bad.mu.Unlock()

	store := tempStore(t)
	goodHome := tempHome(t, "good")
	badHome := tempHome(t, "bad")
	oats := session.NewFake(session.Inspection{Present: true, State: session.StateIdle, RawState: "idle"})
	logs := &logCapture{}

	broker, _ := liveBroker(t, Config{
		Store:   store,
		Session: oats,
		Log:     logs.log,
		OpenStream: func(identityHome string) (run.EventStreamOpener, error) {
			if strings.HasPrefix(identityHome, badHome) {
				return openerFor(t, bad.URL), nil
			}
			return openerFor(t, good.URL), nil
		},
	})
	for _, home := range []string{goodHome, badHome} {
		if err := broker.Register(Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession}); err != nil {
			t.Fatal(err)
		}
	}

	waitFor(t, "one identity to be quarantined and the other to stream", func() bool {
		quarantined, streaming := false, false
		for _, stream := range broker.Status().Streams {
			if strings.HasPrefix(stream.IdentityHome, badHome) && stream.Phase == string(StreamQuarantined) {
				quarantined = true
			}
			if strings.HasPrefix(stream.IdentityHome, goodHome) && stream.Phase == string(StreamLive) {
				streaming = true
			}
		}
		return quarantined && streaming
	})
	if !strings.Contains(logs.all(), "stream quarantined") {
		t.Fatalf("the quarantine was not reported:\n%s", logs.all())
	}
	// The daemon is still serving: the healthy identity still gets its wake.
	waitFor(t, "the healthy identity to be woken", func() bool { return len(oats.Submissions()) > 0 })
}

// TestReconnectAfterAnOutageRaisesOneCatchUpHint (§6): on recovery the snapshot
// supplies what was missed and the synthesized channel_reconnected produces one
// catch-up hint, not one per message.
func TestReconnectAfterAnOutageRaisesOneCatchUpHint(t *testing.T) {
	var mu sync.Mutex
	fail := true
	opens := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		opens++
		shouldFail := fail
		mu.Unlock()
		if shouldFail {
			// A transport-level failure, not a 4xx: retried, not quarantined.
			hj, ok := w.(http.Hijacker)
			if ok {
				conn, _, err := hj.Hijack()
				if err == nil {
					_ = conn.Close()
					return
				}
			}
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, sseEvent("actionable_mail", `{"message_id":"m1","from_alias":"alice"}`))
		if flusher, ok := w.(http.Flusher); ok {
			flusher.Flush()
		}
		<-r.Context().Done()
	}))
	t.Cleanup(server.Close)

	store := tempStore(t)
	home := tempHome(t, "instance")
	oats := session.NewFake(session.Inspection{Home: home, Present: true, State: session.StateIdle, RawState: "idle"})
	logs := &logCapture{}

	broker, _ := liveBroker(t, Config{
		Store:      store,
		Session:    oats,
		Log:        logs.log,
		BackoffMin: 10 * time.Millisecond,
		BackoffMax: 20 * time.Millisecond,
		OpenStream: func(string) (run.EventStreamOpener, error) { return openerFor(t, server.URL), nil },
	})
	if err := broker.Register(Registration{Home: home, IdentityHome: home + "/.aw", Delivery: DeliverySession}); err != nil {
		t.Fatal(err)
	}

	waitFor(t, "the outage to be reported", func() bool { return strings.Contains(logs.all(), "stream outage") })
	mu.Lock()
	fail = false
	mu.Unlock()

	waitFor(t, "the stream to recover", func() bool { return strings.Contains(logs.all(), "stream reconnected") })
	waitFor(t, "a wake after recovery", func() bool { return len(oats.Submissions()) > 0 })

	text := oats.Submissions()[0].Text
	if !strings.Contains(text, "reconnected — earlier items may still be unread") {
		t.Fatalf("the catch-up hint is missing:\n%s", text)
	}
	if strings.Count(text, "reconnected") != 1 {
		t.Fatalf("more than one catch-up hint per recovery:\n%s", text)
	}
	// The daemon survived the outage rather than stopping on it.
	if !broker.Status().DaemonRunning {
		t.Fatal("an outage stopped the daemon")
	}
}
