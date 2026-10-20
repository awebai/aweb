package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// An events subscription is made of several streams: the server closes every
// stream at its duration cap (MAX_STREAM_DURATION in
// server/src/aweb/routes/events.py), and a proxy may cut one sooner. These tests
// pin that `aw events stream` keeps the subscription across those ends, without
// repeating what it already printed and without hammering a failing server.

const connectedPreamble = "event: connected\ndata: {\"agent_id\":\"a-1\",\"team_id\":\"backend:acme.com\"}\n\n"

func mailEvent(messageID, subject string) string {
	return fmt.Sprintf("event: actionable_mail\ndata: {\"message_id\":%q,\"from_alias\":\"alice\",\"subject\":%q}\n\n", messageID, subject)
}

// abruptlyCloseStream writes an SSE prologue and then kills the TCP connection
// without a terminating chunk, which reaches the client as "unexpected EOF". A
// handler that simply returns ends the chunked body cleanly instead.
func abruptlyCloseStream(t *testing.T, w http.ResponseWriter, events ...string) {
	t.Helper()
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		t.Fatal("test server does not support hijacking, so an abrupt close cannot be reproduced")
	}
	conn, buf, err := hijacker.Hijack()
	if err != nil {
		t.Fatalf("hijack: %v", err)
	}
	fmt.Fprintf(buf, "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nTransfer-Encoding: chunked\r\n\r\n")
	for _, ev := range events {
		fmt.Fprintf(buf, "%x\r\n%s\r\n", len(ev), ev)
	}
	_ = buf.Flush()
	// No terminating "0\r\n\r\n": the body is left incomplete on purpose.
	_ = conn.Close()
}

// serveStream writes events on an open stream and then ends it cleanly, the way
// the server ends a stream at its duration cap.
func serveStream(t *testing.T, w http.ResponseWriter, events ...string) {
	t.Helper()
	flusher, ok := w.(http.Flusher)
	if !ok {
		t.Fatal("no flusher")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	for _, ev := range events {
		fmt.Fprint(w, ev)
		flusher.Flush()
	}
}

func eventsTestServer(t *testing.T, stream func(open int64, w http.ResponseWriter, r *http.Request)) (*atomic.Int64, string) {
	t.Helper()
	var opens atomic.Int64
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			requireCertificateAuthForTest(t, r)
			stream(opens.Add(1), w, r)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))
	return &opens, server.URL
}

func buildAwForTest(t *testing.T, ctx context.Context, tmp string) string {
	t.Helper()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	return bin
}

// runEventsStream runs `aw events stream --json` for timeoutSeconds against
// serverURL, with extraEnv added, and returns its combined output and exit error.
func runEventsStream(t *testing.T, serverURL string, timeoutSeconds int, extraEnv ...string) (string, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutSeconds+60)*time.Second)
	defer cancel()
	tmp := t.TempDir()
	bin := buildAwForTest(t, ctx, tmp)
	writeDefaultWorkspaceBindingForTest(t, tmp, serverURL)
	run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", fmt.Sprint(timeoutSeconds))
	run.Env = append(testCommandEnv(tmp), extraEnv...)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	return string(out), err
}

func decodeEventLines(output string) []map[string]any {
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &ev); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

func countMessage(events []map[string]any, messageID string) int {
	n := 0
	for _, ev := range events {
		if ev["message_id"] == messageID {
			n++
		}
	}
	return n
}

// A stream cut mid-chunk by the server or a proxy is a reconnect, not an error,
// and the reconnected stream delivers what the cut one never carried.
func TestEventsStreamReconnectsAfterAStreamIsCutMidChunk(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		if open == 1 {
			abruptlyCloseStream(t, w, connectedPreamble)
			return
		}
		serveStream(t, w, connectedPreamble, mailEvent("m-after-cut", "survived"))
	})

	output, err := runEventsStream(t, url, 6)

	if err != nil {
		t.Fatalf("aw events stream exited non-zero (%v) after a cut stream:\n%s", err, output)
	}
	if strings.Contains(strings.ToLower(output), "unexpected eof") {
		t.Fatalf("output reports an unexpected EOF:\n%s", output)
	}
	if got := opens.Load(); got < 2 {
		t.Fatalf("the client opened %d stream(s); it must reconnect after a cut", got)
	}
	if countMessage(decodeEventLines(output), "m-after-cut") != 1 {
		t.Fatalf("the reconnected stream's event was not printed exactly once:\n%s", output)
	}
}

// The server's planned close at its duration cap ends the stream cleanly; the
// subscription continues until --timeout or Ctrl-C.
func TestEventsStreamReconnectsAfterTheServersPlannedClose(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		if open == 1 {
			serveStream(t, w, connectedPreamble)
			return
		}
		serveStream(t, w, connectedPreamble, mailEvent("m-after-close", "next stream"))
	})

	output, err := runEventsStream(t, url, 6)

	if err != nil {
		t.Fatalf("aw events stream exited non-zero (%v):\n%s", err, output)
	}
	if got := opens.Load(); got < 2 {
		t.Fatalf("the client opened %d stream(s); it ended the subscription at the server's planned close", got)
	}
	if countMessage(decodeEventLines(output), "m-after-close") != 1 {
		t.Fatalf("the event on the next stream was not printed exactly once:\n%s", output)
	}
}

// Each new stream announces everything still actionable, so mail that stays
// unread is announced again after every reconnect. A consumer of `aw events
// stream` is told about a message once.
func TestEventsStreamPrintsAMessageReannouncedAfterAReconnectOnce(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		if open == 1 {
			serveStream(t, w, connectedPreamble, mailEvent("m-unread", "still unread"))
			return
		}
		serveStream(t, w, connectedPreamble, mailEvent("m-unread", "still unread"), mailEvent(fmt.Sprintf("m-new-%d", open), "new"))
	})

	output, err := runEventsStream(t, url, 6)

	if err != nil {
		t.Fatalf("aw events stream exited non-zero (%v):\n%s", err, output)
	}
	if got := opens.Load(); got < 3 {
		t.Fatalf("only %d stream(s) opened; the test needs at least two reconnects", got)
	}
	events := decodeEventLines(output)
	if got := countMessage(events, "m-unread"); got != 1 {
		t.Fatalf("m-unread printed %d times across %d streams; it must be printed once:\n%s", got, opens.Load(), output)
	}
	if countMessage(events, "m-new-2") != 1 {
		t.Fatalf("a new message on a reconnected stream was not printed:\n%s", output)
	}
}

// A request the server refuses on its merits is refused the same way every
// time, so the stream stops with the server's error rather than retrying it.
func TestEventsStreamStopsWhenTheServerRefusesTheStream(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"detail":"certificate revoked"}`)
	})

	output, err := runEventsStream(t, url, 6)

	if err == nil {
		t.Fatalf("aw events stream exited zero after the server refused the stream:\n%s", output)
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("the client opened %d stream(s) against a refusal; it must stop after the first", got)
	}
}

// Five consecutive runs, each cut repeatedly: none may fail, and the reconnect
// rate must stay bounded.
func TestEventsStreamSurvivesRepeatedCutsAcrossFiveRuns(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		abruptlyCloseStream(t, w, connectedPreamble)
	})

	for attempt := 1; attempt <= 5; attempt++ {
		output, err := runEventsStream(t, url, 4)
		if err != nil {
			t.Fatalf("run %d/5 exited non-zero (%v):\n%s", attempt, err, output)
		}
		if strings.Contains(strings.ToLower(output), "unexpected eof") {
			t.Fatalf("run %d/5 reported an unexpected EOF:\n%s", attempt, output)
		}
	}
	if got := opens.Load(); got < 5 {
		t.Fatalf("only %d stream opens across five runs; the client is not reconnecting", got)
	}
	// Each 4s run starts at the backoff floor; about five opens per run is
	// expected. Far more means the backoff is not escalating.
	if got := opens.Load(); got > 40 {
		t.Fatalf("%d stream opens across five 4s runs; the backoff is not escalating between reconnects", got)
	}
}

// The server sends the connected preamble on every stream, so the preamble
// alone is not evidence of a working stream. A server that only answers and
// hangs up must push the reconnect delay up, or the client becomes a steady
// load on a server that is already failing.
func TestTheConnectedPreambleAloneDoesNotHoldTheBackoffAtItsFloor(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		abruptlyCloseStream(t, w, connectedPreamble)
	})

	output, err := runEventsStream(t, url, 6)

	if err != nil {
		t.Fatalf("run exited non-zero (%v):\n%s", err, output)
	}
	// With escalation a 6s window admits about five opens
	// (250ms + 500ms + 1s + 2s + 4s); pinned at the floor it is many more.
	if got := opens.Load(); got > 8 {
		t.Fatalf("%d stream opens in 6s against a server that only sends the preamble; the backoff is not escalating", got)
	}
	if got := opens.Load(); got < 2 {
		t.Fatalf("only %d open(s); the client stopped reconnecting", got)
	}
}

// A healthy idle stream carries only the preamble and keepalive comments, which
// never become events, and then closes at the duration cap. It differs from a
// failing server only in how long it lasted, so a stream that stayed open past
// the health threshold resets the backoff: an idle agent is the one waiting to
// be woken, and must not be left reconnecting slowly.
func TestALongLivedQuietStreamKeepsTheReconnectDelayAtItsFloor(t *testing.T) {
	t.Parallel()
	const (
		threshold = 300 * time.Millisecond
		holdOpen  = 500 * time.Millisecond
	)
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		serveStream(t, w, connectedPreamble)
		flusher := w.(http.Flusher)
		deadline := time.Now().Add(holdOpen)
		for time.Now().Before(deadline) {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(holdOpen / 4):
			}
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		}
	})

	output, err := runEventsStream(t, url, 6, fmt.Sprintf("AW_EVENTS_HEALTHY_STREAM_MS=%d", threshold.Milliseconds()))

	if err != nil {
		t.Fatalf("run exited non-zero (%v):\n%s", err, output)
	}
	// Each healthy cycle costs holdOpen plus the floor delay; a client that
	// escalates instead spends most of the window asleep.
	if got := opens.Load(); got < 7 {
		t.Fatalf("only %d opens in 6s for streams that each stayed open past the health threshold; a healthy idle subscription is backing off as if the server were failing", got)
	}
}

// The printed set is bounded so a subscription that runs for weeks does not
// grow without limit: past the bound the oldest message is forgotten, and if
// it is announced again it prints again.
func TestThePrintedSetForgetsItsOldestMessagePastItsBound(t *testing.T) {
	printed := newPrintedEvents(2)
	mail := func(id string) *awid.AgentEvent {
		return &awid.AgentEvent{Type: awid.AgentEventActionableMail, MessageID: id}
	}

	for _, id := range []string{"m-1", "m-2", "m-3"} {
		if !printed.firstTime(mail(id)) {
			t.Fatalf("%s was not printed the first time it was announced", id)
		}
	}
	if printed.firstTime(mail("m-3")) || printed.firstTime(mail("m-2")) {
		t.Fatal("a message still within the bound was printed again")
	}
	if !printed.firstTime(mail("m-1")) {
		t.Fatal("the oldest message was not forgotten past the bound")
	}
}

// --timeout ends the subscription even while a stream is open and idle: the
// open stream's body is bound to the subscription, not only the open request.
func TestEventsStreamTimeoutEndsAnOpenIdleStream(t *testing.T) {
	t.Parallel()
	_, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		serveStream(t, w, connectedPreamble)
		<-r.Context().Done()
	})

	started := time.Now()
	output, err := runEventsStream(t, url, 1)
	elapsed := time.Since(started)

	if err != nil {
		t.Fatalf("aw events stream exited non-zero (%v) at its timeout:\n%s", err, output)
	}
	// The build happens inside runEventsStream, so measure only a generous bound.
	if elapsed > 45*time.Second {
		t.Fatalf("aw events stream ran %s with --timeout 1 on an open idle stream", elapsed)
	}
}

// An error frame is lifecycle, not work: a server that answers with only the
// preamble and an error, then closes, must push the reconnect delay up.
func TestAnErrorOnlyStreamDoesNotHoldTheBackoffAtItsFloor(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		serveStream(t, w, connectedPreamble, "event: error\ndata: {\"detail\":\"poll failure\"}\n\n")
	})

	output, err := runEventsStream(t, url, 6)

	if err != nil {
		t.Fatalf("run exited non-zero (%v):\n%s", err, output)
	}
	if got := opens.Load(); got > 8 {
		t.Fatalf("%d stream opens in 6s against a server that only sends an error; the backoff is not escalating", got)
	}
	if got := opens.Load(); got < 2 {
		t.Fatalf("only %d open(s); the client stopped reconnecting", got)
	}
}

// A malformed frame is a protocol failure, not a stream end: the command stops
// and names it instead of silently reconnecting.
func TestEventsStreamStopsAndNamesAMalformedFrame(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		serveStream(t, w, connectedPreamble, "event: actionable_mail\ndata: {not json\n\n")
	})

	output, err := runEventsStream(t, url, 6)

	if err == nil {
		t.Fatalf("aw events stream exited zero after a malformed frame:\n%s", output)
	}
	if !strings.Contains(output, "invalid character") {
		t.Fatalf("the output does not name the parse failure:\n%s", output)
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("the client opened %d streams after a malformed frame; it must stop at the first", got)
	}
}

// A grant that ended (expired, revoked, its subject or issuer inactive) ends
// the subscription with the server's reason.
func TestEventsStreamStopsWhenTheGrantEnds(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		serveStream(t, w, connectedPreamble, "event: grant_revoked\ndata: {\"detail\":\"identity grant revoked\"}\n\n")
	})

	output, err := runEventsStream(t, url, 6)

	if err == nil {
		t.Fatalf("aw events stream exited zero after its grant was revoked:\n%s", output)
	}
	if !strings.Contains(output, "agent event stream closed: identity grant revoked") {
		t.Fatalf("the output does not give the server's reason:\n%s", output)
	}
	if got := opens.Load(); got != 1 {
		t.Fatalf("the client opened %d streams after its grant was revoked; it must stop at the first", got)
	}
}

// Grant verification that is temporarily unavailable asks to be retried, so
// the subscription reconnects, with backoff, and says why.
func TestEventsStreamRetriesWhenGrantVerificationIsUnavailable(t *testing.T) {
	t.Parallel()
	opens, url := eventsTestServer(t, func(open int64, w http.ResponseWriter, r *http.Request) {
		if open == 1 {
			serveStream(t, w, connectedPreamble, "event: verification_unavailable\ndata: {\"detail\":\"identity grant verification unavailable\"}\n\n")
			return
		}
		serveStream(t, w, connectedPreamble, mailEvent("m-after-retry", "verified again"))
	})

	output, err := runEventsStream(t, url, 6)

	if err != nil {
		t.Fatalf("aw events stream exited non-zero (%v) on a retryable verification outage:\n%s", err, output)
	}
	if got := opens.Load(); got < 2 {
		t.Fatalf("the client opened %d stream(s); it must retry a verification outage", got)
	}
	if !strings.Contains(output, "identity grant verification unavailable; retry") {
		t.Fatalf("the output does not say why it reconnected:\n%s", output)
	}
	if countMessage(decodeEventLines(output), "m-after-retry") != 1 {
		t.Fatalf("the retried stream's event was not printed:\n%s", output)
	}
}

// A proxy that resets an HTTP/2 stream mid-response is a transport end. The
// CLI's SSE transport attempts HTTP/2, and the reset surfaces as an HTTP/2
// stream error that is not a net.Error, so the classifier must reconnect on
// it rather than recognise transport errors by type.
func TestAnHTTP2StreamResetIsATransportEnd(t *testing.T) {
	server := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("expected HTTP/2, got %s", r.Proto)
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, connectedPreamble)
		w.(http.Flusher).Flush()
		panic(http.ErrAbortHandler) // RST_STREAM, as a proxy cutting the stream.
	}))
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()

	client, err := awid.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	// The production SSE transport, trusting only this test server.
	transport := awid.NewSSETransport()
	transport.TLSClientConfig = server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	client.SetSSEClient(&http.Client{Transport: transport})
	defer transport.CloseIdleConnections()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	stream, err := client.EventStream(ctx, time.Now().Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if ev, err := stream.Next(ctx); err != nil || ev.Type != awid.AgentEventConnected {
		t.Fatalf("preamble: event=%v err=%v", ev, err)
	}
	_, err = stream.Next(ctx)
	if err == nil {
		t.Fatal("expected the stream reset to end the read")
	}
	if retryable, fatal := classifyStreamEnd(err); retryable != nil || fatal != nil {
		t.Fatalf("an HTTP/2 stream reset (%T: %v) did not classify as a reconnect: retryable=%v fatal=%v", err, err, retryable, fatal)
	}
}

// Only the failures that reconnecting cannot fix stop the subscription: a grant
// that ended and a frame that does not decode. Any other read error, including
// one the client has never seen, reconnects.
func TestAnUnrecognisedReadErrorReconnects(t *testing.T) {
	if retryable, fatal := classifyStreamEnd(errors.New("an error no one listed")); retryable != nil || fatal != nil {
		t.Fatalf("an unrecognised read error stopped the subscription: retryable=%v fatal=%v", retryable, fatal)
	}
}
