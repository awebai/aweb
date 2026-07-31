package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// aweb-aamn. The customer symptom is "unexpected EOF", exit 1, after one event,
// 5/5 reproducible. The server closes every events stream at MAX_STREAM_DURATION
// (server/src/aweb/routes/events.py:42, 300s) BY DESIGN, and cli/go/cmd/aw/events.go
// asked for a 24h deadline while opening exactly one stream - so the design cap and
// the client's expectation could not both be satisfied, and the client surfaced the
// difference as an error.
//
// The close is reproduced by HIJACKING the connection and closing the socket without
// writing the terminating chunk. A handler that simply returns ends the chunked body
// cleanly, which the client already treated as io.EOF and exit 0 - so a test built
// that way would pass against the unfixed client and measure nothing.

// abruptlyCloseStream writes an SSE prologue and then kills the TCP connection
// without a terminating chunk, which is what reaches the client as "unexpected EOF".
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

func buildAwForTest(t *testing.T, ctx context.Context, tmp string) string {
	t.Helper()
	bin := filepath.Join(tmp, "aw")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "./cmd/aw")
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	build.Dir = filepath.Clean(filepath.Join(wd, "..", ".."))
	build.Env = os.Environ()
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, string(out))
	}
	return bin
}

func decodeEventLines(output string) []map[string]any {
	var events []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err == nil {
			events = append(events, ev)
		}
	}
	return events
}

// A subscription that outlives the server's stream-lifetime cap must be
// re-established rather than surfaced as an error. This is the customer's exact
// failure: one stream, cut by the server, reported as "unexpected EOF" with exit 1.
func TestEventsStreamReestablishesAfterServerClosesTheStream(t *testing.T) {
	t.Parallel()

	var opens atomic.Int64
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			requireCertificateAuthForTest(t, r)
			switch opens.Add(1) {
			case 1:
				// The server's own lifetime cap, reached mid-subscription.
				abruptlyCloseStream(t, w,
					"event: connected\ndata: {\"agent_id\":\"a-1\",\"team_id\":\"backend:acme.com\"}\n\n")
			default:
				// The re-established stream carries the event the client would
				// otherwise never have received.
				flusher, ok := w.(http.Flusher)
				if !ok {
					t.Fatal("no flusher")
				}
				w.Header().Set("Content-Type", "text/event-stream")
				w.WriteHeader(http.StatusOK)
				fmt.Fprint(w, "event: actionable_mail\ndata: {\"message_id\":\"m-after-reconnect\",\"from_alias\":\"alice\",\"subject\":\"survived\"}\n\n")
				flusher.Flush()
			}
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := buildAwForTest(t, ctx, tmp)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", "8")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	output := string(out)

	if runErr != nil {
		t.Fatalf("aw events stream exited non-zero (%v) on a server-initiated close; the customer symptom is exactly this:\n%s", runErr, output)
	}
	if strings.Contains(strings.ToLower(output), "unexpected eof") {
		t.Fatalf("output still reports an unexpected EOF:\n%s", output)
	}
	if got := opens.Load(); got < 2 {
		t.Fatalf("the client opened %d stream(s); a subscription that outlives one stream must re-establish it", got)
	}

	events := decodeEventLines(output)
	var sawReconnectedEvent bool
	for _, ev := range events {
		if ev["message_id"] == "m-after-reconnect" {
			sawReconnectedEvent = true
		}
	}
	if !sawReconnectedEvent {
		// Reconnecting is not the point; receiving what the reconnect exists to
		// deliver is. A client that reopens and reads nothing has the same
		// delivery gap as one that exits.
		t.Fatalf("no event was delivered on the re-established stream, so the reconnect delivered nothing:\n%s", output)
	}
}

// Five consecutive attempts, because the report is 5/5 reproducible. One green run
// against an intermittent fault establishes nothing.
func TestEventsStreamSurvivesRepeatedServerClosesAcrossFiveAttempts(t *testing.T) {
	t.Parallel()

	var opens atomic.Int64
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			requireCertificateAuthForTest(t, r)
			// Every stream is cut. The client must keep re-establishing rather
			// than erroring on the first one.
			abruptlyCloseStream(t, w,
				"event: connected\ndata: {\"agent_id\":\"a-1\",\"team_id\":\"backend:acme.com\"}\n\n")
			opens.Add(1)
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := buildAwForTest(t, ctx, tmp)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	for attempt := 1; attempt <= 5; attempt++ {
		run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", "4")
		run.Env = testCommandEnv(tmp)
		run.Dir = tmp
		out, runErr := run.CombinedOutput()
		output := string(out)

		if runErr != nil {
			t.Fatalf("attempt %d/5 exited non-zero (%v):\n%s", attempt, runErr, output)
		}
		if strings.Contains(strings.ToLower(output), "unexpected eof") {
			t.Fatalf("attempt %d/5 reported an unexpected EOF:\n%s", attempt, output)
		}
	}

	if got := opens.Load(); got < 5 {
		t.Fatalf("only %d stream opens across five attempts; the client is not re-establishing", got)
	}
	// An upper bound as well as a lower one. Without it this assertion is satisfied
	// by 5 opens and by 80 equally, so it cannot tell a client that reconnects with
	// escalating backoff from one hammering the server at its floor - which is the
	// defect charlie found on review. Each 4s attempt is a fresh process starting at
	// the 250ms floor, so about five opens per attempt is expected.
	if got := opens.Load(); got > 40 {
		t.Fatalf("%d stream opens across five 4s attempts; the backoff is not escalating between reconnects", got)
	}
	t.Logf("stream opens across five 4s attempts: %d", opens.Load())
}

// aweb-aamn, charlie's finding on review. The server emits `event: connected`
// unconditionally on every stream (server/src/aweb/routes/events.py:383), so a
// "did this stream deliver anything" flag keyed on ANY event is true for every
// stream that opens at all. That made the backoff escalation dead code and pinned
// the reconnect rate at the 250ms floor forever - measured at 3.2 opens/sec,
// sustained, against a server that only ever sends the preamble and cuts.
//
// An agent subscribed to a failing server then amplifies load on it, which is the
// exact scenario the backoff exists to prevent and it bites hardest when the server
// is already in trouble.
//
// The codebase already draws this line: awid/event_source_test.go asserts
// "connected never wakes" - connected is informational, not delivery.
func TestConnectedPreambleAloneDoesNotHoldTheBackoffAtItsFloor(t *testing.T) {
	t.Parallel()

	var opens atomic.Int64
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			requireCertificateAuthForTest(t, r)
			opens.Add(1)
			// Only the preamble, then cut. This server is not serving a
			// subscription; it just answers and hangs up.
			abruptlyCloseStream(t, w,
				"event: connected\ndata: {\"agent_id\":\"a-1\",\"team_id\":\"backend:acme.com\"}\n\n")
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := buildAwForTest(t, ctx, tmp)
	writeDefaultWorkspaceBindingForTest(t, tmp, server.URL)

	const windowSeconds = 6
	run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", fmt.Sprint(windowSeconds))
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	if out, err := run.CombinedOutput(); err != nil {
		t.Fatalf("run exited non-zero (%v):\n%s", err, string(out))
	}

	// With escalation running, a 6s window admits about five opens
	// (250ms + 500ms + 1s + 2s + 4s). Without it, the floor is permanent and the
	// count runs an order of magnitude higher. The bound is deliberately loose:
	// it discriminates "escalating" from "pinned at the floor", not a schedule.
	const maxOpens = 8
	if got := opens.Load(); got > maxOpens {
		t.Fatalf("%d stream opens in %ds against a server that only sends the preamble; the backoff is not escalating, so this is a %0.1f/sec load amplifier",
			got, windowSeconds, float64(got)/float64(windowSeconds))
	}
	// The other direction: it must still be reconnecting at all, or this passes
	// for the wrong reason.
	if got := opens.Load(); got < 2 {
		t.Fatalf("only %d open(s); the client stopped reconnecting entirely", got)
	}
}
