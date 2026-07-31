package main

import (
	"context"
	"fmt"
	"net/http"
	"os/exec"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// aweb-aamn, raised by eve on review. The open-failure classifier decides whether a
// subscription ends or backs off, and nothing exercised it in either direction - the
// tests only ever wrote StatusOK. So the line could have been inverted without a test
// noticing, which is how it came to treat 429 as fatal in the first place.
//
// Both directions are asserted. The retry direction is the one that would have caught
// the original defect.
func TestStreamOpenFailureClassification(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name  string
		code  int
		fatal bool
		why   string
	}{
		{"unauthorized is refused identically every time", http.StatusUnauthorized, true,
			"bad credentials do not become good by reopening; looping would bury the reason"},
		{"forbidden is refused identically every time", http.StatusForbidden, true, ""},
		{"not found is refused identically every time", http.StatusNotFound, true, ""},
		{"unprocessable deadline is refused identically every time", http.StatusUnprocessableEntity, true, ""},
		{"too many requests means reopen later", http.StatusTooManyRequests, false,
			"429 means precisely 'retry after a delay'; ending the subscription does the opposite of what the server asked"},
		{"request timeout means reopen later", http.StatusRequestTimeout, false, ""},
		{"server error is not fatal", http.StatusInternalServerError, false, ""},
		{"bad gateway is not fatal", http.StatusBadGateway, false,
			"an intermediary failing is the case reconnection exists for"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := isFatalStreamOpenError(&awid.APIError{StatusCode: tc.code})
			if got != tc.fatal {
				t.Fatalf("status %d classified fatal=%v, want %v. %s", tc.code, got, tc.fatal, tc.why)
			}
		})
	}
}

// The end-to-end direction eve named: a 429 must not end the subscription. A unit
// test over the classifier cannot show that the loop actually consults it.
func TestRateLimitedOpenKeepsTheSubscriptionAlive(t *testing.T) {
	t.Parallel()

	var opens atomic.Int64
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			requireCertificateAuthForTest(t, r)
			// Rate-limited twice, then serve. A client that treats 429 as fatal
			// never reaches the third open and never sees the event.
			if opens.Add(1) <= 2 {
				w.WriteHeader(http.StatusTooManyRequests)
				fmt.Fprint(w, `{"detail":"slow down"}`)
				return
			}
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("no flusher")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "event: actionable_mail\ndata: {\"message_id\":\"m-after-429\",\"from_alias\":\"alice\",\"subject\":\"served\"}\n\n")
			flusher.Flush()
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

	run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", "8")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	output := string(out)

	if runErr != nil {
		t.Fatalf("a rate-limited open ended the subscription (%v); 429 asks the client to wait, not to stop:\n%s", runErr, output)
	}
	var served bool
	for _, ev := range decodeEventLines(output) {
		if ev["message_id"] == "m-after-429" {
			served = true
		}
	}
	if !served {
		t.Fatalf("the client never got past the rate limit to the event waiting behind it (%d opens):\n%s", opens.Load(), output)
	}
}

// The other direction, end to end: a genuinely fatal refusal must still exit rather
// than loop forever against a server that will refuse identically every time.
func TestUnauthorizedOpenEndsTheSubscription(t *testing.T) {
	t.Parallel()

	var opens atomic.Int64
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			opens.Add(1)
			w.WriteHeader(http.StatusUnauthorized)
			fmt.Fprint(w, `{"detail":"bad signature"}`)
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

	run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", "8")
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()

	if runErr == nil {
		t.Fatalf("an unauthorized open did not end the subscription; it would retry a refusal forever:\n%s", string(out))
	}
	// And it stopped promptly rather than retrying its way there.
	if got := opens.Load(); got > 2 {
		t.Fatalf("%d opens against a server returning 401; the refusal reason is being buried in a reconnect loop", got)
	}
}
