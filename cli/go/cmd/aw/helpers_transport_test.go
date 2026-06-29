package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// Venue WiFi / hostile NAT hardening (aweb-aaqm): the base URL fallback must
// wrap the tuned API/SSE transports, not raw http.DefaultTransport, and the
// SSE client must keep no overall timeout.

func TestConfigureBaseURLFallbackWrapsTunedTransports(t *testing.T) {
	c, err := aweb.New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	sel := &awconfig.Selection{ServerName: "example", WorkspacePath: t.TempDir()}
	configureBaseURLFallback(c, sel, "https://example.com")

	httpClient := c.HTTPClient()
	fallback, ok := httpClient.Transport.(*baseURLFallbackTransport)
	if !ok {
		t.Fatalf("HTTP transport=%T, want *baseURLFallbackTransport", httpClient.Transport)
	}
	base, ok := fallback.base.(*http.Transport)
	if !ok {
		t.Fatalf("fallback base=%T, want tuned *http.Transport", fallback.base)
	}
	if base == http.DefaultTransport {
		t.Fatal("fallback base must not be raw http.DefaultTransport")
	}
	if base.IdleConnTimeout != 15*time.Second {
		t.Fatalf("fallback base IdleConnTimeout=%s, want tuned 15s", base.IdleConnTimeout)
	}
	if httpClient.Timeout != awid.APITimeout() {
		t.Fatalf("HTTP client Timeout=%s, want APITimeout()=%s", httpClient.Timeout, awid.APITimeout())
	}

	sseClient := c.SSEClient()
	if sseClient.Timeout != 0 {
		t.Fatalf("SSE client Timeout=%s, must stay zero for long-lived streams", sseClient.Timeout)
	}
	sseFallback, ok := sseClient.Transport.(*baseURLFallbackTransport)
	if !ok {
		t.Fatalf("SSE transport=%T, want *baseURLFallbackTransport", sseClient.Transport)
	}
	sseBase, ok := sseFallback.base.(*http.Transport)
	if !ok || sseBase == http.DefaultTransport {
		t.Fatalf("SSE fallback base=%T, want tuned *http.Transport distinct from DefaultTransport", sseFallback.base)
	}
	if sseBase == base {
		t.Fatal("SSE and API fallback bases must be distinct transport instances")
	}
}

// countingRoundTripper fails every call with a timeout error and records how
// many attempts the fallback transport made.
type countingRoundTripper struct {
	calls int
}

type fakeTimeoutError struct{}

func (fakeTimeoutError) Error() string {
	return "context deadline exceeded (Client.Timeout exceeded while awaiting headers)"
}
func (fakeTimeoutError) Timeout() bool   { return true }
func (fakeTimeoutError) Temporary() bool { return true }

func (c *countingRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	c.calls++
	return nil, fakeTimeoutError{}
}

func TestShouldRetryBaseURLRequestNeverReplaysMutatingTransportErrors(t *testing.T) {
	transportErr := fakeTimeoutError{}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if !shouldRetryBaseURLRequest(method, nil, transportErr) {
			t.Fatalf("%s with transport error must be retried (safe read)", method)
		}
	}
	for _, method := range []string{http.MethodPost, http.MethodPatch, http.MethodPut, http.MethodDelete} {
		if shouldRetryBaseURLRequest(method, nil, transportErr) {
			t.Fatalf("%s with transport error must NOT be replayed: the write may have applied", method)
		}
	}
	// A 404 response means the server answered and nothing was applied
	// (misconfigured base path): replaying any method is safe.
	notFound := &http.Response{StatusCode: http.StatusNotFound}
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodPatch} {
		if !shouldRetryBaseURLRequest(method, notFound, nil) {
			t.Fatalf("%s with a concrete 404 response should retry against the corrected base", method)
		}
	}
	if shouldRetryBaseURLRequest(http.MethodGet, &http.Response{StatusCode: http.StatusOK}, nil) {
		t.Fatal("200 response must not retry")
	}
}

func TestBaseURLFallbackDoesNotReplayMutatingTransportError(t *testing.T) {
	base := &countingRoundTripper{}
	transport := &baseURLFallbackTransport{
		base: base,
		state: &baseURLFallbackState{
			configuredBaseURL: "http://configured.invalid",
			currentBaseURL:    "http://configured.invalid",
		},
	}
	req := httptest.NewRequest(http.MethodPatch, "http://configured.invalid/api/v1/tasks/x", strings.NewReader(`{}`))
	resp, err := transport.RoundTrip(req)
	if resp != nil || err == nil {
		t.Fatalf("expected propagated transport error, got resp=%v err=%v", resp, err)
	}
	if base.calls != 1 {
		t.Fatalf("mutating request was attempted %d times, want exactly 1 (no fallback replay)", base.calls)
	}
}

func TestMutatingTimeoutThroughFallbackStillSaysMayHaveApplied(t *testing.T) {
	var serverHits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&serverHits, 1)
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	c, err := aweb.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	sel := &awconfig.Selection{ServerName: "example", WorkspacePath: t.TempDir()}
	configureBaseURLFallback(c, sel, server.URL)
	c.HTTPClient().Timeout = 100 * time.Millisecond

	err = c.Do(context.Background(), http.MethodPatch, "/v1/tasks/x", map[string]string{"status": "done"}, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "may have applied") {
		t.Fatalf("timeout through the fallback transport must keep the may-have-applied wording; got: %v", err)
	}
	if hits := atomic.LoadInt32(&serverHits); hits != 1 {
		t.Fatalf("server saw %d requests, want exactly 1 (no fallback replay of the write)", hits)
	}
}
