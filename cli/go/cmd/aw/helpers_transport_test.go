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

// Venue WiFi / hostile NAT hardening (aweb-aaqm): the answering-mount transport must
// wrap the tuned API/SSE transports, not raw http.DefaultTransport, and the
// SSE client must keep no overall timeout.

func TestConfigureAnsweringMountHintWrapsTunedTransports(t *testing.T) {
	c, err := aweb.New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	sel := &awconfig.Selection{ServerName: "example", WorkspacePath: t.TempDir()}
	configureAnsweringMountHint(c, sel, "https://example.com")

	httpClient := c.HTTPClient()
	hinting, ok := httpClient.Transport.(*answeringMountTransport)
	if !ok {
		t.Fatalf("HTTP transport=%T, want *answeringMountTransport", httpClient.Transport)
	}
	base, ok := hinting.base.(*http.Transport)
	if !ok {
		t.Fatalf("transport base=%T, want tuned *http.Transport", hinting.base)
	}
	if base == http.DefaultTransport {
		t.Fatal("transport base must not be raw http.DefaultTransport")
	}
	if base.IdleConnTimeout != 15*time.Second {
		t.Fatalf("transport base IdleConnTimeout=%s, want tuned 15s", base.IdleConnTimeout)
	}
	if httpClient.Timeout != awid.APITimeout() {
		t.Fatalf("HTTP client Timeout=%s, want APITimeout()=%s", httpClient.Timeout, awid.APITimeout())
	}

	sseClient := c.SSEClient()
	if sseClient.Timeout != 0 {
		t.Fatalf("SSE client Timeout=%s, must stay zero for long-lived streams", sseClient.Timeout)
	}
	sseHinting, ok := sseClient.Transport.(*answeringMountTransport)
	if !ok {
		t.Fatalf("SSE transport=%T, want *answeringMountTransport", sseClient.Transport)
	}
	sseBase, ok := sseHinting.base.(*http.Transport)
	if !ok || sseBase == http.DefaultTransport {
		t.Fatalf("SSE transport base=%T, want tuned *http.Transport distinct from DefaultTransport", sseHinting.base)
	}
	if sseBase == base {
		t.Fatal("SSE and API transport bases must be distinct transport instances")
	}
}

// countingRoundTripper fails every call with a timeout error and records how
// many attempts the transport under test made.
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

func TestAnsweringMountTransportSendsARequestOnceOnTransportError(t *testing.T) {
	base := &countingRoundTripper{}
	transport := &answeringMountTransport{
		base:  base,
		state: &answeringMountState{configuredBaseURL: "http://configured.invalid"},
	}
	req := httptest.NewRequest(http.MethodPatch, "http://configured.invalid/api/v1/tasks/x", strings.NewReader(`{}`))
	resp, err := transport.RoundTrip(req)
	if resp != nil || err == nil {
		t.Fatalf("expected propagated transport error, got resp=%v err=%v", resp, err)
	}
	if base.calls != 1 {
		t.Fatalf("request was attempted %d times, want exactly 1", base.calls)
	}
}

func TestMutatingTimeoutThroughAnsweringMountTransportStillSaysMayHaveApplied(t *testing.T) {
	var serverHits int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		atomic.AddInt32(&serverHits, 1)
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	c, err := aweb.New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	sel := &awconfig.Selection{ServerName: "example", WorkspacePath: t.TempDir()}
	configureAnsweringMountHint(c, sel, server.URL)
	c.HTTPClient().Timeout = 100 * time.Millisecond

	err = c.Do(context.Background(), http.MethodPatch, "/v1/tasks/x", map[string]string{"status": "done"}, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "may have applied") {
		t.Fatalf("timeout through the answering-mount transport must keep the may-have-applied wording; got: %v", err)
	}
	if hits := atomic.LoadInt32(&serverHits); hits != 1 {
		t.Fatalf("server saw %d requests, want exactly 1 (the write is not sent again)", hits)
	}
}
