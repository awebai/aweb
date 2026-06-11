package main

import (
	"net/http"
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
