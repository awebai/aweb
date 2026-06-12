package awid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Venue WiFi / hostile NAT hardening (aweb-aaqm): normal API clients must use
// a tuned transport with finite connect/TLS/header timeouts and a short idle
// window, never raw http.DefaultTransport. SSE keeps a distinct transport
// with no overall client timeout so long-lived streams survive.

func TestNewAPITransportTunedForHostileNetworks(t *testing.T) {
	transport := NewAPITransport()
	if transport == http.DefaultTransport {
		t.Fatal("API transport must not be raw http.DefaultTransport")
	}
	if transport.IdleConnTimeout != 15*time.Second {
		t.Fatalf("IdleConnTimeout=%s, want 15s", transport.IdleConnTimeout)
	}
	if transport.TLSHandshakeTimeout <= 0 {
		t.Fatal("TLSHandshakeTimeout must be finite")
	}
	if transport.ResponseHeaderTimeout <= 0 {
		t.Fatal("ResponseHeaderTimeout must be finite")
	}
	if transport.DialContext == nil {
		t.Fatal("DialContext with a finite dial timeout is required")
	}
	if transport.MaxIdleConnsPerHost <= 0 {
		t.Fatal("MaxIdleConnsPerHost must be set explicitly")
	}
	if transport.Proxy == nil {
		t.Fatal("Proxy must be preserved (venue networks often require proxies)")
	}
	if transport.DisableKeepAlives {
		t.Fatal("keepalives stay enabled: the awid client is shared by long-lived processes and multi-request commands; the short IdleConnTimeout bounds stale reuse instead")
	}
}

func TestNewSSETransportDistinctFromAPITransport(t *testing.T) {
	api := NewAPITransport()
	sse := NewSSETransport()
	if api == sse {
		t.Fatal("SSE must use its own transport instance")
	}
	if sse == http.DefaultTransport {
		t.Fatal("SSE transport must not be raw http.DefaultTransport")
	}
	if sse.DialContext == nil || sse.TLSHandshakeTimeout <= 0 {
		t.Fatal("SSE transport still needs finite dial/TLS timeouts to detect blackholed connects")
	}
}

func TestNewClientUsesTunedTransportsAndNoSSETimeout(t *testing.T) {
	c, err := New("https://example.com")
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout <= 0 {
		t.Fatal("normal API client must have an overall timeout")
	}
	apiTransport, ok := c.httpClient.Transport.(*http.Transport)
	if !ok || apiTransport == http.DefaultTransport {
		t.Fatalf("normal API client transport=%T, want tuned *http.Transport", c.httpClient.Transport)
	}
	if c.sseClient.Timeout != 0 {
		t.Fatalf("SSE client Timeout=%s, must be zero for long-lived streams", c.sseClient.Timeout)
	}
	sseTransport, ok := c.sseClient.Transport.(*http.Transport)
	if !ok || sseTransport == http.DefaultTransport {
		t.Fatalf("SSE client transport=%T, want tuned *http.Transport", c.sseClient.Transport)
	}
	if apiTransport == sseTransport {
		t.Fatal("API and SSE clients must not share a transport instance")
	}
}

func TestAPITimeoutDefaultsTo30s(t *testing.T) {
	t.Setenv("AWEB_HTTP_TIMEOUT", "")
	if got := APITimeout(); got != 30*time.Second {
		t.Fatalf("APITimeout()=%s, want 30s default", got)
	}
}

func TestAPITimeoutReadsEnvDuration(t *testing.T) {
	t.Setenv("AWEB_HTTP_TIMEOUT", "45s")
	if got := APITimeout(); got != 45*time.Second {
		t.Fatalf("APITimeout()=%s, want 45s from env", got)
	}
	t.Setenv("AWEB_HTTP_TIMEOUT", "1m")
	if got := APITimeout(); got != time.Minute {
		t.Fatalf("APITimeout()=%s, want 1m from env", got)
	}
}

func TestAPITimeoutInvalidEnvFallsBackToDefault(t *testing.T) {
	for _, invalid := range []string{"banana", "-5s", "0"} {
		t.Setenv("AWEB_HTTP_TIMEOUT", invalid)
		if got := APITimeout(); got != 30*time.Second {
			t.Fatalf("APITimeout() with %q = %s, want 30s fallback", invalid, got)
		}
	}
}

func TestMutatingRequestTimeoutErrorSaysMayHaveApplied(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
	}))
	defer server.Close()

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.httpClient.Timeout = 100 * time.Millisecond

	err = c.Do(context.Background(), http.MethodPatch, "/v1/tasks/x", map[string]string{"status": "done"}, nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if !strings.Contains(err.Error(), "may have applied") || !strings.Contains(err.Error(), "before retrying") {
		t.Fatalf("mutating timeout error must warn the write may have applied; got: %v", err)
	}

	getErr := c.Do(context.Background(), http.MethodGet, "/v1/tasks/x", nil, nil)
	if getErr == nil {
		t.Fatal("expected timeout error on GET")
	}
	if strings.Contains(getErr.Error(), "may have applied") {
		t.Fatalf("read timeout must not carry the mutation warning; got: %v", getErr)
	}
}

func TestNewAPITransportHeaderTimeoutFollowsAPITimeout(t *testing.T) {
	// The observed venue failure class is "Client.Timeout exceeded while
	// awaiting headers": a hard-coded header timeout below AWEB_HTTP_TIMEOUT
	// would make the documented override a no-op for exactly that class.
	t.Setenv("AWEB_HTTP_TIMEOUT", "30s")
	if got := NewAPITransport().ResponseHeaderTimeout; got != 30*time.Second {
		t.Fatalf("ResponseHeaderTimeout=%s, want 30s following AWEB_HTTP_TIMEOUT", got)
	}
	t.Setenv("AWEB_HTTP_TIMEOUT", "")
	if got := NewAPITransport().ResponseHeaderTimeout; got != 30*time.Second {
		t.Fatalf("ResponseHeaderTimeout=%s, want 30s default", got)
	}
}
