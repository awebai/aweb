package awid

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func withDefaultUserAgent(t *testing.T, userAgent string) {
	t.Helper()
	previous := DefaultUserAgent()
	SetDefaultUserAgent(userAgent)
	t.Cleanup(func() { SetDefaultUserAgent(previous) })
}

type userAgentRecorder struct {
	mu   sync.Mutex
	seen []string
}

func (r *userAgentRecorder) handler(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.mu.Lock()
		r.seen = append(r.seen, req.Header.Get("User-Agent"))
		r.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

func (r *userAgentRecorder) last(t *testing.T) string {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.seen) == 0 {
		t.Fatal("server saw no request")
	}
	return r.seen[len(r.seen)-1]
}

func TestClientRequestsCarryTheDefaultUserAgent(t *testing.T) {
	withDefaultUserAgent(t, "aw/9.9.9 (test/arch)")
	rec := &userAgentRecorder{}
	server := httptest.NewServer(rec.handler(`{}`))
	defer server.Close()

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Get(context.Background(), "/v1/anything", &out); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t); got != "aw/9.9.9 (test/arch)" {
		t.Fatalf("User-Agent = %q, want the default", got)
	}
}

func TestDelegateUserAgentOverridesTheDefault(t *testing.T) {
	withDefaultUserAgent(t, "aw/9.9.9 (test/arch)")
	rec := &userAgentRecorder{}
	server := httptest.NewServer(rec.handler(`{}`))
	defer server.Close()

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	c.SetUserAgent("aw-beads-mail/9.9.9")
	var out map[string]any
	if err := c.Get(context.Background(), "/v1/anything", &out); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t); got != "aw-beads-mail/9.9.9" {
		t.Fatalf("User-Agent = %q, want the delegate's", got)
	}
}

func TestEventStreamCarriesTheUserAgent(t *testing.T) {
	withDefaultUserAgent(t, "aw/9.9.9 (test/arch)")
	seen := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		seen <- req.Header.Get("User-Agent")
		w.Header().Set("Content-Type", "text/event-stream")
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	stream, err := c.EventStream(context.Background(), time.Now().Add(time.Minute))
	if err == nil && stream != nil {
		_ = stream.Close()
	}
	select {
	case got := <-seen:
		if got != "aw/9.9.9 (test/arch)" {
			t.Fatalf("stream User-Agent = %q, want the default", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("server saw no stream request")
	}
}

func TestDoNoRedirectFillsOnlyAMissingUserAgent(t *testing.T) {
	withDefaultUserAgent(t, "aw/9.9.9 (test/arch)")
	rec := &userAgentRecorder{}
	server := httptest.NewServer(rec.handler(`{}`))
	defer server.Close()

	req, _ := http.NewRequest(http.MethodGet, server.URL, nil)
	resp, err := DoNoRedirect(server.Client(), req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := rec.last(t); got != "aw/9.9.9 (test/arch)" {
		t.Fatalf("User-Agent = %q, want the default", got)
	}

	req, _ = http.NewRequest(http.MethodGet, server.URL, nil)
	req.Header.Set("User-Agent", "caller/1")
	resp, err = DoNoRedirect(server.Client(), req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if got := rec.last(t); got != "caller/1" {
		t.Fatalf("User-Agent = %q, an explicit caller value must win", got)
	}
}

func TestNoDefaultUserAgentLeavesGoDefault(t *testing.T) {
	withDefaultUserAgent(t, "")
	rec := &userAgentRecorder{}
	server := httptest.NewServer(rec.handler(`{}`))
	defer server.Close()

	c, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := c.Get(context.Background(), "/v1/anything", &out); err != nil {
		t.Fatal(err)
	}
	if got := rec.last(t); !strings.HasPrefix(got, "Go-http-client/") {
		t.Fatalf("User-Agent = %q, want Go's default when no default is set", got)
	}
}
