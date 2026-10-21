package awid

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func newCompressionTestServer(t *testing.T, handler http.Handler) *httptest.Server {
	t.Helper()
	// A listener can reuse an earlier fixture's port. Isolate the complete base,
	// while preserving the real process cache within each fixture and its clients.
	mount := "/" + base64.RawURLEncoding.EncodeToString([]byte(t.TempDir()))
	server := httptest.NewServer(http.StripPrefix(mount, handler))
	server.URL += mount
	return server
}

func TestCompressionFixtureDoesNotPoisonReusedListener(t *testing.T) {
	var probes, compressed atomic.Int32
	advertiser := newCompressionTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			probes.Add(1)
			w.Header().Set("Accept-Encoding", "gzip")
			return
		}
		if r.Header.Get("Content-Encoding") == "gzip" {
			compressed.Add(1)
		}
		w.Write([]byte(`{}`))
	}))
	t.Cleanup(advertiser.Close)
	for n := 0; n < 2; n++ {
		c, err := New(advertiser.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := c.DoRaw(context.Background(), "POST", "/v1/test", "application/json", map[string]string{"body": "warm"})
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if probes.Load() != 1 || compressed.Load() != 2 {
		t.Fatalf("advertiser probes=%d compressed=%d", probes.Load(), compressed.Load())
	}
	address := advertiser.Listener.Addr().String()
	advertiser.Close()

	// Force the same port rather than waiting for the OS to happen to reuse it.
	listener, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatal(err)
	}
	plain := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		var input map[string]string
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		if input["body"] != "plain" || r.Header.Get("Content-Encoding") != "" {
			http.Error(w, "unexpected plain request", http.StatusBadRequest)
			return
		}
		w.Write([]byte(`{}`))
	}))
	plain.Listener.Close()
	plain.Listener = listener
	plain.Start()
	t.Cleanup(plain.Close)
	c, err := New(plain.URL)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.DoRaw(context.Background(), "POST", "/v1/test", "application/json", map[string]string{"body": "plain"})
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if readErr != nil {
		t.Fatal(readErr)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("reused listener returned %d: %s", resp.StatusCode, body)
	}
}
