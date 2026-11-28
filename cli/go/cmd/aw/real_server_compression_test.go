package main

import (
	"bytes"
	"net"
	"net/http"
	"net/url"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A real-server world forgets what this test process learned about its
// server's request compression when it ends. Without that, a later test
// server given the same loopback port receives gzip bodies it never
// advertised (vm-3ada7934: TestHostedRosterRunsNativeChildExchange read
// '\x1f' after the rotation tests ran in the same process).
func TestRealServerWorldForgetsRequestCompressionForItsAddress(t *testing.T) {
	var serverURL string
	t.Run("world", func(t *testing.T) {
		world := newRealCommandWorld(t)
		serverURL = world.Stack.ServerURL
		request, err := http.NewRequestWithContext(world.Context, http.MethodPost, serverURL+"/health", bytes.NewReader([]byte(`{"probe":true}`)))
		if err != nil {
			t.Fatal(err)
		}
		response, err := awid.DoServerRequest(&http.Client{Timeout: 10 * time.Second}, request, serverURL)
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
	})

	address, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	var listener net.Listener
	deadline := time.Now().Add(10 * time.Second)
	for {
		if listener, err = net.Listen("tcp", address.Host); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("listen on the ended world's address %s: %v", address.Host, err)
	}
	encodings := make(chan string, 4)
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			encodings <- r.Header.Get("Content-Encoding")
		}
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() { _ = server.Close(); awid.ForgetRequestCompression(serverURL) })

	request, err := http.NewRequest(http.MethodPost, serverURL+"/v1/anything", bytes.NewReader([]byte(`{"plain":true}`)))
	if err != nil {
		t.Fatal(err)
	}
	response, err := awid.DoServerRequest(&http.Client{Timeout: 10 * time.Second}, request, serverURL)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if encoding := <-encodings; encoding != "" {
		t.Fatalf("a server on the ended world's address received Content-Encoding %q it never advertised", encoding)
	}
}
