package awid

import (
	"bytes"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A server that takes over a closed server's port is probed afresh once its
// base is forgotten: the earlier server's answer does not stand for it.
func TestForgetRequestCompressionProbesAReusedBaseAgain(t *testing.T) {
	first, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := first.Addr().String()
	plain := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	}))
	plain.Listener.Close()
	plain.Listener = first
	plain.Start()
	ForgetRequestCompression(plain.URL)
	postToCompressionBase(t, plain.URL)
	plain.Close()

	var second net.Listener
	for deadline := time.Now().Add(5 * time.Second); ; {
		if second, err = net.Listen("tcp", addr); err == nil || time.Now().After(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Skipf("port %s was not free to reuse: %v", addr, err)
	}
	var encoding string
	gzipServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Accept-Encoding", "gzip")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		encoding = r.Header.Get("Content-Encoding")
		_, _ = w.Write([]byte(`{}`))
	}))
	gzipServer.Listener.Close()
	gzipServer.Listener = second
	gzipServer.Start()
	defer gzipServer.Close()
	if gzipServer.URL != plain.URL {
		t.Fatalf("second server at %s, want the reused base %s", gzipServer.URL, plain.URL)
	}

	ForgetRequestCompression(gzipServer.URL)
	postToCompressionBase(t, gzipServer.URL)
	if encoding != "gzip" {
		t.Fatalf("Content-Encoding = %q after forgetting the reused base, want gzip", encoding)
	}
}

func postToCompressionBase(t *testing.T, base string) {
	t.Helper()
	body := bytes.Repeat([]byte("x"), 2048)
	req, err := http.NewRequest(http.MethodPost, base+"/v1/thing", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := DoServerRequest(&http.Client{Timeout: 5 * time.Second}, req, base)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
}

// Forgetting a server's origin forgets every base mounted on it, so a test
// that uses srv.URL+"/api" is isolated as well as one that uses srv.URL.
func TestForgetRequestCompressionCoversEveryMountOnTheOrigin(t *testing.T) {
	keep := "http://127.0.0.2:1"
	for _, base := range []string{"http://127.0.0.1:1", "http://127.0.0.1:1/api", "http://127.0.0.1:1/other", keep} {
		support := &requestCompressionSupport{ready: make(chan struct{})}
		close(support.ready)
		requestCompressionServers.Store(base, support)
	}
	t.Cleanup(func() { requestCompressionServers.Delete(keep) })

	ForgetRequestCompression("http://127.0.0.1:1")

	for _, base := range []string{"http://127.0.0.1:1", "http://127.0.0.1:1/api", "http://127.0.0.1:1/other"} {
		if _, ok := requestCompressionServers.Load(base); ok {
			t.Fatalf("%s is still cached after forgetting its origin", base)
		}
	}
	if _, ok := requestCompressionServers.Load(keep); !ok {
		t.Fatal("another origin's entry was forgotten")
	}
}
