package main

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// aweb-aamn. The customer's stream died at 60s while the server's own lifetime cap
// is 300s, so the 60s cut came from something between them. The server emits an idle
// heartbeat (EVENTS_HEARTBEAT_INTERVAL, server/src/aweb/routes/events.py:41) whose
// entire purpose is to put bytes on the wire so an intermediary does not consider the
// connection idle.
//
// Testing that needs an intermediary that cuts on REAL idleness. Modelling the cut
// inside the SSE handler would put the keepalive and the cut decision in the same
// place, and the test would assert only that the handler did what it was told. This
// proxy sits between the client and the server and watches actual bytes traverse it,
// so the keepalive is measured rather than assumed.
type idleCuttingProxy struct {
	listener net.Listener
	cuts     atomic.Int64
}

// newIdleCuttingProxy forwards TCP to backendAddr and severs any connection that
// carries no bytes in either direction for idleAfter.
func newIdleCuttingProxy(t *testing.T, backendAddr string, idleAfter time.Duration) *idleCuttingProxy {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	p := &idleCuttingProxy{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })

	go func() {
		for {
			client, err := listener.Accept()
			if err != nil {
				return
			}
			go p.handle(client, backendAddr, idleAfter)
		}
	}()
	return p
}

func (p *idleCuttingProxy) handle(client net.Conn, backendAddr string, idleAfter time.Duration) {
	backend, err := net.Dial("tcp", backendAddr)
	if err != nil {
		_ = client.Close()
		return
	}

	var mu sync.Mutex
	lastByte := time.Now()
	touch := func() {
		mu.Lock()
		lastByte = time.Now()
		mu.Unlock()
	}

	done := make(chan struct{})
	var closeOnce sync.Once
	shutdown := func() {
		closeOnce.Do(func() {
			_ = client.Close()
			_ = backend.Close()
			close(done)
		})
	}

	pump := func(dst, src net.Conn) {
		buf := make([]byte, 4096)
		for {
			n, err := src.Read(buf)
			if n > 0 {
				touch()
				if _, werr := dst.Write(buf[:n]); werr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		shutdown()
	}
	go pump(backend, client)
	go pump(client, backend)

	// The watchdog: no bytes either way for idleAfter and the connection is cut,
	// with no close frame - which is what reaches the client as an unexpected EOF.
	go func() {
		ticker := time.NewTicker(idleAfter / 4)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				mu.Lock()
				idle := time.Since(lastByte)
				mu.Unlock()
				if idle >= idleAfter {
					p.cuts.Add(1)
					shutdown()
					return
				}
			}
		}
	}()
}

func (p *idleCuttingProxy) addr() string { return p.listener.Addr().String() }

// countStreamOpensThroughIdleProxy runs an events subscription through a proxy that
// cuts idle connections, and reports how many streams the client had to open. With
// the heartbeat present a single stream should carry the whole window; without it the
// proxy severs the connection every idle period and the count climbs.
func countStreamOpensThroughIdleProxy(t *testing.T, emitHeartbeat bool) (opens int64, cuts int64) {
	t.Helper()

	const (
		heartbeatEvery = 150 * time.Millisecond
		proxyIdleAfter = 600 * time.Millisecond
		observeFor     = 4
	)

	var streamOpens atomic.Int64
	backend := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/v1/events/stream"):
			requireCertificateAuthForTest(t, r)
			streamOpens.Add(1)
			flusher, ok := w.(http.Flusher)
			if !ok {
				t.Fatal("no flusher")
			}
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "event: connected\ndata: {\"agent_id\":\"a-1\",\"team_id\":\"backend:acme.com\"}\n\n")
			flusher.Flush()

			// Idle for the rest of the window. This is the condition the heartbeat
			// exists for: no events to send, and a connection that must stay up.
			deadline := time.Now().Add(time.Duration(observeFor) * time.Second)
			for time.Now().Before(deadline) {
				select {
				case <-r.Context().Done():
					return
				case <-time.After(heartbeatEvery):
				}
				if emitHeartbeat {
					fmt.Fprint(w, ": keepalive\n\n")
					flusher.Flush()
				}
			}
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected path=%s", r.URL.Path)
		}
	}))

	backendAddr := strings.TrimPrefix(backend.URL, "http://")
	proxy := newIdleCuttingProxy(t, backendAddr, proxyIdleAfter)

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := buildAwForTest(t, ctx, tmp)
	writeDefaultWorkspaceBindingForTest(t, tmp, "http://"+proxy.addr())

	run := exec.CommandContext(ctx, bin, "events", "stream", "--json", "--timeout", fmt.Sprint(observeFor))
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, runErr := run.CombinedOutput()
	if runErr != nil {
		t.Fatalf("aw events stream exited non-zero (%v):\n%s", runErr, string(out))
	}
	return streamOpens.Load(), proxy.cuts.Load()
}

// The positive half: with the heartbeat on the wire, one stream carries an idle
// window several times longer than the proxy's idle tolerance.
func TestIdleKeepaliveKeepsOneStreamAliveThroughAnIdleCuttingProxy(t *testing.T) {
	t.Parallel()

	opens, cuts := countStreamOpensThroughIdleProxy(t, true)

	if cuts != 0 {
		t.Fatalf("the proxy cut %d connection(s) despite the keepalive, so the keepalive is not reaching the wire", cuts)
	}
	if opens != 1 {
		t.Fatalf("client opened %d streams over an idle window; with a keepalive it should need exactly 1", opens)
	}
}

// The falsifier the acceptance requires. Suppressing the keepalive must make the
// measurement go red, otherwise a green run above proves only that nothing was
// stressing the connection.
//
// Note what it is keyed on. Before this task the suppressed-keepalive case surfaced
// as exit 1, so exit code was the natural signal. It no longer is: the client now
// re-establishes the stream, so it exits 0 either way. Keying this on exit code would
// make it a check that cannot fail. The keepalive's actual effect is on how many
// streams a subscription costs, so that is what is measured.
func TestSuppressingTheIdleKeepaliveMakesTheProxyCutTheStream(t *testing.T) {
	t.Parallel()

	opens, cuts := countStreamOpensThroughIdleProxy(t, false)

	if cuts == 0 {
		t.Fatalf("the proxy never cut an idle connection with the keepalive suppressed, so the fixture cannot produce the original failure and the positive test above measures nothing")
	}
	if opens < 2 {
		t.Fatalf("client opened %d stream(s) with the keepalive suppressed; the proxy cut %d connection(s), so it should have had to reopen", opens, cuts)
	}
}
