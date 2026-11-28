package handoff

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"testing"
	"time"
)

const testCode = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // 32 zero bytes, base64url, no padding

func listen(t *testing.T) *Loopback {
	t.Helper()
	l, err := ListenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(l.Close)
	l.Expect("h1")
	return l
}

func get(t *testing.T, target string) int {
	t.Helper()
	resp, err := http.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func callback(l *Loopback, query string) string {
	return l.RedirectURI() + "?" + query
}

func TestRedirectURIIsALiteralLoopbackAddress(t *testing.T) {
	l := listen(t)
	u, err := url.Parse(l.RedirectURI())
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.RawQuery != "" || u.Fragment != "" {
		t.Fatalf("redirect uri %q", l.RedirectURI())
	}
}

func TestTheFirstExactCallbackYieldsTheCode(t *testing.T) {
	l := listen(t)
	type result struct {
		code string
		err  error
	}
	waited := make(chan result, 1)
	go func() {
		code, err := l.Wait(context.Background(), time.Now().Add(time.Minute))
		waited <- result{code, err}
	}()
	resp, err := http.Get(callback(l, "handoff_id=h1&code="+testCode))
	if err != nil {
		t.Fatal(err)
	}
	page, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || string(page) != callbackPage {
		t.Fatalf("status %d page %q err %v", resp.StatusCode, page, err)
	}
	if r := <-waited; r.err != nil || r.code != testCode {
		t.Fatalf("code %q err %v", r.code, r.err)
	}
}

func TestTheAcceptedCallbackClosesTheListenerBeforeHandingOverTheCode(t *testing.T) {
	l := listen(t)
	get(t, callback(l, "handoff_id=h1&code="+testCode))
	// The browser can return before aw reaches Wait: the code handed over,
	// not Wait, marks the end of the accepted callback.
	if code := <-l.codes; code != testCode {
		t.Fatalf("code %q", code)
	}
	if conn, err := net.Dial("tcp", l.listener.Addr().String()); err == nil {
		conn.Close()
		t.Fatal("listener still accepts connections")
	}
}

func TestWaitReleasesTheListeningSocketBeforeServingHasStarted(t *testing.T) {
	// One processor keeps the serving goroutine from starting before Wait.
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(1))
	l, err := ListenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	address := l.listener.Addr().String()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := l.Wait(ctx, time.Now().Add(time.Minute)); err != context.Canceled {
		t.Fatalf("err %v", err)
	}
	again, err := net.Listen("tcp", address)
	if err != nil {
		t.Fatalf("listening socket still held: %v", err)
	}
	again.Close()
}

func TestEveryOtherRequestIsNotFoundAndYieldsNothing(t *testing.T) {
	l := listen(t)
	base := l.RedirectURI()
	for name, target := range map[string]string{
		"another path":         strings.TrimSuffix(base, "/callback") + "/other?handoff_id=h1&code=" + testCode,
		"another handoff":      callback(l, "handoff_id=h2&code="+testCode),
		"a missing code":       callback(l, "handoff_id=h1"),
		"a repeated code":      callback(l, "handoff_id=h1&code="+testCode+"&code="+testCode),
		"an extra parameter":   callback(l, "handoff_id=h1&code="+testCode+"&state=x"),
		"a short code":         callback(l, "handoff_id=h1&code=AAAA"),
		"a padded code":        callback(l, "handoff_id=h1&code="+testCode+"%3D"),
		"a non-canonical code": callback(l, "handoff_id=h1&code="+testCode[:42]+"B"),
	} {
		if status := get(t, target); status != http.StatusNotFound {
			t.Errorf("%s: status %d", name, status)
		}
	}
	resp, err := http.Post(callback(l, "handoff_id=h1&code="+testCode), "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("POST: status %d", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if code, err := l.Wait(ctx, time.Now().Add(time.Minute)); err == nil {
		t.Fatalf("yielded %q", code)
	}
}

func TestTheListenerClosesAfterTheFirstAcceptedCallback(t *testing.T) {
	l := listen(t)
	get(t, callback(l, "handoff_id=h1&code="+testCode))
	if _, err := l.Wait(context.Background(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := http.Get(callback(l, "handoff_id=h1&code="+testCode)); err == nil {
		t.Fatal("listener still answers")
	}
}

func TestWaitEndsAtTheHandoffExpiry(t *testing.T) {
	l := listen(t)
	_, err := l.Wait(context.Background(), time.Now().Add(50*time.Millisecond))
	if ErrorCode(err) != "handoff_expired" {
		t.Fatalf("err %v", err)
	}
}

func TestACallbackBeforeTheHandoffIsKnownYieldsNothing(t *testing.T) {
	l, err := ListenLoopback()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	for _, query := range []string{"handoff_id=h1&code=" + testCode, "handoff_id=&code=" + testCode} {
		if status := get(t, callback(l, query)); status != http.StatusNotFound {
			t.Fatalf("%s: status %d", query, status)
		}
	}
}
