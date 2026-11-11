package handoff

import (
	"context"
	"net/http"
	"net/url"
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
	if status := get(t, callback(l, "handoff_id=h1&code="+testCode)); status != http.StatusOK {
		t.Fatalf("status %d", status)
	}
	code, err := l.Wait(context.Background(), time.Now().Add(time.Minute))
	if err != nil || code != testCode {
		t.Fatalf("code %q err %v", code, err)
	}
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

func TestAWakeCallbackCarriesOnlyTheHandoffID(t *testing.T) {
	l, err := ListenWake()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.Expect("h1")
	for name, query := range map[string]string{
		"a code":             "handoff_id=h1&code=" + testCode,
		"another handoff":    "handoff_id=h2",
		"an extra param":     "handoff_id=h1&state=x",
		"a repeated handoff": "handoff_id=h1&handoff_id=h1",
	} {
		if status := get(t, callback(l, query)); status != http.StatusNotFound {
			t.Errorf("%s: status %d", name, status)
		}
	}
	if status := get(t, callback(l, "handoff_id=h1")); status != http.StatusOK {
		t.Fatalf("wake: status %d", status)
	}
	if _, err := l.Wait(context.Background(), time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
}
