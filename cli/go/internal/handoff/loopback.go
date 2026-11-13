package handoff

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

const callbackPath = "/callback"

const callbackPage = "<!doctype html><meta charset=utf-8><title>aw</title><p>Done. Return to your terminal.</p>\n"

// Loopback is the one-shot listener on 127.0.0.1 that receives a handoff's
// code when the browser follows the app's redirect (RFC 8252). It accepts
// exactly one GET on its path, for the handoff it expects, and answers every
// other request 404 without reading anything from it.
type Loopback struct {
	listener net.Listener
	server   *http.Server
	codes    chan string

	// wake is a governance completion: it carries only handoff_id, as a hint
	// to read the receipt, and never a code (human-assurance-contract.md).
	wake bool

	mu        sync.Mutex
	handoffID string
	accepted  bool
	closeOnce sync.Once
}

// ListenWake is a loopback for a governance approval: the browser's return
// carries only the handoff id and wakes aw to read the receipt.
func ListenWake() (*Loopback, error) {
	l, err := ListenLoopback()
	if err != nil {
		return nil, err
	}
	l.wake = true
	return l, nil
}

// ListenLoopback listens on a random port of 127.0.0.1.
func ListenLoopback() (*Loopback, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen on the loopback address: %w", err)
	}
	l := &Loopback{listener: listener, codes: make(chan string, 1)}
	l.server = &http.Server{Handler: http.HandlerFunc(l.serve), ReadHeaderTimeout: 10 * time.Second}
	go l.server.Serve(listener) //nolint:errcheck // Serve returns when Close shuts the listener.
	return l, nil
}

// RedirectURI is the URI the handoff start registers.
func (l *Loopback) RedirectURI() string {
	return "http://" + l.listener.Addr().String() + callbackPath
}

// Expect names the handoff whose callback the listener accepts. Until it is
// called, every request is answered 404.
func (l *Loopback) Expect(handoffID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.handoffID = handoffID
}

// Wait returns the code of the accepted callback. It gives up at the
// handoff's expiry, or when ctx ends.
func (l *Loopback) Wait(ctx context.Context, expiresAt time.Time) (string, error) {
	timer := time.NewTimer(time.Until(expiresAt))
	defer timer.Stop()
	select {
	case code := <-l.codes:
		return code, nil
	case <-timer.C:
		l.Close()
		return "", coded("handoff_expired", errors.New("the handoff expired before the browser returned to aw"))
	case <-ctx.Done():
		l.Close()
		return "", ctx.Err()
	}
}

// Close stops the listener.
func (l *Loopback) Close() {
	l.closeOnce.Do(func() { l.server.Close() })
}

func (l *Loopback) serve(w http.ResponseWriter, r *http.Request) {
	code, ok := l.accept(r)
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write([]byte(callbackPage))
	l.codes <- code
	go l.Close()
}

func (l *Loopback) accept(r *http.Request) (string, bool) {
	if r.Method != http.MethodGet || r.URL.Path != callbackPath || r.URL.RawPath != "" {
		return "", false
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || len(query["handoff_id"]) != 1 {
		return "", false
	}
	code := ""
	if l.wake {
		if len(query) != 1 {
			return "", false
		}
	} else {
		if len(query) != 2 || len(query["code"]) != 1 || !canonicalToken(query["code"][0]) {
			return "", false
		}
		code = query["code"][0]
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.accepted || l.handoffID == "" || query["handoff_id"][0] != l.handoffID {
		return "", false
	}
	l.accepted = true
	return code, true
}

// canonicalToken reports whether value is 32 bytes in canonical unpadded
// base64url, the encoding of a handoff code and verifier.
func canonicalToken(value string) bool {
	if len(value) != 43 {
		return false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(value)
	return err == nil && len(raw) == 32
}
