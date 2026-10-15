package awid

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func captureHTTPDiagnostics(t *testing.T, run func() error) (diagnosticReport, string) {
	t.Helper()
	op := &httpDiagnosticOperation{started: time.Now()}
	previous := activeHTTPDiagnostics.Swap(op)
	defer activeHTTPDiagnostics.Store(previous)
	err := run()
	var out bytes.Buffer
	op.finish(err, &out)
	if err == nil {
		if out.Len() != 0 {
			t.Fatal("successful command emitted diagnostics")
		}
		return diagnosticReport{}, ""
	}
	data := strings.TrimPrefix(strings.TrimSpace(out.String()), httpDiagnosticPrefix)
	var report diagnosticReport
	if err := json.Unmarshal([]byte(data), &report); err != nil {
		t.Fatalf("invalid diagnostic: %v %q", err, out.String())
	}
	return report, data
}
func diagnosticRequest(t *testing.T, client *http.Client, ctx context.Context, rawURL string) error {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := DoNoRedirect(client, req)
	if err == nil {
		_, _ = io.Copy(io.Discard, resp.Body)
		_ = resp.Body.Close()
	}
	return err
}
func TestHTTPDiagnosticBoundaries(t *testing.T) {
	t.Run("dns", func(t *testing.T) {
		stop := make(chan struct{})
		defer close(stop)
		var lookups atomic.Int32
		resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			lookups.Add(1)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-stop:
				return nil, errors.New("private DNS canary")
			}
		}}
		dialer := &net.Dialer{Resolver: resolver}
		transport := &http.Transport{DialContext: dialer.DialContext}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 250 * time.Millisecond, Transport: transport}
		report, data := captureHTTPDiagnostics(t, func() error {
			return diagnosticRequest(t, client, context.Background(), "http://private-user:private-password@private-host-canary.invalid/private-path-canary?token=private-query-canary")
		})
		if lookups.Load() == 0 {
			t.Fatal("controlled DNS stall was not reached")
		}
		if len(report.Requests) != 1 || report.Requests[0].Stage != "dns" {
			t.Fatalf("DNS boundary lost: %+v", report)
		}
		for _, secret := range []string{"private-user", "private-password", "private-host-canary", "private-path-canary", "private-query-canary", "private DNS canary"} {
			if strings.Contains(data, secret) {
				t.Fatalf("diagnostic leaked %s", secret)
			}
		}
	})
	t.Run("connect", func(t *testing.T) {
		stop := make(chan struct{})
		defer close(stop)
		var entered atomic.Bool
		transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			entered.Store(true)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-stop:
				return nil, errors.New("private dial canary")
			}
		}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 250 * time.Millisecond, Transport: transport}
		report, _ := captureHTTPDiagnostics(t, func() error {
			return diagnosticRequest(t, client, context.Background(), "http://127.0.0.1:1/v1/messages/inbox?message_id=private-id")
		})
		if !entered.Load() || len(report.Requests) != 1 || report.Requests[0].Stage != "connect" || report.Requests[0].Route != "mail_source" {
			t.Fatalf("connect boundary lost: %+v", report)
		}
	})
	t.Run("tls", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		accepted := make(chan net.Conn, 1)
		go func() {
			conn, err := listener.Accept()
			if err == nil {
				accepted <- conn
			}
		}()
		transport := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 250 * time.Millisecond, Transport: transport}
		report, _ := captureHTTPDiagnostics(t, func() error {
			return diagnosticRequest(t, client, context.Background(), "https://"+listener.Addr().String()+"/v1/messages/inbox")
		})
		select {
		case conn := <-accepted:
			_ = conn.Close()
		default:
			t.Fatal("TLS stall did not accept a connection")
		}
		if len(report.Requests) != 1 || report.Requests[0].Stage != "tls" {
			t.Fatalf("TLS boundary lost: %+v", report)
		}
	})
	t.Run("await_response_and_reuse", func(t *testing.T) {
		var requests atomic.Int32
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if requests.Add(1) == 1 {
				_, _ = io.WriteString(w, "ok")
				return
			}
			<-r.Context().Done()
		}))
		defer server.Close()
		transport := &http.Transport{}
		defer transport.CloseIdleConnections()
		client := &http.Client{Timeout: 250 * time.Millisecond, Transport: transport}
		report, _ := captureHTTPDiagnostics(t, func() error {
			if err := diagnosticRequest(t, client, context.Background(), server.URL); err != nil {
				t.Fatal(err)
			}
			return diagnosticRequest(t, client, context.Background(), server.URL)
		})
		if len(report.Requests) != 2 || report.Requests[1].Stage != "await_response" || !report.Requests[1].Reused {
			t.Fatalf("reused connection/header boundary lost: %+v", report)
		}
	})
	t.Run("local_budget", func(t *testing.T) {
		ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		defer cancel()
		report, _ := captureHTTPDiagnostics(t, func() error {
			RecordHTTPDiagnosticPhase("key_read_started")
			RecordHTTPDiagnosticPhase("key_read_ready")
			return diagnosticRequest(t, &http.Client{}, ctx, "http://127.0.0.1:1/v1/messages/inbox")
		})
		if len(report.Requests) != 1 || report.Requests[0].Stage != "local_budget" || len(report.Phases) != 2 {
			t.Fatalf("pre-request budget boundary lost: %+v", report)
		}
	})
}
func TestHTTPDiagnosticSuccessAndRecoveredFailureStaySilent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer server.Close()
	captureHTTPDiagnostics(t, func() error { return diagnosticRequest(t, server.Client(), context.Background(), server.URL) })
	captureHTTPDiagnostics(t, func() error {
		expired, cancel := context.WithCancel(context.Background())
		cancel()
		if err := diagnosticRequest(t, server.Client(), expired, server.URL); err == nil {
			t.Fatal("controlled first failure did not fail")
		}
		return diagnosticRequest(t, server.Client(), context.Background(), server.URL)
	})
}
func TestHTTPDiagnosticBuffersAndPhaseVocabularyAreBounded(t *testing.T) {
	report, data := captureHTTPDiagnostics(t, func() error {
		for i := 0; i < 100; i++ {
			RecordHTTPDiagnosticPhase("private-phase-canary")
			RecordHTTPDiagnosticPhase("client_selection_started")
			req, _ := http.NewRequest(http.MethodGet, "http://private-host-canary/private-path-canary", nil)
			_, attempt := beginHTTPDiagnostics(req)
			for j := 0; j < 100; j++ {
				attempt.event("get_connection", nil)
			}
			attempt.finish(errors.New("private-error-canary"))
		}
		return errors.New("private-command-error-canary")
	})
	if len(report.Requests) != diagnosticRequestLimit || len(report.Phases) != diagnosticEventLimit || report.DroppedRequests != 100-diagnosticRequestLimit {
		t.Fatalf("buffers unbounded: %+v", report)
	}
	for _, r := range report.Requests {
		if len(r.Events) != diagnosticEventLimit {
			t.Fatal("event buffer unbounded")
		}
	}
	if strings.Contains(data, "private-") {
		t.Fatal("diagnostic accepted arbitrary caller or request strings")
	}
}

func TestHTTPDiagnosticInvalidRequestKeepsTransportRefusal(t *testing.T) {
	report, _ := captureHTTPDiagnostics(t, func() error {
		_, err := DoNoRedirect(&http.Client{}, &http.Request{Method: http.MethodGet, Header: make(http.Header)})
		if err == nil {
			t.Fatal("request without a URL was accepted")
		}
		return err
	})
	if len(report.Requests) != 1 || report.Requests[0].Route != "other_api" {
		t.Fatal("invalid request lost its diagnostic")
	}
}

func TestHTTPDiagnosticReconnectUsesCurrentConnectionPhase(t *testing.T) {
	report, _ := captureHTTPDiagnostics(t, func() error {
		req, _ := http.NewRequest(http.MethodGet, "http://private-host.invalid", nil)
		traced, attempt := beginHTTPDiagnostics(req)
		trace := httptrace.ContextClientTrace(traced.Context())
		trace.GetConn("private-host.invalid:80")
		trace.GotConn(httptrace.GotConnInfo{Reused: true})
		trace.WroteRequest(httptrace.WroteRequestInfo{})
		// A transparent transport retry starts a fresh connection, then stalls
		// in DNS. The prior connection's successful write must not mask that.
		trace.GetConn("private-host.invalid:80")
		trace.DNSStart(httptrace.DNSStartInfo{Host: "private-host.invalid"})
		attempt.finish(context.DeadlineExceeded)
		return context.DeadlineExceeded
	})
	if len(report.Requests) != 1 || report.Requests[0].Stage != "dns" || report.Requests[0].Reused {
		t.Fatalf("stale connection state masked the retry: %+v", report)
	}
}
