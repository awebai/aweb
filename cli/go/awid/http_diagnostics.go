package awid

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const HTTPDiagnosticsEnvVar = "AWEB_HTTP_DIAGNOSTICS"
const httpDiagnosticPrefix = "AW HTTP DIAGNOSTIC "
const diagnosticRequestLimit = 8
const diagnosticEventLimit = 32

type diagnosticEvent struct {
	Phase        string `json:"phase"`
	Milliseconds int64  `json:"ms"`
}

type httpDiagnosticOperation struct {
	mu       sync.Mutex
	started  time.Time
	phases   []diagnosticEvent
	attempts []*httpDiagnosticAttempt
	dropped  int
	closed   bool
}

type httpDiagnosticAttempt struct {
	mu                                sync.Mutex
	started                           time.Time
	method, route                     string
	remaining                         *int64
	expiredAtStart                    bool
	events                            []diagnosticEvent
	dnsStarted, dnsDone, dnsFailed    bool
	tlsStarted, tlsDone, tlsFailed    bool
	gotConn, reused, wrote, firstByte bool
	errorClass                        string
}

type diagnosticRequestReport struct {
	Method            string            `json:"method"`
	Route             string            `json:"route"`
	Stage             string            `json:"stage"`
	ErrorClass        string            `json:"error_class,omitempty"`
	BudgetRemainingMS *int64            `json:"budget_remaining_ms,omitempty"`
	Reused            bool              `json:"reused"`
	Events            []diagnosticEvent `json:"events"`
}

type diagnosticReport struct {
	ElapsedMS       int64                     `json:"elapsed_ms"`
	ErrorClass      string                    `json:"error_class"`
	Phases          []diagnosticEvent         `json:"phases"`
	Requests        []diagnosticRequestReport `json:"requests"`
	DroppedRequests int                       `json:"dropped_requests,omitempty"`
}

var activeHTTPDiagnostics atomic.Pointer[httpDiagnosticOperation]

// StartHTTPDiagnostics owns one CLI process's diagnostic lifetime. Only the
// command runner starts it; SDK requests alone never enable or print traces.
// Collect in memory and emit once, only if the command ultimately fails.
func StartHTTPDiagnostics() func(error) {
	if os.Getenv(HTTPDiagnosticsEnvVar) != "1" {
		return func(error) {}
	}
	op := &httpDiagnosticOperation{started: time.Now()}
	previous := activeHTTPDiagnostics.Swap(op)
	return func(err error) {
		if !activeHTTPDiagnostics.CompareAndSwap(op, previous) {
			return
		}
		op.finish(err, os.Stderr)
	}
}

// RecordHTTPDiagnosticPhase accepts a fixed vocabulary, never caller data.
func RecordHTTPDiagnosticPhase(phase string) {
	switch phase {
	case "api_budget_started", "client_selection_started", "client_selection_ready", "key_read_started", "key_read_ready":
	default:
		return
	}
	op := activeHTTPDiagnostics.Load()
	if op == nil {
		return
	}
	op.mu.Lock()
	defer op.mu.Unlock()
	if !op.closed && len(op.phases) < diagnosticEventLimit {
		op.phases = append(op.phases, diagnosticEvent{phase, time.Since(op.started).Milliseconds()})
	}
}

func diagnosticErrorClass(err error) string {
	switch {
	case err == nil:
		return ""
	case errors.Is(err, context.DeadlineExceeded):
		return "deadline"
	case errors.Is(err, context.Canceled):
		return "canceled"
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		return "dns"
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return "network_timeout"
	}
	return "other"
}

func diagnosticRoute(path string) string {
	switch {
	case strings.HasSuffix(path, "/v1/agents/heartbeat"):
		return "api_probe"
	case strings.HasSuffix(path, "/v1/messages/inbox"):
		return "mail_inbox"
	case strings.HasSuffix(path, "/v1/messages"):
		return "mail_send"
	case strings.Contains(path, "/v1/messages/") && strings.HasSuffix(path, "/ack"):
		return "mail_ack"
	case strings.Contains(path, "/v1/chat/sessions/") && strings.HasSuffix(path, "/messages"):
		return "chat_messages"
	default:
		return "other_api"
	}
}

func diagnosticMethod(method string) string {
	switch method {
	case "GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS":
		return method
	}
	return "OTHER"
}

func (a *httpDiagnosticAttempt) event(phase string, update func()) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if update != nil {
		update()
	}
	if len(a.events) < diagnosticEventLimit {
		a.events = append(a.events, diagnosticEvent{phase, time.Since(a.started).Milliseconds()})
	}
}

func beginHTTPDiagnostics(req *http.Request) (*http.Request, *httpDiagnosticAttempt) {
	op := activeHTTPDiagnostics.Load()
	if op == nil || req == nil {
		return req, nil
	}
	route := "other_api"
	if req.URL != nil {
		route = diagnosticRoute(req.URL.Path)
		if route == "mail_inbox" && req.URL.Query().Has("message_id") {
			route = "mail_source"
		}
	}
	a := &httpDiagnosticAttempt{started: time.Now(), method: diagnosticMethod(req.Method), route: route}
	if deadline, ok := req.Context().Deadline(); ok {
		remaining := time.Until(deadline).Milliseconds()
		a.remaining = &remaining
		a.expiredAtStart = !time.Now().Before(deadline)
	}
	op.mu.Lock()
	if op.closed {
		op.mu.Unlock()
		return req, nil
	}
	if len(op.attempts) == diagnosticRequestLimit {
		op.attempts = op.attempts[1:]
		op.dropped++
	}
	op.attempts = append(op.attempts, a)
	op.mu.Unlock()
	trace := &httptrace.ClientTrace{
		GetConn: func(string) {
			a.event("get_connection", func() {
				// net/http may transparently retry a stale connection inside one
				// Do call. Classify the current connection, retaining older events.
				a.gotConn, a.reused, a.wrote, a.firstByte = false, false, false, false
				a.dnsStarted, a.dnsDone, a.dnsFailed = false, false, false
				a.tlsStarted, a.tlsDone, a.tlsFailed = false, false, false
			})
		},
		DNSStart: func(httptrace.DNSStartInfo) { a.event("dns_start", func() { a.dnsStarted = true }) },
		DNSDone: func(d httptrace.DNSDoneInfo) {
			a.event("dns_done", func() { a.dnsDone = true; a.dnsFailed = d.Err != nil })
		},
		ConnectStart: func(string, string) { a.event("connect_start", nil) },
		ConnectDone: func(_, _ string, _ error) {
			a.event("connect_done", nil)
		},
		TLSHandshakeStart: func() { a.event("tls_start", func() { a.tlsStarted = true }) },
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			a.event("tls_done", func() { a.tlsDone = true; a.tlsFailed = err != nil })
		},
		GotConn: func(c httptrace.GotConnInfo) {
			a.event("got_connection", func() { a.gotConn = true; a.reused = c.Reused })
		},
		WroteRequest:         func(w httptrace.WroteRequestInfo) { a.event("request_written", func() { a.wrote = w.Err == nil }) },
		GotFirstResponseByte: func() { a.event("first_response_byte", func() { a.firstByte = true }) },
	}
	return req.WithContext(httptrace.WithClientTrace(req.Context(), trace)), a
}

func (a *httpDiagnosticAttempt) finish(err error) {
	if a == nil {
		return
	}
	a.event("request_returned", func() { a.errorClass = diagnosticErrorClass(err) })
}

func (a *httpDiagnosticAttempt) report() diagnosticRequestReport {
	a.mu.Lock()
	defer a.mu.Unlock()
	stage := "response"
	switch {
	case a.errorClass == "":
		stage = "headers_received"
	case a.expiredAtStart && a.errorClass == "deadline":
		stage = "local_budget"
	case !a.gotConn && (a.dnsFailed || (a.dnsStarted && !a.dnsDone)):
		stage = "dns"
	case !a.gotConn && (a.tlsFailed || (a.tlsStarted && !a.tlsDone)):
		stage = "tls"
	case !a.gotConn:
		stage = "connect"
	case !a.wrote:
		stage = "write_request"
	case !a.firstByte:
		stage = "await_response"
	}
	return diagnosticRequestReport{a.method, a.route, stage, a.errorClass, a.remaining, a.reused, append([]diagnosticEvent{}, a.events...)}
}

func (op *httpDiagnosticOperation) finish(err error, out io.Writer) {
	op.mu.Lock()
	if op.closed {
		op.mu.Unlock()
		return
	}
	op.closed = true
	if err == nil {
		op.mu.Unlock()
		return
	}
	report := diagnosticReport{ElapsedMS: time.Since(op.started).Milliseconds(), ErrorClass: diagnosticErrorClass(err), Phases: append([]diagnosticEvent{}, op.phases...), Requests: []diagnosticRequestReport{}, DroppedRequests: op.dropped}
	attempts := append([]*httpDiagnosticAttempt{}, op.attempts...)
	op.mu.Unlock()
	for _, a := range attempts {
		report.Requests = append(report.Requests, a.report())
	}
	data, marshalErr := json.Marshal(report)
	if marshalErr == nil {
		_, _ = io.WriteString(out, httpDiagnosticPrefix+string(data)+"\n")
	}
}
