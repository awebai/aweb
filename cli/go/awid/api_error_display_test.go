package awid

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"unicode"
)

func TestAPIErrorResponseMetadataBound(t *testing.T) {
	client, _ := New("https://example.test")
	client.httpClient = &http.Client{Transport: registryRetryRoundTripper(func(r *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 403, Request: r, Header: http.Header{
			"Content-Type": []string{"text/html"},
			"X-Request-Id": []string{strings.Repeat("r", 300) + "\x1b\n\u202e"},
			"Cf-Ray":       []string{"ray\x1b\t\u202e" + strings.Repeat("c", 300)},
			"Cf-Mitigated": []string{"challenge\x1b\t\u202e" + strings.Repeat("m", 300)},
		}, Body: io.NopCloser(strings.NewReader("<html><title>Blocked</title>private-response-content</html>"))}, nil
	})}
	err := client.Get(context.Background(), "/v1/test", nil)
	if err == nil {
		t.Fatal("expected HTTP error")
	}
	out := err.Error()
	if len(out) > 1024 {
		t.Fatalf("error has %d bytes; max 1024", len(out))
	}
	if strings.Contains(out, "private-response-content") {
		t.Fatal("body leaked")
	}
	for _, r := range out {
		if (unicode.IsControl(r) && r != '\n') || unicode.Is(unicode.Cf, r) {
			t.Fatalf("unsafe output character %U", r)
		}
	}
	for _, want := range []string{"http 403", "x-request-id:", "cf-ray:", "cf-mitigated:"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in %s", want, out)
		}
	}
	// Raw body remains available to existing structured error/retry consumers.
	body, ok := HTTPErrorBody(err)
	if !ok || !strings.Contains(body, "private-response-content") {
		t.Fatal("raw error body contract changed")
	}
}

func TestAPIErrorNonJSONTraceOmitsBody(t *testing.T) {
	t.Setenv("AW_TRACE", "1")
	req, _ := http.NewRequest(http.MethodGet, "https://example.test/v1/test", nil)
	const body = "<html><title>Blocked</title>private-response-content</html>"
	resp := &http.Response{StatusCode: 403, Request: req, Header: http.Header{"Content-Type": []string{"text/html"}, "Cf-Ray": []string{"ray-trace"}}, Body: io.NopCloser(strings.NewReader(body))}
	trace := captureStderrForTest(t, func() {
		if err := TraceHTTPResponse(resp); err != nil {
			t.Fatal(err)
		}
	})
	if strings.Contains(trace, "private-response-content") || !strings.Contains(trace, "body omitted") || !strings.Contains(trace, "ray-trace") {
		t.Fatal("non-JSON trace exposed body or lost metadata")
	}
	data, err := io.ReadAll(resp.Body)
	resp.Body.Close()
	if err != nil || string(data) != body {
		t.Fatal("trace changed body consumed by error handlers")
	}
}

func TestAPIErrorBlockedFirewallGuidanceBoundary(t *testing.T) {
	for _, tc := range []struct {
		name                         string
		status                       int
		contentType, body, mitigated string
		wantAdvice                   bool
	}{
		{"blocked", 403, "text/html", "<html><title>Blocked</title>secret-body</html>", "", true},
		{"title-whitespace-case", 403, "text/html; charset=utf-8", "<html><TITLE>  bLoCkEd \n</TITLE>secret-body</html>", "", true},
		{"sniffed-html", 403, "", "<!doctype html><title>Blocked</title>secret-body", "", true},
		{"xhtml", 403, "application/xhtml+xml", "<title>Blocked</title>secret-body", "", true},
		{"blocked-with-challenge-header", 403, "text/html", "<html><title>Blocked</title>secret-body</html>", "challenge", true},
		{"other-html", 403, "text/html", "<html><title>Forbidden</title>secret-body</html>", "", false},
		{"challenge", 403, "text/html", "<html><title>Just a moment...</title>secret-body</html>", "challenge", false},
		{"json-detail", 403, "application/json", `{"detail":"Blocked"}`, "", false},
		{"json-in-html-type", 403, "text/html", `{"detail":"<html><title>Blocked</title></html>"}`, "", false},
		{"plain-text", 403, "text/plain", "Blocked secret-body", "", false},
		{"plain-text-with-title", 403, "text/plain", "<title>Blocked</title>secret-body", "", false},
		{"wrong-status", 404, "text/html", "<html><title>Blocked</title>secret-body</html>", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			response := &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": []string{tc.contentType}, "Cf-Mitigated": []string{tc.mitigated}, "X-Request-Id": []string{"request-fixture"}}}
			err := newAPIError(response, tc.body)
			out := err.Error()
			if strings.Contains(out, "firewall") != tc.wantAdvice {
				t.Fatalf("firewall guidance=%v, want %v: %s", strings.Contains(out, "firewall"), tc.wantAdvice, out)
			}
			if tc.wantAdvice && len(strings.Split(out, "\n")) != 2 {
				t.Fatalf("expected status/title line above firewall guidance: %s", out)
			}
			if err.StatusCode != tc.status || err.Body != tc.body || !strings.Contains(out, "request-fixture") {
				t.Fatal("display changed status, raw body, or response metadata")
			}
			if strings.Contains(out, "secret-body") || len(out) > 1024 {
				t.Fatalf("non-JSON display leaked body or exceeded bound: %s", out)
			}
		})
	}
}
