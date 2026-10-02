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
		}, Body: io.NopCloser(strings.NewReader("<html>private-response-content</html>"))}, nil
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
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
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
