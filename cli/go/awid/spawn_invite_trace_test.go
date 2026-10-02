package awid

import (
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestAcceptSpawnInviteTraceRedactsBodies(t *testing.T) {
	t.Setenv("AW_TRACE", "1")
	const body = `{"token":"aw_inv_secret_fixture_token"}`
	for _, prefix := range []string{"", "/prefix"} {
		t.Run(prefix, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodPost, "https://example.test"+prefix+"/api/v1/spawn/accept-invite", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp := &http.Response{StatusCode: 403, Request: req, Body: io.NopCloser(strings.NewReader(body))}
			trace := captureStderrForTest(t, func() {
				TraceHTTPRequest(req, []byte(body))
				if err := TraceHTTPResponse(resp); err != nil {
					t.Fatal(err)
				}
			})
			if strings.Contains(trace, "aw_inv_secret") || strings.Count(trace, "<redacted: invite acceptance>") != 2 {
				t.Fatal("invite trace did not redact both bodies")
			}
			remaining, err := io.ReadAll(resp.Body)
			resp.Body.Close()
			if err != nil || string(remaining) != body {
				t.Fatal("trace changed response decoding")
			}
		})
	}
}

func TestAcceptSpawnInviteDoesNotEchoToken(t *testing.T) {
	t.Setenv("AW_TRACE", "1")
	const token = "aw_inv_secret_fixture_token"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = w.Write([]byte(`{"detail":"invalid token: ` + token + `"}`))
	}))
	defer server.Close()
	pub, key, _ := ed25519.GenerateKey(nil)
	client, err := NewWithIdentity(server.URL+"/prefix/api", key, ComputeDIDKey(pub))
	if err != nil {
		t.Fatal(err)
	}
	trace := captureStderrForTest(t, func() {
		_, err = client.AcceptSpawnInvite(context.Background(), &SpawnAcceptInviteRequest{Token: token, DID: ComputeDIDKey(pub)})
	})
	if err == nil {
		t.Fatal("expected refusal")
	}
	if strings.Contains(trace, token) || strings.Contains(err.Error(), token) {
		t.Fatal("accept-invite leaked token through trace/error")
	}
	if status, ok := HTTPStatusCode(err); !ok || status != 403 {
		t.Fatalf("lost error status: %v", err)
	}
}
