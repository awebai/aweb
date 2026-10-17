package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
)

func TestHostedRemovalTracePreservesRequestAndResponse(t *testing.T) {
	for _, status := range []int{http.StatusOK, http.StatusUnauthorized} {
		for _, enabled := range []bool{false, true} {
			name := http.StatusText(status)
			if enabled {
				name += "/trace"
			} else {
				name += "/quiet"
			}
			t.Run(name, func(t *testing.T) {
				traceSetting := "0"
				if enabled {
					traceSetting = "1"
				}
				t.Setenv("AW_TRACE", traceSetting)
				const apiKey = "aw_sk_removal_trace_secret"
				const cookie = "removal_cookie_secret"
				const team = "default:trace.aweb.ai"
				const responseBody = `{"status":"removed","alias":"retiree","alias_released":true}`
				var calls atomic.Int32
				server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if serveUnadvertisedHealth(w, r) {
						return
					}
					calls.Add(1)
					if r.Method != http.MethodPost || r.URL.EscapedPath() != "/api/v1/teams/default%3Atrace.aweb.ai/agents/self-remove" {
						t.Errorf("unexpected removal target: %s %s", r.Method, r.URL.EscapedPath())
					}
					if r.Header.Get("Authorization") != "Bearer "+apiKey {
						t.Error("removal request lost its own Bearer credential")
					}
					var body selfRetireRequest
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.Alias != "retiree" {
						t.Errorf("removal request body changed: alias=%q err=%v", body.Alias, err)
					}
					w.Header().Set("Set-Cookie", cookie)
					w.Header().Set("X-Request-Id", "trace-removal-request")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, responseBody)
				}))
				defer server.Close()
				plan := selfRetirePlan{awebURL: server.URL + "/api", apiKey: apiKey, teamID: team, alias: "retiree"}
				var result selfRetireResponse
				var callErr error
				trace := captureHostedRemovalTrace(t, func() {
					result, callErr = postSelfRetireWithAPIKey(context.Background(), plan)
				})
				if status == http.StatusOK {
					if callErr != nil || !result.AliasReleased || result.Alias != "retiree" {
						t.Fatalf("trace changed response decoding: result=%+v err=%v", result, callErr)
					}
				} else if callErr == nil || !strings.Contains(callErr.Error(), "401") || !strings.Contains(callErr.Error(), responseBody) {
					t.Fatalf("trace changed error status/body: %v", callErr)
				}
				if calls.Load() != 1 {
					t.Fatalf("removal sent %d times, want exactly once", calls.Load())
				}
				if strings.Contains(trace, apiKey) || strings.Contains(trace, cookie) {
					t.Fatal("trace exposed a credential")
				}
				if enabled {
					for _, want := range []string{
						"POST " + server.URL + "/api/v1/teams/default%3Atrace.aweb.ai/agents/self-remove",
						`{"alias":"retiree"}`, "HTTP " + strconv.Itoa(status),
						"Authorization: <redacted>", "Set-Cookie: <redacted>", "trace-removal-request", responseBody,
					} {
						if !strings.Contains(trace, want) {
							t.Errorf("trace omitted request/response evidence %q: %s", want, trace)
						}
					}
				} else if trace != "" {
					t.Fatalf("disabled tracing emitted output: %s", trace)
				}
			})
		}
	}
}

func captureHostedRemovalTrace(t *testing.T, fn func()) string {
	t.Helper()
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	original := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = original; _ = f.Close() }()
	fn()
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
