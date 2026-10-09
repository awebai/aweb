package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"unicode"
)

func TestProbeAwebBaseURLRejectsRedirects(t *testing.T) {
	for _, status := range []int{300, 301, 302, 303, 304, 307, 308, 399} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			var targetHits, sourceHits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusOK)
			}))
			defer target.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sourceHits.Add(1)
				if r.Method != http.MethodGet || r.URL.Path != "/v1/agents/heartbeat" {
					t.Errorf("unexpected probe: %s %s", r.Method, r.URL.Path)
				}
				w.Header().Set("Location", target.URL+"/elsewhere")
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(status)
			}))
			defer source.Close()
			ok, err := probeAwebBaseURL(context.Background(), source.URL)
			if ok || err == nil || sourceHits.Load() != 1 || targetHits.Load() != 0 {
				t.Fatalf("redirect candidate: ok=%v err=%v source=%d target=%d", ok, err, sourceHits.Load(), targetHits.Load())
			}
		})
	}
}

func TestProbeAwebBaseURLPreservesResponses(t *testing.T) {
	for _, tc := range []struct {
		status      int
		contentType string
		want        bool
	}{
		{200, "application/json", true}, {204, "application/json", true},
		{401, "application/json", true}, {405, "application/json", true},
		{404, "application/json", false}, {200, "text/html", false},
	} {
		t.Run(fmt.Sprintf("%d/%s", tc.status, tc.contentType), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", tc.contentType)
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			ok, err := probeAwebBaseURL(context.Background(), server.URL)
			if err != nil || ok != tc.want {
				t.Fatalf("ok=%v err=%v, want %v", ok, err, tc.want)
			}
		})
	}
}

func TestResolveWorkingBaseURLRejectsRedirectCandidate(t *testing.T) {
	for _, validAPI := range []bool{false, true} {
		t.Run(fmt.Sprint(validAPI), func(t *testing.T) {
			var targetHits, sourceHits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
			}))
			defer target.Close()
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sourceHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				if validAPI && r.URL.Path == "/api/v1/agents/heartbeat" {
					w.WriteHeader(http.StatusOK)
					return
				}
				w.Header().Set("Location", target.URL)
				w.WriteHeader(http.StatusTemporaryRedirect)
			}))
			defer source.Close()
			got, err := resolveWorkingBaseURLContext(context.Background(), source.URL)
			if targetHits.Load() != 0 || sourceHits.Load() != 2 {
				t.Fatalf("candidate requests: source=%d target=%d", sourceHits.Load(), targetHits.Load())
			}
			if validAPI {
				if err != nil || got != source.URL+"/api" {
					t.Fatalf("selected=%q err=%v", got, err)
				}
			} else if err == nil || got != "" {
				t.Fatalf("all redirects accepted: selected=%q err=%v", got, err)
			}
		})
	}
}

func TestProbeAwebBaseURLRejectsSameOriginRedirect(t *testing.T) {
	var probeHits, redirectedHits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/v1/agents/heartbeat" {
			probeHits.Add(1)
			w.Header().Set("Location", "/redirected-heartbeat")
			w.WriteHeader(http.StatusTemporaryRedirect)
			return
		}
		redirectedHits.Add(1)
	}))
	defer server.Close()
	ok, err := probeAwebBaseURL(context.Background(), server.URL)
	if ok || err == nil || probeHits.Load() != 1 || redirectedHits.Load() != 0 {
		t.Fatalf("same-origin redirect: ok=%v err=%v probe=%d redirected=%d", ok, err, probeHits.Load(), redirectedHits.Load())
	}
}

func TestResolveWorkingBaseURLRedirectDiagnostic(t *testing.T) {
	for _, tc := range []struct{ name, location, want string }{
		{"upgrade", "https://api.example.test/api", "https://api.example.test/api"},
		{"malformed", "https://username:password@api.example.test/%zz?secret=query#fragment", "heartbeat probe request failed"},
		{"untrusted", "https://username:password@api.example.test/" + strings.Repeat("x", 2000) + "?secret=query#fragment", "https://api.example.test/"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var hits atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path != "/v1/agents/heartbeat" {
					w.WriteHeader(http.StatusNotFound)
					return
				}
				w.Header().Set("Location", tc.location)
				w.WriteHeader(http.StatusMovedPermanently)
			}))
			defer server.Close()
			got, err := resolveWorkingBaseURLContext(context.Background(), server.URL)
			if got != "" || err == nil {
				t.Fatalf("got=%q err=%v", got, err)
			}
			message := err.Error()
			if !strings.Contains(message, tc.want) || (tc.name != "malformed" && !strings.Contains(message, "AWEB_URL")) || hits.Load() != 2 {
				t.Fatalf("missing redirect diagnostic or wrong request count: %q hits=%d", message, hits.Load())
			}
			if len(message) > 600 || strings.ContainsAny(message, "\r\n") {
				t.Fatalf("unbounded/multiline diagnostic: length=%d", len(message))
			}
			for _, private := range []string{"username", "password", "secret", "query", "fragment"} {
				if strings.Contains(message, private) {
					t.Fatalf("redirect diagnostic exposed %s", private)
				}
			}
		})
	}
}

func TestRedirectLocationDisplaySanitizes(t *testing.T) {
	base, _ := url.Parse("http://source.example/api/v1/agents/heartbeat")
	for _, tc := range []struct{ raw, want string }{
		{"https://username:password@target.example:8443/pa\r\nth\x1b?secret=query#fragment", "https://target.example:8443/path"},
		{"/other?secret=query#fragment", "http://source.example/other"},
		{"https://username:password@target.example/\r\n" + strings.Repeat("x", 2000) + "?secret=query#fragment", "https://target.example/" + strings.Repeat("x", 230) + "..."},
		{"javascript:alert(1)", "(missing or invalid Location)"},
		{"https://target.example/%zz", "(missing or invalid Location)"},
		{"", "(missing or invalid Location)"},
	} {
		got := redirectLocationDisplay(tc.raw, base)
		if got != tc.want || len(got) > 256 {
			t.Fatalf("unexpected display %q (length %d)", got, len(got))
		}
		if strings.IndexFunc(got, unicode.IsControl) >= 0 {
			t.Fatal("control character in display")
		}
	}
}
