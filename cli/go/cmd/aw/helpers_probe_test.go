package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
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
			if ok || err != nil || sourceHits.Load() != 1 || targetHits.Load() != 0 {
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
	if ok || err != nil || probeHits.Load() != 1 || redirectedHits.Load() != 0 {
		t.Fatalf("same-origin redirect: ok=%v err=%v probe=%d redirected=%d", ok, err, probeHits.Load(), redirectedHits.Load())
	}
}
