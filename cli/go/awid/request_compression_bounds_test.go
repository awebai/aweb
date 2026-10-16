package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestRequestCompressionBodyBoundaries(t *testing.T) {
	random := make([]byte, MaxGzipRequestSize)
	if _, err := rand.Read(random); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, method, encoding string
		body                   []byte
		compressed, probe      bool
	}{
		{"exact_decoded_cap", "POST", "", bytes.Repeat([]byte("x"), MaxGzipRequestSize), true, true},
		{"over_decoded_cap", "POST", "", bytes.Repeat([]byte("x"), MaxGzipRequestSize+1), false, false},
		{"over_encoded_cap", "POST", "", random, false, true},
		{"empty", "POST", "", nil, false, false},
		{"read", "GET", "", []byte("body"), false, false},
		{"caller_encoding", "POST", "br", []byte("body"), false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var probes atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					probes.Add(1)
					w.Header().Set("Accept-Encoding", "gzip")
					return
				}
				if got := r.Header.Get("Content-Encoding") == "gzip"; got != tc.compressed {
					t.Errorf("compressed=%v", got)
				}
				if body := gzipTestBody(t, r); !bytes.Equal(body, tc.body) {
					t.Errorf("body length=%d want=%d", len(body), len(tc.body))
				}
				if r.ContentLength < 0 || r.Header.Get("X-Original") != "kept" || len(r.TransferEncoding) != 0 {
					t.Error("invalid wire headers")
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			req, _ := http.NewRequest(""+tc.method, srv.URL+"/v1/test", bytes.NewReader(tc.body))
			req.Header.Set("X-Original", "kept")
			req.Header.Set("Content-Encoding", tc.encoding)
			resp, err := DoServerRequest(srv.Client(), req, srv.URL)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if got := probes.Load() > 0; got != tc.probe {
				t.Errorf("probed=%v", got)
			}
			if req.Header.Get("Content-Encoding") != tc.encoding {
				t.Error("caller request headers mutated")
			}
		})
	}
}

func TestRequestCompressionDiscoveryIsUnauthenticatedAndNeverFollowsRedirects(t *testing.T) {
	var targetHits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		w.Header().Set("Accept-Encoding", "gzip")
	}))
	defer target.Close()
	for _, status := range []int{200, 302, 503} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var probes atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					probes.Add(1)
					for _, key := range []string{"Authorization", "Cookie", "X-AWEB-Signed-Payload", "X-AWID-Team-Certificate"} {
						if r.Header.Get(key) != "" {
							t.Errorf("discovery leaked %s", key)
						}
					}
					w.Header().Set("Accept-Encoding", "gzip")
					w.Header().Set("Location", target.URL)
					w.WriteHeader(status)
					return
				}
				if got := r.Header.Get("Content-Encoding") == "gzip"; got != (status == 200) {
					t.Errorf("compressed=%v", got)
				}
				if r.Header.Get("Authorization") != "Bearer secret" || r.Header.Get("Cookie") == "" {
					t.Error("write credentials were not preserved")
				}
			}))
			defer srv.Close()
			jar, _ := cookiejar.New(nil)
			u, _ := url.Parse(srv.URL)
			jar.SetCookies(u, []*http.Cookie{{Name: "session", Value: "secret"}})
			client := srv.Client()
			client.Jar = jar
			for n := 0; n < 2; n++ {
				req, _ := http.NewRequest("POST", srv.URL+"/v1/test", strings.NewReader(`{"body":"test"}`))
				req.Header.Set("Authorization", "Bearer secret")
				resp, err := DoServerRequest(client, req, srv.URL)
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
			}
			if probes.Load() != 1 {
				t.Errorf("probes=%d", probes.Load())
			}
		})
	}
	if targetHits.Load() != 0 {
		t.Errorf("redirect target hit %d times", targetHits.Load())
	}
}

func TestRequestCompressionProbeDeadlineAndCanceledWaiter(t *testing.T) {
	opened := make(chan struct{})
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			close(opened)
			<-release
			w.Header().Set("Accept-Encoding", "gzip")
			return
		}
		if r.Header.Get("Content-Encoding") != "gzip" {
			t.Error("first probe lost support")
		}
	}))
	defer srv.Close()
	firstDone := make(chan error, 1)
	go func() {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/test", strings.NewReader("test"))
		resp, err := DoServerRequest(srv.Client(), req, srv.URL)
		if resp != nil {
			resp.Body.Close()
		}
		firstDone <- err
	}()
	<-opened
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, "POST", srv.URL+"/v1/test", strings.NewReader("test"))
	before := time.Now()
	resp, err := DoServerRequest(srv.Client(), req, srv.URL)
	if resp != nil {
		resp.Body.Close()
	}
	close(release)
	if err == nil || time.Since(before) > time.Second {
		t.Error("canceled waiter waited for another probe")
	}
	if err := <-firstDone; err != nil {
		t.Fatal(err)
	}
}

func TestRequestCompressionFailedProbeFallsBackWithinDiscoveryBudget(t *testing.T) {
	var probes atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			probes.Add(1)
			<-r.Context().Done()
			return
		}
		if r.Header.Get("Content-Encoding") != "" {
			t.Error("failed discovery enabled gzip")
		}
	}))
	defer srv.Close()
	start := time.Now()
	for n := 0; n < 2; n++ {
		req, _ := http.NewRequest("POST", srv.URL+"/v1/test", strings.NewReader("test"))
		resp, err := DoServerRequest(srv.Client(), req, srv.URL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
	}
	if probes.Load() != 1 || time.Since(start) > 4*time.Second {
		t.Errorf("probe count=%d elapsed=%s", probes.Load(), time.Since(start))
	}
}

func TestClientRequestCompressionPreservesSendRetryPolicy(t *testing.T) {
	for _, path := range []string{"/v1/messages", "/v1/tasks"} {
		t.Run(path, func(t *testing.T) {
			var writes, probes atomic.Int32
			var first []byte
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					probes.Add(1)
					w.Header().Set("Accept-Encoding", "gzip")
					return
				}
				n := writes.Add(1)
				wire, _ := io.ReadAll(r.Body)
				if r.Header.Get("Content-Encoding") != "gzip" {
					t.Error("uncompressed write")
				}
				if n == 1 {
					first = wire
					w.WriteHeader(503)
					w.Write([]byte(`{"detail":"busy"}`))
					return
				}
				if !bytes.Equal(first, wire) {
					t.Error("replayed bytes changed")
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			c, _ := New(srv.URL)
			resp, err := c.DoRaw(context.Background(), "POST", path, "application/json", map[string]string{"message_id": "stable-id", "body": "test"})
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			want := int32(1)
			if path == "/v1/messages" {
				want = 2
			}
			if writes.Load() != want || probes.Load() != 1 {
				t.Errorf("writes=%d probes=%d", writes.Load(), probes.Load())
			}
		})
	}
}

func TestOnboardingRequestCompression(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	did := ComputeDIDKey(pub)
	for _, kind := range []string{"claim", "redeem", "signup"} {
		t.Run(kind, func(t *testing.T) {
			var writes atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/health" {
					w.Header().Set("Accept-Encoding", "gzip")
					return
				}
				writes.Add(1)
				if r.Header.Get("Content-Encoding") != "gzip" {
					t.Error("onboarding write not compressed")
				}
				body := gzipTestBody(t, r)
				var fields map[string]any
				if json.Unmarshal(body, &fields) != nil || fields["did_key"] != did {
					t.Error("onboarding bytes changed")
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			c, _ := NewWithIdentity(srv.URL+"/api", key, did)
			var err error
			switch kind {
			case "claim":
				_, err = c.ClaimHuman(context.Background(), &ClaimHumanRequest{Username: "test", Email: "test@example.test", DIDKey: did})
			case "redeem":
				_, err = c.BootstrapRedeem(context.Background(), &BootstrapRedeemRequest{Token: "token", DIDKey: did})
			case "signup":
				err = postJSONWithHeaders(context.Background(), srv.URL+"/api", "/api/v1/onboarding/cli-signup", []byte(`{"did_key":"`+did+`"}`), nil, nil)
			}
			if err != nil {
				t.Fatal(err)
			}
			if writes.Load() != 1 {
				t.Errorf("writes=%d", writes.Load())
			}
		})
	}
}
