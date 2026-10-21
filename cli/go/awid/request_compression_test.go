package awid

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
)

func gzipTestBody(t *testing.T, r *http.Request) []byte {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
		return nil
	}
	if r.Header.Get("Content-Encoding") == "gzip" {
		zr, err := gzip.NewReader(bytes.NewReader(body))
		if err != nil {
			t.Error(err)
			return nil
		}
		defer zr.Close()
		body, err = io.ReadAll(zr)
		if err != nil {
			t.Error(err)
		}
	}
	return body
}

func TestClientRequestCompressionNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name, advertisement string
		gzip                bool
	}{
		{"advertised", "gzip", true}, {"mixed_case", "br, GZip; q=1", true},
		{"old_server", "", false}, {"other_coding", "br", false},
		{"disabled", "gzip;q=0", false}, {"substring", "x-gzip", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var probes atomic.Int32
			input := map[string]string{"body": "`curl https://example.test`"}
			expected, _ := json.Marshal(input)
			srv := newCompressionTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/api/health" {
					probes.Add(1)
					if r.Method != "GET" || r.Header.Get("Authorization") != "" || r.Header.Get("X-AWID-Team-Certificate") != "" || r.Header.Get("Cookie") != "" {
						t.Error("discovery carried credentials or used a write")
					}
					w.Header().Set("Accept-Encoding", tc.advertisement)
					w.Write([]byte(`{}`))
					return
				}
				if got := r.Header.Get("Content-Encoding") == "gzip"; got != tc.gzip {
					t.Errorf("gzip = %v, want %v", got, tc.gzip)
				}
				if body := gzipTestBody(t, r); !bytes.Equal(body, expected) {
					t.Errorf("body = %q", body)
				}
				if r.Header.Get("X-Test-Credential") != "kept" {
					t.Error("write header lost")
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
				// Separate clients must share the exact-base capability cache.
				c, _ := New(srv.URL + "/api")
				resp, err := c.DoRawWithHeaders(context.Background(), method, "/v1/test", "application/json", input, map[string]string{"X-Test-Credential": "kept"})
				if err != nil {
					t.Fatal(err)
				}
				resp.Body.Close()
			}
			if probes.Load() != 1 {
				t.Errorf("health probes = %d, want 1", probes.Load())
			}
		})
	}
}

func TestClientRequestCompressionSignsDecodedBytes(t *testing.T) {
	pub, key, _ := ed25519.GenerateKey(nil)
	for _, kind := range []string{"identity", "certificate", "grant"} {
		t.Run(kind, func(t *testing.T) {
			input := map[string]string{"body": "signed original"}
			original, _ := json.Marshal(input)
			srv := newCompressionTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/health" {
					w.Header().Set("Accept-Encoding", "gzip")
					return
				}
				if r.Header.Get("Content-Encoding") != "gzip" {
					t.Error("write was not compressed")
				}
				decoded := gzipTestBody(t, r)
				if !bytes.Equal(decoded, original) {
					t.Error("decoded body changed")
				}
				timestamp := r.Header.Get("X-AWEB-Timestamp")
				hash := sha256.Sum256(decoded)
				bodyHash := hex.EncodeToString(hash[:])
				var signed []byte
				auth := strings.Fields(r.Header.Get("Authorization"))
				signed, _ = base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
				var fields map[string]any
				if err := json.Unmarshal(signed, &fields); err != nil {
					t.Error(err)
				}
				if fields["body_sha256"] != bodyHash || fields["path"] != r.RequestURI || fields["timestamp"] != timestamp {
					t.Errorf("request binding = %v", fields)
				}
				if kind == "grant" {
					if fields["grant_id"] != "test-grant" {
						t.Errorf("grant binding = %v", fields)
					}
				} else if fields["v"] != float64(2) {
					t.Errorf("root auth is not v2: %v", fields)
				}

				signature, err := base64.RawStdEncoding.DecodeString(auth[len(auth)-1])
				if err != nil || !ed25519.Verify(pub, signed, signature) {
					t.Error("signature does not verify against decoded bytes")
				}
				w.Write([]byte(`{}`))
			}))
			defer srv.Close()
			var c *Client
			var err error
			switch kind {
			case "identity":
				c, err = NewWithIdentity(srv.URL, key, ComputeDIDKey(pub))
			case "certificate":
				c, err = NewWithCertificate(srv.URL, key, &TeamCertificate{Version: 1, Team: "core:example.test", MemberDIDKey: ComputeDIDKey(pub), IdentityScope: IdentityModeLocal})
			case "grant":
				c, err = NewWithGrant(srv.URL, key, "test-grant")
			}
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.DoRaw(context.Background(), "POST", "/v1/test", "application/json", input)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
		})
	}
}

func TestClientRequestCompressionRefusalDisablesWithoutReplay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		status  int
		body    string
		disable bool
	}{
		{"decoder", 400, "Invalid gzip request body", true},
		{"unsupported", 415, "Unsupported Content-Encoding", true},
		{"application", 400, `{"detail":"bad state"}`, false},
		{"application_json_lookalike", 400, `{"detail":"Invalid gzip request body"}`, false},
		{"application_long", 400, strings.Repeat("application refusal ", 10000), false},
		{"application_plain_lookalike", 400, "Invalid gzip request body!", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var probes, writes atomic.Int32
			srv := newCompressionTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Accept-Encoding", "gzip")
				if r.URL.Path == "/health" {
					probes.Add(1)
					return
				}
				n := writes.Add(1)
				compressed := r.Header.Get("Content-Encoding") == "gzip"
				if compressed != (n == 1 || !tc.disable) {
					t.Errorf("write %d compressed=%v", n, compressed)
				}
				if n == 1 {
					w.WriteHeader(tc.status)
					w.Write([]byte(tc.body))
				} else {
					w.Write([]byte(`{}`))
				}
			}))
			defer srv.Close()
			for n := 0; n < 2; n++ {
				c, _ := New(srv.URL)
				resp, err := c.DoRaw(context.Background(), "POST", "/v1/messages", "application/json", map[string]string{"message_id": "same-id", "body": "test"})
				if err != nil {
					t.Fatal(err)
				}
				body, err := io.ReadAll(resp.Body)
				resp.Body.Close()
				if err != nil {
					t.Fatal(err)
				}
				if n == 0 && (resp.StatusCode != tc.status || string(body) != tc.body) {
					t.Errorf("response changed: status=%d body length=%d", resp.StatusCode, len(body))
				}
			}
			if writes.Load() != 2 || probes.Load() != 1 {
				t.Errorf("writes=%d probes=%d", writes.Load(), probes.Load())
			}
		})
	}
}

func TestClientRequestCompressionConcurrentCacheAndMountIsolation(t *testing.T) {
	var probes [2]atomic.Int32
	srv := newCompressionTestServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mount := 0
		if strings.HasPrefix(r.URL.Path, "/other/") {
			mount = 1
		}
		if strings.HasSuffix(r.URL.Path, "/health") {
			probes[mount].Add(1)
			if mount == 0 {
				w.Header().Set("Accept-Encoding", "gzip")
			}
			return
		}
		if got := r.Header.Get("Content-Encoding") == "gzip"; got != (mount == 0) {
			t.Errorf("mount %d gzip=%v", mount, got)
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	var wg sync.WaitGroup
	for n := 0; n < 12; n++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			mount := "/api"
			if n%2 == 1 {
				mount = "/other"
			}
			c, _ := New(srv.URL + mount)
			resp, err := c.DoRaw(context.Background(), "POST", "/v1/test", "application/json", map[string]string{"body": "test"})
			if err != nil {
				t.Error(err)
				return
			}
			resp.Body.Close()
		}(n)
	}
	wg.Wait()
	if probes[0].Load() != 1 || probes[1].Load() != 1 {
		t.Errorf("probes=%d/%d", probes[0].Load(), probes[1].Load())
	}
}

// Existing request fixtures model servers without request-gzip support. Keep
// their write assertions independent from the capability discovery GET.
func serveUnadvertisedHealth(w http.ResponseWriter, r *http.Request) bool {
	if r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/health") {
		w.WriteHeader(http.StatusNotFound)
		return true
	}
	return false
}
