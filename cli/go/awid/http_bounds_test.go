package awid

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestTrustHTTPBoundValuesArePinned(t *testing.T) {
	const pinnedResponseLimit = 10 * 1024 * 1024
	const pinnedErrorLimit = 64 * 1024
	if MaxResponseSize != pinnedResponseLimit {
		t.Fatalf("MaxResponseSize=%d, security policy requires %d", MaxResponseSize, pinnedResponseLimit)
	}
	if MaxErrorResponseSize != pinnedErrorLimit {
		t.Fatalf("MaxErrorResponseSize=%d, security policy requires %d", MaxErrorResponseSize, pinnedErrorLimit)
	}
}

func TestClientResponseLimitRejectsOversizeWithoutRejectingExactLimit(t *testing.T) {
	const pinnedResponseLimit = 10 * 1024 * 1024
	tests := []struct {
		name      string
		bodySize  int
		wantError bool
	}{
		{name: "exact limit", bodySize: pinnedResponseLimit, wantError: false},
		{name: "limit plus one", bodySize: pinnedResponseLimit + 1, wantError: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{}`+strings.Repeat(" ", test.bodySize-2))
			}))
			t.Cleanup(server.Close)
			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			var out map[string]any
			err = client.Get(context.Background(), "/v1/trust", &out)
			if test.wantError && err == nil {
				t.Fatal("oversize response was accepted")
			}
			if !test.wantError && err != nil {
				t.Fatalf("exact-limit response was rejected: %v", err)
			}
		})
	}
}

func TestTrustResponsesRequireOneJSONDocument(t *testing.T) {
	tests := []struct {
		name      string
		response  string
		wantError bool
		invoke    func(string) error
	}{
		{
			name:     "standard API allows trailing whitespace",
			response: "{} \r\n\t",
			invoke: func(baseURL string) error {
				client, err := New(baseURL)
				if err != nil {
					return err
				}
				var out map[string]any
				return client.Get(context.Background(), "/v1/trust", &out)
			},
		},
		{
			name:      "standard API rejects second document",
			response:  "{}\n{}",
			wantError: true,
			invoke: func(baseURL string) error {
				client, err := New(baseURL)
				if err != nil {
					return err
				}
				var out map[string]any
				return client.Get(context.Background(), "/v1/trust", &out)
			},
		},
		{
			name:     "registry resolver allows trailing whitespace",
			response: "{\"did_aw\":\"did:aw:test\",\"current_did_key\":\"did:key:test\"} \r\n\t",
			invoke: func(baseURL string) error {
				_, err := NewRegistryResolver(nil, nil).resolveKeyFresh(context.Background(), baseURL, "did:aw:test", true)
				return err
			},
		},
		{
			name:      "registry resolver rejects second document",
			response:  "{\"did_aw\":\"did:aw:test\",\"current_did_key\":\"did:key:test\"}\n{}",
			wantError: true,
			invoke: func(baseURL string) error {
				_, err := NewRegistryResolver(nil, nil).resolveKeyFresh(context.Background(), baseURL, "did:aw:test", true)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, test.response)
			}))
			t.Cleanup(server.Close)

			err := test.invoke(server.URL)
			if test.wantError && err == nil {
				t.Fatal("under-limit second JSON document was accepted")
			}
			if !test.wantError && err != nil {
				t.Fatalf("trailing JSON whitespace was rejected: %v", err)
			}
		})
	}
}

func TestTrustEntryPointsRejectOversizeResponses(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	tests := []struct {
		name   string
		invoke func(string) error
	}{
		{name: "claim human", invoke: func(baseURL string) error {
			client, err := NewWithIdentity(baseURL, signingKey, did)
			if err != nil {
				return err
			}
			_, err = client.ClaimHuman(context.Background(), &ClaimHumanRequest{Username: "alice", Email: "alice@example.com", DIDKey: did})
			return err
		}},
		{name: "bootstrap redeem", invoke: func(baseURL string) error {
			client, err := NewWithIdentity(baseURL, signingKey, did)
			if err != nil {
				return err
			}
			_, err = client.BootstrapRedeem(context.Background(), &BootstrapRedeemRequest{Token: "token", DIDKey: did})
			return err
		}},
		{name: "CLI signup", invoke: func(baseURL string) error {
			_, err := CliSignup(context.Background(), baseURL, &CliSignupRequest{Username: "alice", DIDKey: did, DIDAW: "did:aw:test", Alias: "alice"}, signingKey)
			return err
		}},
		{name: "spawn invite acceptance", invoke: func(baseURL string) error {
			client, err := NewWithIdentity(baseURL, signingKey, did)
			if err != nil {
				return err
			}
			_, err = client.AcceptSpawnInvite(context.Background(), &SpawnAcceptInviteRequest{Token: "token", DID: did})
			return err
		}},
		{name: "registry client", invoke: func(baseURL string) error {
			_, err := NewAWIDRegistryClient(nil, nil).GetDIDFull(context.Background(), baseURL, "did:aw:test", signingKey)
			return err
		}},
		{name: "registry resolver", invoke: func(baseURL string) error {
			_, err := NewRegistryResolver(nil, nil).resolveKeyFresh(context.Background(), baseURL, "did:aw:test", true)
			return err
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{}`+strings.Repeat(" ", MaxResponseSize-1))
			}))
			t.Cleanup(server.Close)
			if err := test.invoke(server.URL); err == nil {
				t.Fatal("oversize response was accepted")
			}
		})
	}
}

func TestClientRejectsDecompressedResponseOverLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		compressed := gzip.NewWriter(w)
		_, _ = io.WriteString(compressed, `{}`+strings.Repeat(" ", MaxResponseSize-1))
		_ = compressed.Close()
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := client.Get(context.Background(), "/v1/trust", &out); err == nil {
		t.Fatal("oversize decompressed response was accepted")
	}
}

func TestInjectedNormalHTTPClientCannotRemoveOverallDeadline(t *testing.T) {
	t.Setenv(APITimeoutEnvVar, "10ms")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(100 * time.Millisecond)
		_, _ = io.WriteString(w, `{}`)
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	client.SetHTTPClient(&http.Client{})
	var out map[string]any
	if err := client.Get(context.Background(), "/v1/trust", &out); err == nil {
		t.Fatal("injected zero-timeout client removed the trust request deadline")
	}
}

func TestClientBoundsAndSanitizesErrorExcerpt(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, "bad\x1b[31m\n"+strings.Repeat("x", MaxErrorResponseSize+1024))
	}))
	t.Cleanup(server.Close)
	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	err = client.Get(context.Background(), "/v1/trust", &out)
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		t.Fatalf("error=%v, want APIError", err)
	}
	if len(apiErr.Body) > MaxErrorResponseSize || strings.Contains(apiErr.Body, "\x1b") || strings.Contains(apiErr.Body, "\n") {
		t.Fatalf("unsafe error excerpt length=%d body-prefix=%q", len(apiErr.Body), apiErr.Body[:min(len(apiErr.Body), 32)])
	}
}

func TestRegistryErrorsSanitizeEscapedControlsAfterJSONDecode(t *testing.T) {
	tests := []struct {
		name   string
		invoke func(*http.Client, string) error
	}{
		{
			name: "registry client",
			invoke: func(httpClient *http.Client, baseURL string) error {
				_, err := NewAWIDRegistryClient(httpClient, nil).ResolveKeyAt(context.Background(), baseURL, "did:aw:test")
				return err
			},
		},
		{
			name: "registry resolver",
			invoke: func(httpClient *http.Client, baseURL string) error {
				_, err := NewRegistryResolver(httpClient, nil).resolveKeyFresh(context.Background(), baseURL, "did:aw:test", true)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = io.WriteString(w, `{"detail":"bad\n\u001b[31m"}`)
			}))
			t.Cleanup(server.Close)

			err := test.invoke(server.Client(), server.URL)
			body, ok := HTTPErrorBody(err)
			if !ok {
				t.Fatalf("error=%v, want HTTP error", err)
			}
			if body != "bad [31m" {
				t.Fatalf("unsafe decoded error body %q", body)
			}
		})
	}
}

func TestRegistryErrorSanitizesEscapedStructuredMessage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"detail":{"code":"bad\u001b[31m","message":"bad\n\u001b[31m"}}`)
	}))
	t.Cleanup(server.Close)

	_, err := NewAWIDRegistryClient(server.Client(), nil).ResolveKeyAt(context.Background(), server.URL, "did:aw:test")
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) {
		t.Fatalf("error=%v, want RegistryError", err)
	}
	if registryErr.Code != "bad [31m" {
		t.Fatalf("unsafe decoded registry code %q", registryErr.Code)
	}
	if registryErr.Message != "bad [31m" {
		t.Fatalf("unsafe decoded registry message %q", registryErr.Message)
	}
}

func TestTrustClientsCloseBodiesAfterRepeatedResponses(t *testing.T) {
	const attempts = 4
	normalRequest := func(httpClient *http.Client) error {
		client, err := New("https://trust.example")
		if err != nil {
			return err
		}
		client.SetHTTPClient(httpClient)
		var out map[string]any
		return client.Get(context.Background(), "/v1/trust", &out)
	}
	tests := []struct {
		name       string
		trace      string
		statusCode int
		body       func() io.Reader
		invoke     func(*http.Client) error
		wantError  bool
	}{
		{
			name:       "normal client trace success",
			trace:      "1",
			statusCode: http.StatusOK,
			body: func() io.Reader {
				return strings.NewReader("{}")
			},
			invoke: normalRequest,
		},
		{
			name:       "normal client trace oversize",
			trace:      "1",
			statusCode: http.StatusOK,
			body: func() io.Reader {
				return io.LimitReader(zeroReader{}, 10*1024*1024+1)
			},
			invoke:    normalRequest,
			wantError: true,
		},
		{
			name:       "normal client remote error",
			statusCode: http.StatusInternalServerError,
			body: func() io.Reader {
				return strings.NewReader("malicious error")
			},
			invoke:    normalRequest,
			wantError: true,
		},
		{
			name:       "registry client malformed JSON",
			statusCode: http.StatusOK,
			body: func() io.Reader {
				return strings.NewReader("{\"did_aw\":\"did:aw:test\",\"current_did_key\":\"did:key:test\"}\n{}")
			},
			invoke: func(httpClient *http.Client) error {
				_, err := NewAWIDRegistryClient(httpClient, nil).ResolveKeyAt(context.Background(), "https://trust.example", "did:aw:test")
				return err
			},
			wantError: true,
		},
		{
			name:       "registry resolver malformed JSON",
			statusCode: http.StatusOK,
			body: func() io.Reader {
				return strings.NewReader("{\"did_aw\":\"did:aw:test\",\"current_did_key\":\"did:key:test\"}\n{}")
			},
			invoke: func(httpClient *http.Client) error {
				_, err := NewRegistryResolver(httpClient, nil).resolveKeyFresh(context.Background(), "https://trust.example", "did:aw:test", true)
				return err
			},
			wantError: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("AW_TRACE", test.trace)
			closed := 0
			httpClient := &http.Client{Transport: cleanupRoundTripper(func(req *http.Request) *http.Response {
				return &http.Response{
					StatusCode: test.statusCode,
					Header:     make(http.Header),
					Body: &cleanupBody{
						Reader:  test.body(),
						onClose: func() { closed++ },
					},
					Request: req,
				}
			})}

			for range attempts {
				err := test.invoke(httpClient)
				if test.wantError && err == nil {
					t.Fatal("malicious response was accepted")
				}
				if !test.wantError && err != nil {
					t.Fatalf("valid response failed: %v", err)
				}
			}
			if closed != attempts {
				t.Fatalf("closed %d original response bodies after %d requests", closed, attempts)
			}
		})
	}
}

type cleanupRoundTripper func(*http.Request) *http.Response

func (f cleanupRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req), nil
}

type cleanupBody struct {
	io.Reader
	onClose  func()
	closeErr error
}

func (b *cleanupBody) Close() error {
	b.onClose()
	return b.closeErr
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

func TestTraceResponsePropagatesOriginalBodyCloseError(t *testing.T) {
	t.Setenv("AW_TRACE", "1")
	closeErr := errors.New("close failed")
	closed := 0
	resp := &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body: &cleanupBody{
			Reader:   strings.NewReader("{}"),
			onClose:  func() { closed++ },
			closeErr: closeErr,
		},
	}

	if err := TraceHTTPResponse(resp); !errors.Is(err, closeErr) {
		t.Fatalf("error=%v, want close error", err)
	}
	if closed != 1 {
		t.Fatalf("original body closed %d times, want 1", closed)
	}
	if resp.Body != http.NoBody {
		t.Fatal("failed original body remained reachable after close")
	}
}

func TestTraceResponseCannotReadPastResponseLimit(t *testing.T) {
	t.Setenv("AW_TRACE", "1")
	body := bytes.Repeat([]byte("x"), MaxResponseSize+4096)
	counting := &countingReader{reader: bytes.NewReader(body)}
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(counting)}

	if err := TraceHTTPResponse(resp); err == nil {
		t.Fatal("trace accepted an oversize response")
	}
	if counting.read > MaxResponseSize+1 {
		t.Fatalf("trace read %d bytes, want at most %d", counting.read, MaxResponseSize+1)
	}
}

type countingReader struct {
	reader io.Reader
	read   int
}

func (r *countingReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.read += n
	return n, err
}
