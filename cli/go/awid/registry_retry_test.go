package awid

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
)

type registryRetryRoundTripper func(*http.Request) (*http.Response, error)

func (f registryRetryRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

type registryRetryTimeoutError struct{}

func (registryRetryTimeoutError) Error() string   { return "registry request timed out" }
func (registryRetryTimeoutError) Timeout() bool   { return true }
func (registryRetryTimeoutError) Temporary() bool { return true }

func registryKeyResponse() string {
	return `{"did_aw":"did:aw:test","current_did_key":"did:key:test"}`
}

func TestRegistryClientRetriesServiceUnavailableRead(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if calls.Add(1) == 1 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, registryKeyResponse())
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	resolution, err := client.ResolveKeyAt(context.Background(), server.URL, "did:aw:test")
	if err != nil {
		t.Fatalf("ResolveKeyAt: %v", err)
	}
	if resolution.CurrentDIDKey != "did:key:test" {
		t.Fatalf("current_did_key=%q", resolution.CurrentDIDKey)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
}

func TestRegistryClientRetriesTransientTransportFailures(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		err  error
	}{
		{name: "timeout", err: registryRetryTimeoutError{}},
		{name: "connection reset", err: syscall.ECONNRESET},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			client := NewAWIDRegistryClient(&http.Client{Transport: registryRetryRoundTripper(func(*http.Request) (*http.Response, error) {
				if calls.Add(1) == 1 {
					return nil, tt.err
				}
				return &http.Response{
					StatusCode: http.StatusOK,
					Header:     make(http.Header),
					Body:       io.NopCloser(strings.NewReader(registryKeyResponse())),
				}, nil
			})}, nil)

			if _, err := client.ResolveKeyAt(context.Background(), "https://registry.example", "did:aw:test"); err != nil {
				t.Fatalf("ResolveKeyAt: %v", err)
			}
			if calls.Load() != 2 {
				t.Fatalf("calls=%d, want 2", calls.Load())
			}
		})
	}
}

func TestRegistryClientRetriesInterruptedResponseBody(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	client := NewAWIDRegistryClient(&http.Client{Transport: registryRetryRoundTripper(func(*http.Request) (*http.Response, error) {
		body := registryKeyResponse()
		if calls.Add(1) == 1 {
			body = body[:len(body)/2]
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body: &registryRetryReadCloser{
				Reader: strings.NewReader(body),
				fail:   calls.Load() == 1,
			},
		}, nil
	})}, nil)

	resolution, err := client.ResolveKeyAt(context.Background(), "https://registry.example", "did:aw:test")
	if err != nil {
		t.Fatalf("ResolveKeyAt: %v", err)
	}
	if resolution.CurrentDIDKey != "did:key:test" {
		t.Fatalf("current_did_key=%q", resolution.CurrentDIDKey)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls=%d, want 2", calls.Load())
	}
}

type registryRetryReadCloser struct {
	*strings.Reader
	fail bool
}

func (r *registryRetryReadCloser) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if r.fail && err == io.EOF {
		return n, io.ErrUnexpectedEOF
	}
	return n, err
}

func (*registryRetryReadCloser) Close() error { return nil }

func TestRegistryClientDoesNotRetryNonTransientResponses(t *testing.T) {
	t.Parallel()

	for _, status := range []int{http.StatusUnauthorized, http.StatusTooManyRequests, http.StatusInternalServerError} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			t.Parallel()
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				http.Error(w, http.StatusText(status), status)
			}))
			t.Cleanup(server.Close)

			client := NewAWIDRegistryClient(server.Client(), nil)
			_, err := client.ResolveKeyAt(context.Background(), server.URL, "did:aw:test")
			var registryErr *RegistryError
			if !errors.As(err, &registryErr) || registryErr.StatusCode != status {
				t.Fatalf("error=%v, want RegistryError status %d", err, status)
			}
			if calls.Load() != 1 {
				t.Fatalf("calls=%d, want 1", calls.Load())
			}
		})
	}
}

func TestRegistryRetryBackoffIsBoundedExponential(t *testing.T) {
	t.Parallel()

	for attempt, want := range []int64{100, 200, 400} {
		if got := registryTransientBackoffDelay(attempt).Milliseconds(); got != want {
			t.Errorf("attempt %d delay=%dms, want %dms", attempt, got, want)
		}
	}
}

func TestRegistryClientBoundsServiceUnavailableRetries(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	_, err := client.ResolveKeyAt(context.Background(), server.URL, "did:aw:test")
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) || registryErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("error=%v, want final 503 RegistryError", err)
	}
	if calls.Load() != int32(registryTransientMaxRetries+1) {
		t.Fatalf("calls=%d, want %d", calls.Load(), registryTransientMaxRetries+1)
	}
}

func TestReplaySafeRegistryRequestsAreReadOnly(t *testing.T) {
	t.Parallel()

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodOptions} {
		if !isReplaySafeRegistryRequest(method, "/v1/did/did:aw:test/key") {
			t.Errorf("%s read unexpectedly not retryable", method)
		}
	}
}

func TestRegistryMutationRetryAudit(t *testing.T) {
	t.Parallel()

	// Every mutation formerly allowlisted by the generic transport loop is
	// classified here. Only routes with route-level proof of identical success
	// responses for an exact replay stay admitted; all others need endpoint-
	// specific reconciliation instead of blind resubmission.
	for _, request := range []struct {
		method    string
		path      string
		semantics string
		retry     bool
	}{
		{http.MethodPost, "/v1/did", "exact-idempotent create", true},
		{http.MethodPost, "/v1/did/did:aw:test/encryption-key", "signed state set", false},
		{http.MethodPut, "/v1/did/did:aw:test", "sequence-checked compare-and-swap", false},
		{http.MethodPost, "/v1/namespaces", "conflict-returning create", false},
		{http.MethodPatch, "/v1/namespaces/acme.com", "authorized state set", false},
		{http.MethodDelete, "/v1/namespaces/acme.com", "delete with non-identical replay response", false},
		{http.MethodPost, "/v1/namespaces/acme.com/reverify", "verification state transition", false},
		{http.MethodPost, "/v1/namespaces/acme.com/addresses", "exact-idempotent create", true},
		{http.MethodPost, "/v1/namespaces/acme.com/addresses/claims", "conflict-returning claim", false},
		{http.MethodDelete, "/v1/namespaces/acme.com/addresses/alice", "delete with non-identical replay response", false},
		{http.MethodPost, "/v1/namespaces/acme.com/teams", "conflict-returning create", false},
		{http.MethodPost, "/v1/namespaces/acme.com/teams/backend/visibility", "authorized state set", false},
		{http.MethodDelete, "/v1/namespaces/acme.com/teams/backend", "delete with non-identical replay response", false},
		{http.MethodPost, "/v1/namespaces/acme.com/teams/backend/certificates", "conflict-returning create", false},
		{http.MethodPost, "/v1/namespaces/acme.com/teams/backend/certificates/revoke", "revocation state transition", false},
		{http.MethodPost, "/v1/a2a/delegations", "conflict-returning create", false},
		{http.MethodPost, "/v1/a2a/publications", "conflict-returning create", false},
	} {
		t.Run(request.method+" "+request.path+" ("+request.semantics+")", func(t *testing.T) {
			if got := isReplaySafeRegistryRequest(request.method, request.path); got != request.retry {
				t.Errorf("%s %s (%s) retryable=%t, want %t", request.method, request.path, request.semantics, got, request.retry)
			}
		})
	}
}

func TestRegistryClientDoesNotRetryUnknownPost(t *testing.T) {
	t.Parallel()

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	err := client.requestJSON(context.Background(), http.MethodPost, server.URL, "/v1/future/non-idempotent-action", nil, map[string]string{"value": "one"}, nil)
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) || registryErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("error=%v, want 503 RegistryError", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("503 calls=%d, want 1", calls.Load())
	}

	var transportCalls atomic.Int32
	client = NewAWIDRegistryClient(&http.Client{Transport: registryRetryRoundTripper(func(*http.Request) (*http.Response, error) {
		transportCalls.Add(1)
		return nil, syscall.ECONNRESET
	})}, nil)
	err = client.requestJSON(context.Background(), http.MethodPost, "https://registry.example", "/v1/future/non-idempotent-action", nil, map[string]string{"value": "one"}, nil)
	if !errors.Is(err, syscall.ECONNRESET) {
		t.Fatalf("transport error=%v, want connection reset", err)
	}
	if transportCalls.Load() != 1 {
		t.Fatalf("transport calls=%d, want 1", transportCalls.Load())
	}
}

func TestRegistryClientRetriesExactIdempotentRegisterIdentity(t *testing.T) {
	t.Parallel()

	publicKey, signingKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := ComputeDIDKey(publicKey)
	didAW := ComputeStableID(publicKey)
	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			if posts.Add(1) == 1 {
				http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/did/"+didAW+"/full":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          didAW,
				"current_did_key": didKey,
				"created_at":      "2026-07-23T00:00:00Z",
				"updated_at":      "2026-07-23T00:00:00Z",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	if _, err := client.RegisterIdentity(context.Background(), server.URL, didKey, didAW, signingKey); err != nil {
		t.Fatalf("RegisterIdentity: %v", err)
	}
	if posts.Load() != 2 {
		t.Fatalf("register posts=%d, want 2", posts.Load())
	}
}

func TestRegistryClientDoesNotGenericallyRetryRegisterCertificate(t *testing.T) {
	t.Parallel()

	_, teamKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPublicKey, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := SignTeamCertificate(teamKey, TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  ComputeDIDKey(memberPublicKey),
		Alias:         "alice",
		IdentityScope: IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}

	var posts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/namespaces/acme.com/teams/backend/certificates" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if posts.Add(1) == 1 {
			http.Error(w, "temporarily unavailable", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusCreated)
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	err = client.RegisterCertificate(context.Background(), server.URL, "acme.com", "backend", certificate, teamKey)
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) || registryErr.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("RegisterCertificate error=%v, want 503 RegistryError", err)
	}
	if posts.Load() != 1 {
		t.Fatalf("certificate posts=%d, want 1", posts.Load())
	}
}
