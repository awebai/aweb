package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClientResponseLimitRejectsOversizeWithoutRejectingExactLimit(t *testing.T) {
	tests := []struct {
		name      string
		bodySize  int
		wantError bool
	}{
		{name: "exact limit", bodySize: MaxResponseSize, wantError: false},
		{name: "limit plus one", bodySize: MaxResponseSize + 1, wantError: true},
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

func TestTraceResponseCannotReadPastResponseLimit(t *testing.T) {
	t.Setenv("AW_TRACE", "1")
	body := bytes.Repeat([]byte("x"), MaxResponseSize+4096)
	counting := &countingReader{reader: bytes.NewReader(body)}
	resp := &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(counting)}

	if err := traceHTTPClientResponse(resp); err == nil {
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
