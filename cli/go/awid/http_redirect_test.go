package awid

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestTrustRequestsDoNotFollowRedirects(t *testing.T) {
	_, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))

	tests := []struct {
		name             string
		expectsAuthority bool
		invoke           func(string) error
	}{
		{
			name: "service discovery",
			invoke: func(baseURL string) error {
				_, err := DiscoverServices(context.Background(), baseURL)
				return err
			},
		},
		{
			name:             "standard API request",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				client, err := NewWithIdentity(baseURL, signingKey, did)
				if err != nil {
					return err
				}
				client.SetStableID("did:aw:test")
				var out map[string]any
				return client.Get(context.Background(), "/v1/trust", &out)
			},
		},
		{
			name:             "event SSE handshake",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				client, err := NewWithIdentity(baseURL, signingKey, did)
				if err != nil {
					return err
				}
				stream, err := client.EventStream(context.Background(), time.Now().Add(time.Minute))
				if stream != nil {
					_ = stream.Close()
				}
				return err
			},
		},
		{
			name:             "chat SSE handshake",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				client, err := NewWithIdentity(baseURL, signingKey, did)
				if err != nil {
					return err
				}
				stream, err := client.ChatStream(context.Background(), "session", time.Now().Add(time.Minute), nil)
				if stream != nil {
					_ = stream.Close()
				}
				return err
			},
		},
		{
			name:             "claim human",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				client, err := NewWithIdentity(baseURL, signingKey, did)
				if err != nil {
					return err
				}
				_, err = client.ClaimHuman(context.Background(), &ClaimHumanRequest{Username: "alice", Email: "alice@example.com", DIDKey: did})
				return err
			},
		},
		{
			name:             "bootstrap redeem",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				client, err := NewWithIdentity(baseURL, signingKey, did)
				if err != nil {
					return err
				}
				_, err = client.BootstrapRedeem(context.Background(), &BootstrapRedeemRequest{Token: "secret-bootstrap-token", DIDKey: did})
				return err
			},
		},
		{
			name:             "CLI signup",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				_, err := CliSignup(context.Background(), baseURL, &CliSignupRequest{Username: "alice", DIDKey: did, DIDAW: "did:aw:test", Alias: "alice"}, signingKey)
				return err
			},
		},
		{
			name:             "spawn invite acceptance",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				client, err := NewWithIdentity(baseURL, signingKey, did)
				if err != nil {
					return err
				}
				_, err = client.AcceptSpawnInvite(context.Background(), &SpawnAcceptInviteRequest{Token: "secret-invite-token", DID: did})
				return err
			},
		},
		{
			name:             "signed registry request",
			expectsAuthority: true,
			invoke: func(baseURL string) error {
				client := NewAWIDRegistryClient(nil, nil)
				_, err := client.GetDIDFull(context.Background(), baseURL, "did:aw:test", signingKey)
				return err
			},
		},
		{
			name: "registry resolver request",
			invoke: func(baseURL string) error {
				resolver := NewRegistryResolver(nil, nil)
				_, err := resolver.resolveKeyFresh(context.Background(), baseURL, "did:aw:test", true)
				return err
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var targetHits atomic.Int32
			target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				targetHits.Add(1)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(`{}`))
			}))
			t.Cleanup(target.Close)

			var sourceHits atomic.Int32
			source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				sourceHits.Add(1)
				if test.expectsAuthority && r.Header.Get("Authorization") == "" {
					t.Error("production request did not carry the expected authority header")
				}
				http.Redirect(w, r, target.URL+r.URL.Path, http.StatusTemporaryRedirect)
			}))
			t.Cleanup(source.Close)

			_ = test.invoke(source.URL)
			if sourceHits.Load() != 1 {
				t.Fatalf("redirect source received %d requests, want 1", sourceHits.Load())
			}
			if targetHits.Load() != 0 {
				t.Fatalf("redirect target received %d requests, want 0", targetHits.Load())
			}
		})
	}
}
