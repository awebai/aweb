package aweb

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestIdentityGrant404RequiresServer1272(t *testing.T) {
	tests := []struct {
		name       string
		wantMethod string
		wantPath   string
		invoke     func(context.Context, *Client) error
	}{
		{
			name:       "mint",
			wantMethod: http.MethodPost,
			wantPath:   "/v1/identity-grants",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.MintIdentityGrant(ctx, &IdentityGrantMintRequest{})
				return err
			},
		},
		{
			name:       "list",
			wantMethod: http.MethodGet,
			wantPath:   "/v1/identity-grants",
			invoke: func(ctx context.Context, client *Client) error {
				_, err := client.ListIdentityGrants(ctx)
				return err
			},
		},
		{
			name:       "revoke",
			wantMethod: http.MethodPost,
			wantPath:   "/v1/identity-grants/grant-1/revoke",
			invoke: func(ctx context.Context, client *Client) error {
				return client.RevokeIdentityGrant(ctx, "grant-1")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotMethod, gotPath string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotMethod = r.Method
				gotPath = r.URL.Path
				http.Error(w, "route absent", http.StatusNotFound)
			}))
			t.Cleanup(server.Close)

			client, err := New(server.URL)
			if err != nil {
				t.Fatal(err)
			}
			err = tt.invoke(context.Background(), client)
			if err == nil || !strings.Contains(err.Error(), "identity grants require aweb server 1.27.2 or later") {
				t.Fatalf("error=%v, want minimum-server diagnostic", err)
			}
			if gotMethod != tt.wantMethod || gotPath != tt.wantPath {
				t.Fatalf("request=(%s %s), want (%s %s)", gotMethod, gotPath, tt.wantMethod, tt.wantPath)
			}
		})
	}
}

func TestIdentityGrantNon404PreservesOriginalError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "grant backend unavailable", http.StatusBadGateway)
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ListIdentityGrants(context.Background())
	if err == nil || !strings.Contains(err.Error(), "grant backend unavailable") {
		t.Fatalf("error=%v, want original backend error", err)
	}
	if strings.Contains(err.Error(), "requires aweb server") {
		t.Fatalf("non-404 error was rewritten as a compatibility diagnostic: %v", err)
	}
}

func TestMintIdentityGrantSendsWireContractBody(t *testing.T) {
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/identity-grants" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Errorf("decode mint body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(IdentityGrantView{
			GrantID:      "grant-42",
			TeamID:       "backend:acme.com",
			SubjectAlias: "alice",
			SubjectDIDAW: "did:aw:alice",
			GrantDIDKey:  "did:key:zSession",
			Scopes:       []string{"mail.read", "mail.send"},
			IssuedAt:     "2026-08-12T00:00:00Z",
			ExpiresAt:    "2026-08-12T08:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	client, err := New(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	view, err := client.MintIdentityGrant(context.Background(), &IdentityGrantMintRequest{
		GrantDIDKey: "did:key:zSession",
		Scopes:      []string{"mail.read", "mail.send"},
		TTLSeconds:  28800,
		Label:       "worker",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotBody["grant_did_key"] != "did:key:zSession" || gotBody["label"] != "worker" {
		t.Fatalf("mint body=%v", gotBody)
	}
	if ttl, ok := gotBody["ttl_seconds"].(float64); !ok || int(ttl) != 28800 {
		t.Fatalf("ttl_seconds=%v", gotBody["ttl_seconds"])
	}
	scopes, _ := gotBody["scopes"].([]any)
	if len(scopes) != 2 || scopes[0] != "mail.read" || scopes[1] != "mail.send" {
		t.Fatalf("scopes=%v", gotBody["scopes"])
	}
	if view.GrantID != "grant-42" || view.TeamID != "backend:acme.com" || view.ExpiresAt != "2026-08-12T08:00:00Z" {
		t.Fatalf("view=%+v", view)
	}
}

func TestGrantAuthenticatedRequestsCarryCredentialHeaders(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	sessionDID := awid.ComputeDIDKey(pub)
	const grantID = "5f0f9f4e-6f4e-4a52-a2e4-7d1c3f9b1a11"

	tests := []struct {
		name       string
		method     string
		path       string
		body       any
		invoke     func(context.Context, *Client) error
		wantMethod string
	}{
		{
			name:   "post with body",
			method: http.MethodPost,
			path:   "/v1/messages",
			body:   map[string]string{"subject": "hi"},
			invoke: func(ctx context.Context, client *Client) error {
				return client.Post(ctx, "/v1/messages", map[string]string{"subject": "hi"}, nil)
			},
		},
		{
			name:   "get without body",
			method: http.MethodGet,
			path:   "/v1/agents",
			invoke: func(ctx context.Context, client *Client) error {
				return client.Get(ctx, "/v1/agents", nil)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var gotHeader http.Header
			var gotBody []byte
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				gotHeader = r.Header.Clone()
				gotBody, _ = io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte("{}"))
			}))
			t.Cleanup(server.Close)

			client, err := NewWithGrant(server.URL, priv, grantID)
			if err != nil {
				t.Fatal(err)
			}
			if err := tt.invoke(context.Background(), client); err != nil {
				t.Fatal(err)
			}

			authorization := gotHeader.Get("Authorization")
			parts := strings.Fields(authorization)
			if len(parts) != 4 || parts[0] != "AWEB-Grant" || parts[1] != "DIDKey" || parts[2] != sessionDID {
				t.Fatalf("authorization=%q", authorization)
			}
			signature, err := base64.RawStdEncoding.DecodeString(parts[3])
			if err != nil {
				t.Fatalf("decode signature: %v", err)
			}
			if gotHeader.Get("X-AWEB-Grant-ID") != grantID {
				t.Fatalf("grant id header=%q", gotHeader.Get("X-AWEB-Grant-ID"))
			}
			timestamp := gotHeader.Get("X-AWEB-Timestamp")
			if _, err := time.Parse(time.RFC3339, timestamp); err != nil {
				t.Fatalf("timestamp %q: %v", timestamp, err)
			}
			canonical, err := base64.RawURLEncoding.DecodeString(gotHeader.Get("X-AWEB-Signed-Payload"))
			if err != nil {
				t.Fatalf("decode signed payload: %v", err)
			}
			if !ed25519.Verify(pub, canonical, signature) {
				t.Fatal("signature does not verify over the signed payload")
			}

			var payload struct {
				V          int    `json:"v"`
				Auth       string `json:"auth"`
				Aud        string `json:"aud"`
				Method     string `json:"method"`
				Path       string `json:"path"`
				GrantID    string `json:"grant_id"`
				BodySHA256 string `json:"body_sha256"`
				Timestamp  string `json:"timestamp"`
			}
			if err := json.Unmarshal(canonical, &payload); err != nil {
				t.Fatalf("decode payload %s: %v", canonical, err)
			}
			if payload.V != 1 || payload.Auth != "identity-grant" {
				t.Fatalf("payload envelope=%+v", payload)
			}
			if payload.Aud != server.URL {
				t.Fatalf("aud=%q want %q", payload.Aud, server.URL)
			}
			if payload.Method != tt.method || payload.Path != tt.path {
				t.Fatalf("payload target=(%s %s), want (%s %s)", payload.Method, payload.Path, tt.method, tt.path)
			}
			if payload.GrantID != grantID {
				t.Fatalf("payload grant_id=%q", payload.GrantID)
			}
			if payload.Timestamp != timestamp {
				t.Fatalf("payload timestamp=%q header=%q", payload.Timestamp, timestamp)
			}
			wantBodyHash := fmt.Sprintf("%x", sha256.Sum256(gotBody))
			if payload.BodySHA256 != wantBodyHash {
				t.Fatalf("body_sha256=%q want %q", payload.BodySHA256, wantBodyHash)
			}
		})
	}
}
