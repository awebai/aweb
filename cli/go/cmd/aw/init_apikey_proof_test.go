package main

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// The workspaces/init request proves the caller holds the agent's did:key
// with cli-signup's DIDKey envelope, carried beside the Bearer team key.
func TestPostAPIKeyWorkspaceInitProvesTheDIDKeyHolder(t *testing.T) {
	t.Parallel()
	_, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))

	var gotHeader http.Header
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHeader = r.Header.Clone()
		gotBody, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"server_url":"http://example.test","alias":"alice","did":"` + didKey + `"}`))
	}))
	defer server.Close()

	if _, err := postAPIKeyWorkspaceInit(context.Background(), server.URL, "aw_sk_test", apiKeyBootstrapRequest{DID: didKey, Alias: "alice"}, signingKey); err != nil {
		t.Fatal(err)
	}
	if got := gotHeader.Get("Authorization"); got != "Bearer aw_sk_test" {
		t.Fatalf("Authorization = %q, want the Bearer team key unchanged", got)
	}
	timestamp := gotHeader.Get("X-AWEB-Timestamp")
	when, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(when).Abs() > time.Minute {
		t.Fatalf("X-AWEB-Timestamp = %q", timestamp)
	}
	parts := strings.Fields(gotHeader.Get("X-AWEB-DIDKey-Signature"))
	if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != didKey {
		t.Fatalf("X-AWEB-DIDKey-Signature = %q, want DIDKey <the body's did:key> <signature>", gotHeader.Get("X-AWEB-DIDKey-Signature"))
	}
	signature, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature is not raw standard base64: %v", err)
	}
	digest := sha256.Sum256(gotBody)
	envelope, _ := json.Marshal(map[string]string{
		"body_sha256": hex.EncodeToString(digest[:]),
		"method":      "POST",
		"path":        "/api/v1/workspaces/init",
		"timestamp":   timestamp,
	})
	if !ed25519.Verify(signingKey.Public().(ed25519.PublicKey), envelope, signature) {
		t.Fatalf("signature does not verify over %s", envelope)
	}
	_, otherKey, _ := ed25519.GenerateKey(nil)
	if ed25519.Verify(otherKey.Public().(ed25519.PublicKey), envelope, signature) {
		t.Fatal("signature verifies under an unrelated key")
	}
}

func TestPostAPIKeyWorkspaceInitRefusesWithoutASigningKey(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("an unproven request reached the server")
	}))
	defer server.Close()
	if _, err := postAPIKeyWorkspaceInit(context.Background(), server.URL, "aw_sk_test", apiKeyBootstrapRequest{}, nil); err == nil {
		t.Fatal("expected a refusal without the agent's signing key")
	}
}
