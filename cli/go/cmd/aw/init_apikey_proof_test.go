package main

import (
	"compress/gzip"
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

// testWorkspaceInitKey signs workspaces/init in tests that do not inspect the proof.
var testWorkspaceInitKey = func() ed25519.PrivateKey {
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		panic(err)
	}
	return key
}()

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

	awid.ForgetRequestCompression(server.URL)
	if _, err := postAPIKeyWorkspaceInit(context.Background(), server.URL, "aw_sk_test", apiKeyBootstrapRequest{DID: didKey, Alias: "alice"}, signingKey); err != nil {
		t.Fatal(err)
	}
	if got := gotHeader.Get("Authorization"); got != "Bearer aw_sk_test" {
		t.Fatalf("Authorization = %q, want the Bearer team key unchanged", got)
	}
	timestamp := gotHeader.Get("X-AWEB-DIDKey-Timestamp")
	when, err := time.Parse(time.RFC3339, timestamp)
	if err != nil || time.Since(when).Abs() > time.Minute {
		t.Fatalf("X-AWEB-DIDKey-Timestamp = %q", timestamp)
	}
	// X-AWEB-Timestamp would make Cloud's auth bridge treat the request as a
	// malformed team-certificate call and refuse it before the init handler.
	if values := gotHeader.Values("X-AWEB-Timestamp"); len(values) != 0 {
		t.Fatalf("X-AWEB-Timestamp = %q, want none", values)
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
	awid.ForgetRequestCompression(server.URL)
	if _, err := postAPIKeyWorkspaceInit(context.Background(), server.URL, "aw_sk_test", apiKeyBootstrapRequest{}, nil); err == nil {
		t.Fatal("expected a refusal without the agent's signing key")
	}
}

// With gzip negotiated, the proof still covers the decoded body bytes, which
// is what a server checks after decoding.
func TestWorkspaceInitProofCoversTheDecodedBodyWhenGzipped(t *testing.T) {
	t.Parallel()
	_, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	var encoding, timestamp, proof string
	var decoded []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			w.Header().Set("Accept-Encoding", "gzip")
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		encoding = r.Header.Get("Content-Encoding")
		timestamp = r.Header.Get("X-AWEB-DIDKey-Timestamp")
		proof = r.Header.Get("X-AWEB-DIDKey-Signature")
		body := io.Reader(r.Body)
		if encoding == "gzip" {
			zr, err := gzip.NewReader(r.Body)
			if err != nil {
				t.Error(err)
				return
			}
			body = zr
		}
		decoded, _ = io.ReadAll(body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"server_url":"http://example.test","alias":"alice","did":"` + didKey + `"}`))
	}))
	defer server.Close()

	awid.ForgetRequestCompression(server.URL)
	if _, err := postAPIKeyWorkspaceInit(context.Background(), server.URL, "aw_sk_test", apiKeyBootstrapRequest{DID: didKey, Alias: "alice"}, signingKey); err != nil {
		t.Fatal(err)
	}
	if encoding != "gzip" {
		t.Fatalf("Content-Encoding = %q, want gzip after the server advertised it", encoding)
	}
	parts := strings.Fields(proof)
	if len(parts) != 3 {
		t.Fatalf("proof = %q", proof)
	}
	signature, _ := base64.RawStdEncoding.DecodeString(parts[2])
	digest := sha256.Sum256(decoded)
	envelope, _ := json.Marshal(map[string]string{
		"body_sha256": hex.EncodeToString(digest[:]),
		"method":      "POST",
		"path":        "/api/v1/workspaces/init",
		"timestamp":   timestamp,
	})
	if !ed25519.Verify(signingKey.Public().(ed25519.PublicKey), envelope, signature) {
		t.Fatal("proof does not verify over the decoded body")
	}
}
