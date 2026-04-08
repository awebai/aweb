package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestClaimHuman(t *testing.T) {
	t.Parallel()

	var gotBodyBytes []byte
	var gotBody map[string]any
	var gotAuth string
	var gotTimestamp string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != onboardingClaimHumanPath {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		gotAuth = r.Header.Get("Authorization")
		gotTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		var err error
		gotBodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(gotBodyBytes, &gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "verification_sent",
			"email":  "alice@example.com",
		})
	}))
	t.Cleanup(server.Close)

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := ComputeDIDKey(pub)

	c, err := NewWithIdentity(server.URL, "", priv, didKey)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := c.ClaimHuman(context.Background(), &ClaimHumanRequest{
		Username: "alice",
		Email:    "alice@example.com",
		DIDKey:   didKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	parts := strings.Fields(gotAuth)
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("auth=%q", gotAuth)
	}
	if parts[1] != didKey {
		t.Fatalf("did=%q want %q", parts[1], didKey)
	}

	sigPayload := onboardingDIDKeySignPayload(http.MethodPost, onboardingClaimHumanPath, gotTimestamp, gotBodyBytes)
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, sigPayload, sig) {
		t.Fatal("claim-human signature did not verify")
	}

	// Verify request body.
	if gotBody["username"] != "alice" {
		t.Fatalf("request username=%v", gotBody["username"])
	}
	if gotBody["email"] != "alice@example.com" {
		t.Fatalf("request email=%v", gotBody["email"])
	}
	if gotBody["did_key"] != didKey {
		t.Fatalf("request did_key=%v want %v", gotBody["did_key"], didKey)
	}

	// Verify response.
	if resp.Status != "verification_sent" {
		t.Fatalf("status=%q", resp.Status)
	}
	if resp.Email != "alice@example.com" {
		t.Fatalf("email=%q", resp.Email)
	}
}

func TestClaimHumanHTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"detail":"email already belongs to another account"}`)
	}))
	t.Cleanup(server.Close)

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := ComputeDIDKey(pub)

	c, err := NewWithIdentity(server.URL, "", priv, didKey)
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.ClaimHuman(context.Background(), &ClaimHumanRequest{
		Username: "alice",
		Email:    "alice@example.com",
		DIDKey:   didKey,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	code, ok := HTTPStatusCode(err)
	if !ok || code != http.StatusConflict {
		t.Fatalf("expected 409, got %d (ok=%v)", code, ok)
	}
	body, ok := HTTPErrorBody(err)
	if !ok || !strings.Contains(body, "email already belongs") {
		t.Fatalf("body=%q ok=%v", body, ok)
	}
}

func TestClaimHumanWithAPIBaseURLSignsWirePath(t *testing.T) {
	t.Parallel()

	var gotPath string
	var gotAuth string
	var gotTimestamp string
	var gotBodyBytes []byte

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = strings.TrimSpace(r.Header.Get("Authorization"))
		gotTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		var err error
		gotBodyBytes, err = io.ReadAll(r.Body)
		if err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status": "verification_sent",
			"email":  "alice@example.com",
		})
	}))
	t.Cleanup(server.Close)

	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := ComputeDIDKey(pub)

	c, err := NewWithIdentity(server.URL+"/api", "", priv, didKey)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.ClaimHuman(context.Background(), &ClaimHumanRequest{
		Username: "alice",
		Email:    "alice@example.com",
		DIDKey:   didKey,
	}); err != nil {
		t.Fatal(err)
	}

	if gotPath != onboardingClaimHumanPath {
		t.Fatalf("wire path=%q want %q", gotPath, onboardingClaimHumanPath)
	}
	parts := strings.Fields(gotAuth)
	if len(parts) != 3 {
		t.Fatalf("auth=%q", gotAuth)
	}
	sigPayload := onboardingDIDKeySignPayload(http.MethodPost, gotPath, gotTimestamp, gotBodyBytes)
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, sigPayload, sig) {
		t.Fatal("claim-human /api wire-path signature did not verify")
	}
}
