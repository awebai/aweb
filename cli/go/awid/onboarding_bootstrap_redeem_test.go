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

func TestBootstrapRedeem(t *testing.T) {
	t.Parallel()

	var gotBodyBytes []byte
	var gotBody map[string]any
	var gotAuth string
	var gotTimestamp string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != onboardingBootstrapRedeemPath {
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
			"certificate":    "Y2VydA==",
			"team_address":   "juanre.aweb.ai/default",
			"lifetime":       "persistent",
			"alias":          "laptop-agent",
			"did_aw":         "did:aw:test123",
			"member_address": "juanre.aweb.ai/laptop-agent",
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

	resp, err := c.BootstrapRedeem(context.Background(), &BootstrapRedeemRequest{
		Token:  "bootstrap-token",
		DIDKey: didKey,
		DIDAW:  "did:aw:test123",
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
	sigPayload := cloudDIDKeySignPayload(http.MethodPost, onboardingBootstrapRedeemPath, gotTimestamp, gotBodyBytes)
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, sigPayload, sig) {
		t.Fatal("bootstrap-redeem signature did not verify")
	}

	if gotBody["token"] != "bootstrap-token" {
		t.Fatalf("token=%v", gotBody["token"])
	}
	if gotBody["did_key"] != didKey {
		t.Fatalf("did_key=%v", gotBody["did_key"])
	}
	if gotBody["did_aw"] != "did:aw:test123" {
		t.Fatalf("did_aw=%v", gotBody["did_aw"])
	}

	if resp.TeamAddress != "juanre.aweb.ai/default" {
		t.Fatalf("team_address=%q", resp.TeamAddress)
	}
	if resp.DIDAW != "did:aw:test123" {
		t.Fatalf("did_aw=%q", resp.DIDAW)
	}
}

func TestBootstrapRedeemHTTPError(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_, _ = io.WriteString(w, `{"detail":"token already used"}`)
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

	_, err = c.BootstrapRedeem(context.Background(), &BootstrapRedeemRequest{
		Token:  "bootstrap-token",
		DIDKey: didKey,
	})
	if err == nil {
		t.Fatal("expected error")
	}
	code, ok := HTTPStatusCode(err)
	if !ok || code != http.StatusConflict {
		t.Fatalf("expected 409, got %d (ok=%v)", code, ok)
	}
}

func TestBootstrapRedeemWithAPIBaseURLSignsWirePath(t *testing.T) {
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
			"certificate":  "Y2VydA==",
			"team_address": "juanre.aweb.ai/default",
			"lifetime":     "ephemeral",
			"alias":        "ci-runner-01",
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

	if _, err := c.BootstrapRedeem(context.Background(), &BootstrapRedeemRequest{
		Token:  "bootstrap-token",
		DIDKey: didKey,
	}); err != nil {
		t.Fatal(err)
	}

	if gotPath != onboardingBootstrapRedeemPath {
		t.Fatalf("wire path=%q want %q", gotPath, onboardingBootstrapRedeemPath)
	}
	parts := strings.Fields(gotAuth)
	if len(parts) != 3 {
		t.Fatalf("auth=%q", gotAuth)
	}
	sigPayload := cloudDIDKeySignPayload(http.MethodPost, gotPath, gotTimestamp, gotBodyBytes)
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, sigPayload, sig) {
		t.Fatal("bootstrap-redeem /api wire-path signature did not verify")
	}
}
