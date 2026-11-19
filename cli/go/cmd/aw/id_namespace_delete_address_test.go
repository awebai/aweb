package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIDNamespaceDeleteAddressHappyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-acme",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			verifyRegistrySignatureForTest(t, r, controllerPub, map[string]string{
				"domain":    "acme.com",
				"name":      "alice",
				"operation": "delete_address",
			})
			if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	out, err := executeIDNamespaceDeleteAddress(context.Background(), idNamespaceDeleteAddressOptions{
		Domain: "acme.com",
		Name:   "alice",
		Reason: "retry clean byot setup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "deleted" {
		t.Fatalf("status=%s want deleted", out.Status)
	}
	if out.Address != "acme.com/alice" {
		t.Fatalf("address=%s", out.Address)
	}
	if out.ControllerDID != controllerDID {
		t.Fatalf("controller=%s want %s", out.ControllerDID, controllerDID)
	}
	if gotBody["reason"] != "retry clean byot setup" {
		t.Fatalf("reason=%v", gotBody["reason"])
	}
}

func TestIDNamespaceDeleteAddressRequiresLocalControllerKey(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := executeIDNamespaceDeleteAddress(context.Background(), idNamespaceDeleteAddressOptions{
		Domain: "acme.com",
		Name:   "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "no controller key") {
		t.Fatalf("err=%v", err)
	}
}

func TestIDNamespaceDeleteAddressRejectsControllerMismatch(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/acme.com" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"namespace_id":        "ns-acme",
			"domain":              "acme.com",
			"controller_did":      awid.ComputeDIDKey(otherPub),
			"verification_status": "verified",
			"created_at":          "2026-04-01T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeIDNamespaceDeleteAddress(context.Background(), idNamespaceDeleteAddressOptions{
		Domain: "acme.com",
		Name:   "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match registered controller") {
		t.Fatalf("err=%v", err)
	}
}

func TestIDNamespaceDeleteAddressActiveCertificatesMessage(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	controllerPub, controllerPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerPub)
	if err := awconfig.SaveControllerKey("acme.com", controllerPriv); err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-acme",
				"domain":              "acme.com",
				"controller_did":      controllerDID,
				"verification_status": "verified",
				"created_at":          "2026-04-01T00:00:00Z",
			})
		case r.Method == http.MethodDelete && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			w.WriteHeader(http.StatusConflict)
			_ = json.NewEncoder(w).Encode(map[string]any{"detail": "Address has active certificates"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	_, err = executeIDNamespaceDeleteAddress(context.Background(), idNamespaceDeleteAddressOptions{
		Domain: "acme.com",
		Name:   "alice",
	})
	if err == nil || !strings.Contains(err.Error(), "revoke team membership certificates first") {
		t.Fatalf("err=%v", err)
	}
}

func verifyRegistrySignatureForTest(t *testing.T, r *http.Request, pub ed25519.PublicKey, fields map[string]string) {
	t.Helper()

	auth := strings.TrimSpace(r.Header.Get("Authorization"))
	parts := strings.Split(auth, " ")
	if len(parts) != 3 || parts[0] != "DIDKey" {
		t.Fatalf("Authorization=%q", auth)
	}
	if parts[1] != awid.ComputeDIDKey(pub) {
		t.Fatalf("authorization DID=%s want %s", parts[1], awid.ComputeDIDKey(pub))
	}

	timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
	if timestamp == "" {
		t.Fatal("missing X-AWEB-Timestamp")
	}
	canonical := coveringControllerPayloadForTest(t, r, timestamp, fields)
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sig) {
		t.Fatalf("invalid signature for payload %s", canonical)
	}
}

// coveringControllerPayloadForTest is the covering-v2 payload a controller
// signs for fields (domain and operation, and the operation's claims) over
// exactly the request r at timestamp, checked against r's
// X-AWEB-Signed-Payload. r's body is restored for the handler to read.
func coveringControllerPayloadForTest(t *testing.T, r *http.Request, timestamp string, fields map[string]string) string {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(body) == 0 {
		body = nil
	}
	claims := map[string]any{}
	for key, value := range fields {
		if key != "domain" && key != "operation" && key != "timestamp" {
			claims[key] = value
		}
	}
	payload, err := awid.ControllerRequestPayload("http://"+r.Host, r.Method, r.URL.EscapedPath(), body,
		timestamp, fields["domain"], fields["operation"], claims)
	if err != nil {
		t.Fatalf("covering payload: %v", err)
	}
	signed, err := base64.RawURLEncoding.DecodeString(r.Header.Get("X-AWEB-Signed-Payload"))
	if err != nil || !bytes.Equal(signed, payload) {
		t.Fatalf("signed payload %s, want %s", signed, payload)
	}
	return string(payload)
}
