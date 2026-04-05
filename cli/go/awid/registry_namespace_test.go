package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestRegisterAddressAtSignsWithControllerKey(t *testing.T) {
	t.Parallel()

	subjectPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	subjectDID := ComputeDIDKey(subjectPub)
	subjectStableID := ComputeStableID(subjectPub)

	controllerPub, controllerPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := ComputeDIDKey(controllerPub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/acme.com/addresses" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if auth == "" {
			t.Fatal("missing Authorization header")
		}
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if parts[1] != controllerDID {
			t.Fatalf("authorization DID=%s want controller DID=%s", parts[1], controllerDID)
		}

		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		if timestamp == "" {
			t.Fatal("missing X-AWEB-Timestamp")
		}
		payload := canonicalRegistryJSON(map[string]string{
			"domain":    "acme.com",
			"name":      "alice",
			"operation": "register_address",
			"timestamp": timestamp,
		})
		sig, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(controllerPub, []byte(payload), sig) {
			t.Fatalf("invalid controller signature for payload %s", payload)
		}

		var body addressRegisterRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if body.DIDAW != subjectStableID {
			t.Fatalf("did_aw=%s want %s", body.DIDAW, subjectStableID)
		}
		if body.CurrentDIDKey != subjectDID {
			t.Fatalf("current_did_key=%s want %s", body.CurrentDIDKey, subjectDID)
		}

		_ = json.NewEncoder(w).Encode(map[string]any{
			"address_id":      "addr-1",
			"domain":          "acme.com",
			"name":            "alice",
			"did_aw":          subjectStableID,
			"current_did_key": subjectDID,
			"reachability":    "public",
			"created_at":      "2026-04-05T00:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	client.DefaultRegistryURL = server.URL

	address, err := client.RegisterAddressAt(
		context.Background(),
		server.URL,
		"acme.com",
		"alice",
		subjectStableID,
		subjectDID,
		"public",
		controllerPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if address.CurrentDIDKey != subjectDID {
		t.Fatalf("CurrentDIDKey=%s want %s", address.CurrentDIDKey, subjectDID)
	}
}

func TestRegisterAddressAtRequiresControllerSigningKey(t *testing.T) {
	t.Parallel()

	client := NewAWIDRegistryClient(http.DefaultClient, nil)

	_, err := client.RegisterAddressAt(
		context.Background(),
		"https://registry.example.com",
		"acme.com",
		"alice",
		"did:aw:test",
		"did:key:z6Mktest",
		"public",
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "controller signing key is required") {
		t.Fatalf("err=%v", err)
	}
}
