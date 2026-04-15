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
		"",
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
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "controller signing key is required") {
		t.Fatalf("err=%v", err)
	}
}

func TestDeleteNamespaceAtSignsWithControllerKey(t *testing.T) {
	t.Parallel()

	controllerPub, controllerPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := ComputeDIDKey(controllerPub)

	var gotBody deleteReasonRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/acme.com" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodDelete {
			t.Fatalf("method=%s", r.Method)
		}

		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if parts[1] != controllerDID {
			t.Fatalf("authorization DID=%s want controller DID=%s", parts[1], controllerDID)
		}

		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		payload := canonicalRegistryJSON(map[string]string{
			"domain":    "acme.com",
			"operation": "delete_namespace",
			"timestamp": timestamp,
		})
		sig, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(controllerPub, []byte(payload), sig) {
			t.Fatalf("invalid controller signature for payload %s", payload)
		}

		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	if err := client.DeleteNamespaceAt(
		context.Background(),
		server.URL,
		"acme.com",
		controllerPriv,
		"rollback after partial failure",
	); err != nil {
		t.Fatal(err)
	}
	if gotBody.Reason != "rollback after partial failure" {
		t.Fatalf("reason=%q", gotBody.Reason)
	}
}

func TestDeleteNamespaceAtRequiresControllerSigningKey(t *testing.T) {
	t.Parallel()

	client := NewAWIDRegistryClient(http.DefaultClient, nil)
	err := client.DeleteNamespaceAt(
		context.Background(),
		"https://registry.example.com",
		"acme.com",
		nil,
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "controller signing key is required") {
		t.Fatalf("err=%v", err)
	}
}

func TestRotateNamespaceControllerAtSignsWithNewControllerKey(t *testing.T) {
	t.Parallel()

	oldPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	oldControllerDID := ComputeDIDKey(oldPub)

	newPub, newPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	newControllerDID := ComputeDIDKey(newPub)

	var gotBody namespaceRotateControllerRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/acme.com" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPut {
			t.Fatalf("method=%s", r.Method)
		}

		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if parts[1] != newControllerDID {
			t.Fatalf("authorization DID=%s want new controller DID=%s", parts[1], newControllerDID)
		}

		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		payload := canonicalRegistryJSON(map[string]string{
			"domain":             "acme.com",
			"new_controller_did": newControllerDID,
			"operation":          "rotate_controller",
			"timestamp":          timestamp,
		})
		sig, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(newPub, []byte(payload), sig) {
			t.Fatalf("invalid controller signature for payload %s", payload)
		}

		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"namespace_id":        "ns-1",
			"domain":              "acme.com",
			"controller_did":      newControllerDID,
			"verification_status": "verified",
			"created_at":          "2026-04-15T00:00:00Z",
			"last_verified_at":    "2026-04-15T00:00:00Z",
			"previous_controller": oldControllerDID,
		})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	namespace, err := client.RotateNamespaceControllerAt(
		context.Background(),
		server.URL,
		"acme.com",
		newControllerDID,
		newPriv,
	)
	if err != nil {
		t.Fatal(err)
	}
	if gotBody.NewControllerDID != newControllerDID {
		t.Fatalf("new_controller_did=%q want %q", gotBody.NewControllerDID, newControllerDID)
	}
	if namespace.ControllerDID != newControllerDID {
		t.Fatalf("controller_did=%s want %s", namespace.ControllerDID, newControllerDID)
	}
}

func TestRotateNamespaceControllerAtRequiresMatchingSigningKey(t *testing.T) {
	t.Parallel()

	expectedPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	expectedDID := ComputeDIDKey(expectedPub)
	_, wrongKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	client := NewAWIDRegistryClient(http.DefaultClient, nil)
	_, err = client.RotateNamespaceControllerAt(
		context.Background(),
		"https://registry.example.com",
		"acme.com",
		expectedDID,
		wrongKey,
	)
	if err == nil || !strings.Contains(err.Error(), "signing key does not match") {
		t.Fatalf("err=%v", err)
	}
}

func TestDeleteAddressAtSignsWithControllerKey(t *testing.T) {
	t.Parallel()

	controllerPub, controllerPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := ComputeDIDKey(controllerPub)

	var gotBody deleteReasonRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/acme.com/addresses/alice" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodDelete {
			t.Fatalf("method=%s", r.Method)
		}

		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		parts := strings.Split(auth, " ")
		if len(parts) != 3 || parts[0] != "DIDKey" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if parts[1] != controllerDID {
			t.Fatalf("authorization DID=%s want controller DID=%s", parts[1], controllerDID)
		}

		timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
		payload := canonicalRegistryJSON(map[string]string{
			"domain":    "acme.com",
			"name":      "alice",
			"operation": "delete_address",
			"timestamp": timestamp,
		})
		sig, err := base64.RawStdEncoding.DecodeString(parts[2])
		if err != nil {
			t.Fatalf("decode signature: %v", err)
		}
		if !ed25519.Verify(controllerPub, []byte(payload), sig) {
			t.Fatalf("invalid controller signature for payload %s", payload)
		}

		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]any{"deleted": true})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	if err := client.DeleteAddressAt(
		context.Background(),
		server.URL,
		"acme.com",
		"alice",
		controllerPriv,
		"rollback after partial failure",
	); err != nil {
		t.Fatal(err)
	}
	if gotBody.Reason != "rollback after partial failure" {
		t.Fatalf("reason=%q", gotBody.Reason)
	}
}

func TestDeleteAddressAtRequiresControllerSigningKey(t *testing.T) {
	t.Parallel()

	client := NewAWIDRegistryClient(http.DefaultClient, nil)
	err := client.DeleteAddressAt(
		context.Background(),
		"https://registry.example.com",
		"acme.com",
		"alice",
		nil,
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "controller signing key is required") {
		t.Fatalf("err=%v", err)
	}
}
