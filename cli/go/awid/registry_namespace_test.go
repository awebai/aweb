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

func TestListDIDAddressesAtReadsReverseAddressList(t *testing.T) {
	t.Parallel()

	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Fatalf("method=%s", r.Method)
		}
		if r.URL.Path != "/v1/did/"+stableID+"/addresses" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"addresses": []map[string]any{{
			"address_id":      "addr-1",
			"domain":          "acme.com",
			"name":            "alice",
			"did_aw":          stableID,
			"current_did_key": did,
			"reachability":    "public",
			"created_at":      "2026-04-04T00:00:00Z",
		}}})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	addresses, err := client.ListDIDAddressesAt(context.Background(), server.URL, stableID)
	if err != nil {
		t.Fatal(err)
	}
	if len(addresses) != 1 {
		t.Fatalf("addresses=%d want 1", len(addresses))
	}
	if addresses[0].DIDAW != stableID {
		t.Fatalf("did_aw=%s want %s", addresses[0].DIDAW, stableID)
	}
	if addresses[0].CurrentDIDKey != did {
		t.Fatalf("current_did_key=%s want %s", addresses[0].CurrentDIDKey, did)
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

func TestReverifyNamespaceAtPostsWithoutAuth(t *testing.T) {
	t.Parallel()

	oldControllerDID := "did:key:z6Mkoldcontroller"
	newControllerDID := "did:key:z6Mknewcontroller"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/acme.com/reverify" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if auth := strings.TrimSpace(r.Header.Get("Authorization")); auth != "" {
			t.Fatalf("unexpected Authorization header %q", auth)
		}
		if timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp")); timestamp != "" {
			t.Fatalf("unexpected X-AWEB-Timestamp header %q", timestamp)
		}
		if body, err := io.ReadAll(r.Body); err != nil {
			t.Fatalf("read body: %v", err)
		} else if strings.TrimSpace(string(body)) != "" {
			t.Fatalf("expected empty body, got %q", string(body))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"namespace_id":        "ns-1",
			"domain":              "acme.com",
			"controller_did":      newControllerDID,
			"verification_status": "verified",
			"created_at":          "2026-04-15T00:00:00Z",
			"last_verified_at":    "2026-04-15T00:00:00Z",
			"old_controller_did":  oldControllerDID,
			"new_controller_did":  newControllerDID,
		})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	result, err := client.ReverifyNamespaceAt(
		context.Background(),
		server.URL,
		"acme.com",
	)
	if err != nil {
		t.Fatal(err)
	}
	if result.ControllerDID != newControllerDID {
		t.Fatalf("controller_did=%s want %s", result.ControllerDID, newControllerDID)
	}
	if result.OldControllerDID != oldControllerDID {
		t.Fatalf("old_controller_did=%s want %s", result.OldControllerDID, oldControllerDID)
	}
	if result.NewControllerDID != newControllerDID {
		t.Fatalf("new_controller_did=%s want %s", result.NewControllerDID, newControllerDID)
	}
}

func TestReverifyNamespaceAtRequiresDomain(t *testing.T) {
	t.Parallel()

	client := NewAWIDRegistryClient(http.DefaultClient, nil)
	_, err := client.ReverifyNamespaceAt(
		context.Background(),
		"https://registry.example.com",
		"",
	)
	if err == nil || !strings.Contains(err.Error(), "domain is required") {
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
