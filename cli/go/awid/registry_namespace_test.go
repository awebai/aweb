package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestClaimIdentityAddressAtPostsAtomicSignedPayload(t *testing.T) {
	t.Parallel()

	subjectPub, subjectPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	subjectDID := ComputeDIDKey(subjectPub)
	subjectStableID := ComputeStableID(subjectPub)

	controllerPub, controllerPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	now := time.Date(2026, 6, 6, 9, 30, 0, 0, time.UTC)

	var got atomicAddressClaimRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/did" || r.URL.Path == "/v1/namespaces/acme.com/addresses" {
			t.Fatalf("legacy split endpoint was called: %s %s", r.Method, r.URL.Path)
		}
		if r.URL.Path != "/v1/namespaces/acme.com/addresses/claims" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Fatalf("method=%s", r.Method)
		}
		if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		fields := AtomicAddressClaimFields{
			Operation:        got.Operation,
			Domain:           "acme.com",
			AddressName:      got.AddressName,
			DIDAW:            got.DIDAW,
			CurrentDIDKey:    got.CurrentDIDKey,
			RegistryURL:      got.RegistryURL,
			Timestamp:        got.Timestamp,
			DryRun:           got.DryRun,
			IdentityCustody:  got.IdentityCustody,
			NamespaceCustody: got.NamespaceCustody,
		}
		identityCanonical, err := AtomicAddressClaimIdentityCanonical(fields)
		if err != nil {
			t.Fatal(err)
		}
		identitySig, err := base64.RawStdEncoding.DecodeString(got.IdentitySignature)
		if err != nil {
			t.Fatalf("identity signature decode: %v", err)
		}
		if !ed25519.Verify(subjectPub, []byte(identityCanonical), identitySig) {
			t.Fatalf("invalid identity signature for %s", identityCanonical)
		}
		identityProofHash, err := AtomicAddressClaimIdentityProofHash(identityCanonical, got.IdentitySignature)
		if err != nil {
			t.Fatal(err)
		}
		namespaceCanonical, err := AtomicAddressClaimNamespaceCanonical(fields, identityProofHash)
		if err != nil {
			t.Fatal(err)
		}
		namespaceSig, err := base64.RawStdEncoding.DecodeString(got.NamespaceSignature)
		if err != nil {
			t.Fatalf("namespace signature decode: %v", err)
		}
		if !ed25519.Verify(controllerPub, []byte(namespaceCanonical), namespaceSig) {
			t.Fatalf("invalid namespace signature for %s", namespaceCanonical)
		}
		logPayload := CanonicalDidLogPayload(got.DIDAW, &DidKeyEvidence{
			Seq:            got.DIDLogProof.Seq,
			Operation:      got.DIDLogProof.Operation,
			PreviousDIDKey: got.DIDLogProof.PreviousDIDKey,
			NewDIDKey:      got.DIDLogProof.NewDIDKey,
			PrevEntryHash:  got.DIDLogProof.PrevEntryHash,
			StateHash:      got.DIDLogProof.StateHash,
			AuthorizedBy:   got.DIDLogProof.AuthorizedBy,
			Timestamp:      got.DIDLogProof.Timestamp,
		})
		logSig, err := base64.RawStdEncoding.DecodeString(got.DIDLogProof.Signature)
		if err != nil {
			t.Fatalf("did log signature decode: %v", err)
		}
		if !ed25519.Verify(subjectPub, []byte(logPayload), logSig) {
			t.Fatalf("invalid did log proof signature for %s", logPayload)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"status":            "available",
			"dry_run":           got.DryRun,
			"domain":            "acme.com",
			"name":              got.AddressName,
			"did_aw":            got.DIDAW,
			"current_did_key":   got.CurrentDIDKey,
			"identity_custody":  got.IdentityCustody,
			"namespace_custody": got.NamespaceCustody,
			"did_status":        "would_create",
			"address_status":    "would_create",
		})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	// Pin the clock per-client; mutating a package global races every parallel
	// test that reads it through production code (default-aajc.15).
	client.Now = func() time.Time { return now }
	result, err := client.ClaimIdentityAddressAt(context.Background(), server.URL, AtomicAddressClaimParams{
		Domain:                        "acme.com",
		AddressName:                   "alice",
		DIDAW:                         subjectStableID,
		CurrentDIDKey:                 subjectDID,
		IdentitySigningKey:            subjectPriv,
		NamespaceControllerSigningKey: controllerPriv,
		DryRun:                        true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Status != "available" || !result.DryRun || result.Address != nil {
		t.Fatalf("result=%+v", result)
	}
	if got.RegistryURL != server.URL {
		t.Fatalf("registry_url=%q want %q", got.RegistryURL, server.URL)
	}
	if got.DIDLogProof.Operation != "register_did" || got.DIDLogProof.StateHash == "" {
		t.Fatalf("did_log_proof=%+v", got.DIDLogProof)
	}
}

func TestClaimIdentityAddressAtDecodesKnownAtomicConflictCode(t *testing.T) {
	t.Parallel()

	params := atomicClaimTestParams(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": map[string]any{
				"code":    AtomicAddressClaimCodeAddressTakenDifferentOwner,
				"message": "address is already bound to a different did:aw",
			},
		})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	_, err := client.ClaimIdentityAddressAt(context.Background(), server.URL, params)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	var conflict *AtomicAddressClaimConflictError
	if !errors.As(err, &conflict) {
		t.Fatalf("error %T %[1]v is not AtomicAddressClaimConflictError", err)
	}
	if conflict.StatusCode != http.StatusConflict {
		t.Fatalf("status=%d", conflict.StatusCode)
	}
	if conflict.Code != AtomicAddressClaimCodeAddressTakenDifferentOwner {
		t.Fatalf("code=%q", conflict.Code)
	}
	if conflict.Message == "" {
		t.Fatal("expected conflict message")
	}
}

func TestClaimIdentityAddressAtLeavesUnknownAtomicConflictGeneric(t *testing.T) {
	t.Parallel()

	params := atomicClaimTestParams(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": map[string]any{
				"code":    "new_server_code",
				"message": "server knows a code this client does not",
			},
		})
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	_, err := client.ClaimIdentityAddressAt(context.Background(), server.URL, params)
	if err == nil {
		t.Fatal("expected conflict error")
	}
	var conflict *AtomicAddressClaimConflictError
	if errors.As(err, &conflict) {
		t.Fatalf("unknown code should not be treated as known conflict: %+v", conflict)
	}
	var registryErr *RegistryError
	if !errors.As(err, &registryErr) {
		t.Fatalf("error %T %[1]v is not RegistryError", err)
	}
}

func atomicClaimTestParams(t *testing.T) AtomicAddressClaimParams {
	t.Helper()
	subjectPub, subjectPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, controllerPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	return AtomicAddressClaimParams{
		Domain:                        "acme.com",
		AddressName:                   "alice",
		DIDAW:                         ComputeStableID(subjectPub),
		CurrentDIDKey:                 ComputeDIDKey(subjectPub),
		IdentitySigningKey:            subjectPriv,
		NamespaceControllerSigningKey: controllerPriv,
		DryRun:                        true,
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

func TestRegistryNamespaceAndAddressDecodeDeliveryOrigin(t *testing.T) {
	t.Parallel()

	pub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":            "ns-1",
				"domain":                  "acme.com",
				"controller_did":          "did:key:z6Mkcontroller",
				"verification_status":     "verified",
				"default_delivery_origin": "https://messages.example.com",
				"created_at":              "2026-04-04T00:00:00Z",
			})
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"reachability":    "public",
				"delivery": map[string]any{
					"origin": "https://messages.example.com",
					"source": "namespace_default",
				},
				"created_at": "2026-04-04T00:00:00Z",
			})
		default:
			t.Fatalf("path=%s", r.URL.Path)
		}
	}))
	t.Cleanup(server.Close)

	client := NewAWIDRegistryClient(server.Client(), nil)
	namespace, _, err := client.GetNamespaceAt(context.Background(), server.URL, "acme.com")
	if err != nil {
		t.Fatal(err)
	}
	if namespace.DefaultDeliveryOrigin != "https://messages.example.com" {
		t.Fatalf("DefaultDeliveryOrigin=%q", namespace.DefaultDeliveryOrigin)
	}

	address, _, err := client.GetNamespaceAddressAt(context.Background(), server.URL, "acme.com", "alice")
	if err != nil {
		t.Fatal(err)
	}
	if address.Delivery == nil || address.Delivery.Origin != "https://messages.example.com" || address.Delivery.Source != "namespace_default" {
		t.Fatalf("delivery=%#v", address.Delivery)
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
		nil,
	)
	if err == nil || !strings.Contains(err.Error(), "controller signing key is required") {
		t.Fatalf("err=%v", err)
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
