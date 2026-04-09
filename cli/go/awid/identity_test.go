package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type staticTXTResolver map[string][]string

func (r staticTXTResolver) LookupTXT(_ context.Context, name string) ([]string, error) {
	records, ok := r[name]
	if !ok {
		return nil, &net.DNSError{IsNotFound: true}
	}
	return records, nil
}

func TestDIDKeyResolverValidDID(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	r := &DIDKeyResolver{}
	identity, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q, want %q", identity.DID, did)
	}
	if !identity.PublicKey.Equal(pub) {
		t.Fatal("PublicKey mismatch")
	}
	if identity.ResolvedVia != "did:key" {
		t.Fatalf("ResolvedVia=%q, want did:key", identity.ResolvedVia)
	}
	if identity.Address != "" {
		t.Fatalf("Address should be empty, got %q", identity.Address)
	}
}

func TestDIDKeyResolverInvalidDID(t *testing.T) {
	t.Parallel()

	r := &DIDKeyResolver{}
	_, err := r.Resolve(context.Background(), "not-a-did")
	if err == nil {
		t.Fatal("expected error for invalid DID")
	}
}

func TestDIDKeyResolverRejectsNonDIDKey(t *testing.T) {
	t.Parallel()

	r := &DIDKeyResolver{}
	_, err := r.Resolve(context.Background(), "mycompany/researcher")
	if err == nil {
		t.Fatal("expected error for non-did:key identifier")
	}
}

func TestServerResolverValidAddress(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/resolve/mycompany/researcher" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did":      did,
			"address":  "mycompany/researcher",
			"handle":   "@alice",
			"server":   "app.aweb.ai",
			"custody":  "self",
			"lifetime": "persistent",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	r := &ServerResolver{Client: c}
	identity, err := r.Resolve(context.Background(), "mycompany/researcher")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.Address != "mycompany/researcher" {
		t.Fatalf("Address=%q", identity.Address)
	}
	if identity.Handle != "@alice" {
		t.Fatalf("Handle=%q", identity.Handle)
	}
	if identity.Custody != "self" {
		t.Fatalf("Custody=%q", identity.Custody)
	}
	if identity.Lifetime != "persistent" {
		t.Fatalf("Lifetime=%q", identity.Lifetime)
	}
	if identity.ResolvedVia != "server" {
		t.Fatalf("ResolvedVia=%q", identity.ResolvedVia)
	}
}

func TestServerResolverUsesCanonicalResolvePath(t *testing.T) {
	t.Parallel()

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/resolve/demo/researcher" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"agent_id": "agent-123",
			"address":  "demo/researcher",
			"custody":  "self",
			"lifetime": "ephemeral",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	r := &ServerResolver{Client: c}
	identity, err := r.Resolve(context.Background(), "demo/researcher")
	if err != nil {
		t.Fatal(err)
	}
	if identity.IdentityID != "agent-123" {
		t.Fatalf("identity_id=%q", identity.IdentityID)
	}
	if identity.Handle != "researcher" {
		t.Fatalf("handle=%q", identity.Handle)
	}
}

func TestServerResolverIncludesStableIDAndPublicKey(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	pubB64 := base64.RawStdEncoding.EncodeToString(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did":        did,
			"stable_id":  "did:aw:test123",
			"address":    "mycompany/researcher",
			"public_key": pubB64,
			"custody":    "self",
			"lifetime":   "persistent",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	r := &ServerResolver{Client: c}
	identity, err := r.Resolve(context.Background(), "mycompany/researcher")
	if err != nil {
		t.Fatal(err)
	}
	if identity.StableID != "did:aw:test123" {
		t.Fatalf("stable_id=%q", identity.StableID)
	}
	if identity.PublicKey == nil || !identity.PublicKey.Equal(pub) {
		t.Fatal("public_key was not decoded correctly")
	}
}

func TestServerResolverAcceptsPaddedPublicKey(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	pubB64 := base64.StdEncoding.EncodeToString(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did":        did,
			"address":    "mycompany/researcher",
			"public_key": pubB64,
			"custody":    "self",
			"lifetime":   "persistent",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	r := &ServerResolver{Client: c}
	identity, err := r.Resolve(context.Background(), "mycompany/researcher")
	if err != nil {
		t.Fatal(err)
	}
	if identity.PublicKey == nil || !identity.PublicKey.Equal(pub) {
		t.Fatal("public_key was not decoded correctly")
	}
}

func TestServerResolverFallsBackToDIDWhenPublicKeyEncodingIsInvalid(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did":        did,
			"address":    "mycompany/researcher",
			"public_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGnot-base64-for-this-client",
			"custody":    "self",
			"lifetime":   "ephemeral",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	r := &ServerResolver{Client: c}
	identity, err := r.Resolve(context.Background(), "mycompany/researcher")
	if err != nil {
		t.Fatal(err)
	}
	if identity.PublicKey == nil || !identity.PublicKey.Equal(pub) {
		t.Fatal("public_key should fall back to DID-derived key")
	}
}

func TestServerResolverRejectsDIDPublicKeyMismatch(t *testing.T) {
	t.Parallel()

	pubA, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	pubB, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	didA := ComputeDIDKey(pubA)
	pubBB64 := base64.RawStdEncoding.EncodeToString(pubB)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did":        didA,
			"address":    "mycompany/researcher",
			"public_key": pubBB64,
			"custody":    "self",
			"lifetime":   "persistent",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	r := &ServerResolver{Client: c}
	_, err = r.Resolve(context.Background(), "mycompany/researcher")
	if err == nil {
		t.Fatal("expected DID/public_key mismatch error")
	}
}

func TestPinResolverByDID(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	ps.StorePin(did, "mycompany/researcher", "@alice", "app.aweb.ai")

	r := &PinResolver{Store: ps}
	identity, err := r.Resolve(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.Address != "mycompany/researcher" {
		t.Fatalf("Address=%q", identity.Address)
	}
	if identity.ResolvedVia != "pin" {
		t.Fatalf("ResolvedVia=%q", identity.ResolvedVia)
	}
}

func TestPinResolverByAddress(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	did := "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	ps.StorePin(did, "mycompany/researcher", "@alice", "app.aweb.ai")

	r := &PinResolver{Store: ps}
	identity, err := r.Resolve(context.Background(), "mycompany/researcher")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.Address != "mycompany/researcher" {
		t.Fatalf("Address=%q", identity.Address)
	}
}

func TestPinResolverNotFound(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	r := &PinResolver{Store: ps}
	_, err := r.Resolve(context.Background(), "unknown/agent")
	if err == nil {
		t.Fatal("expected error for unknown agent")
	}
}

func TestChainResolverDispatchesByFormat(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	// did:key identifier should use DIDKeyResolver.
	cr := &ChainResolver{
		DIDKey: &DIDKeyResolver{},
	}
	identity, err := cr.Resolve(context.Background(), did)
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.ResolvedVia != "did:key" {
		t.Fatalf("ResolvedVia=%q", identity.ResolvedVia)
	}
}

func TestChainResolverAliasUsesServer(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/agents/resolve/researcher" {
			t.Fatalf("path=%s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"did":      did,
			"address":  "researcher",
			"custody":  "self",
			"lifetime": "persistent",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithAPIKey(server.URL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}

	cr := &ChainResolver{
		DIDKey: &DIDKeyResolver{},
		Server: &ServerResolver{Client: c},
	}
	identity, err := cr.Resolve(context.Background(), "researcher")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.ResolvedVia != "server" {
		t.Fatalf("ResolvedVia=%q", identity.ResolvedVia)
	}
	// ChainResolver should cross-check and extract public key from DID.
	if identity.PublicKey == nil {
		t.Fatal("PublicKey should be extracted from DID")
	}
	if !identity.PublicKey.Equal(pub) {
		t.Fatal("PublicKey mismatch after cross-check")
	}
}

func TestChainResolverNoServer(t *testing.T) {
	t.Parallel()

	cr := &ChainResolver{
		DIDKey: &DIDKeyResolver{},
	}
	_, err := cr.Resolve(context.Background(), "researcher")
	if err == nil {
		t.Fatal("expected error when no server resolver for address")
	}
}

func TestRegistryResolverResolvesPersistentAddress(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL, ControllerDID: did},
		expiresAt: time.Now().Add(time.Minute),
	}
	identity, err := resolver.Resolve(context.Background(), "acme.com/alice")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.StableID != stableID {
		t.Fatalf("StableID=%q", identity.StableID)
	}
	if identity.ResolvedVia != "registry" {
		t.Fatalf("ResolvedVia=%q", identity.ResolvedVia)
	}
	if identity.ControllerDID != did {
		t.Fatalf("ControllerDID=%q", identity.ControllerDID)
	}
}

func TestRegistryResolverUsesEmbeddedFallbackWhenTXTIsMissing(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/probeproj.aweb.local/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "probeproj.aweb.local",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"reachability":    "private",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	if err := resolver.SetFallbackRegistryURL(server.URL); err != nil {
		t.Fatal(err)
	}

	identity, err := resolver.Resolve(context.Background(), "probeproj.aweb.local/alice")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ServerURL != server.URL {
		t.Fatalf("ServerURL=%q", identity.ServerURL)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q", identity.DID)
	}
}

func TestRegistryResolverRejectsKeyDidAWMismatch(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	otherStableID := "did:aw:SomeoneElse"

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          otherStableID,
				"current_did_key": did,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL},
		expiresAt: time.Now().Add(time.Minute),
	}
	_, err = resolver.Resolve(context.Background(), "acme.com/alice")
	if err == nil || !strings.Contains(err.Error(), "key did:aw mismatch") {
		t.Fatalf("err=%v, want key did:aw mismatch", err)
	}
}

func TestChainResolverAddressUsesRegistry(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": did,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	registry := NewRegistryResolver(server.Client(), staticTXTResolver{})
	registry.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL},
		expiresAt: time.Now().Add(time.Minute),
	}
	cr := &ChainResolver{
		DIDKey:   &DIDKeyResolver{},
		Registry: registry,
		Server:   &ServerResolver{Client: mustClient(t, server.URL)},
	}
	identity, err := cr.Resolve(context.Background(), "acme.com/alice")
	if err != nil {
		t.Fatal(err)
	}
	if identity.ResolvedVia != "registry" {
		t.Fatalf("ResolvedVia=%q", identity.ResolvedVia)
	}
}

func TestRegistryResolverVerifyStableIdentityRejectsKeyDidAWMismatch(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": did,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          "did:aw:SomeoneElse",
				"current_did_key": did,
			})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL},
		expiresAt: time.Now().Add(time.Minute),
	}

	result := resolver.VerifyStableIdentity(context.Background(), "acme.com/alice", stableID)
	if result == nil || result.Outcome != StableIdentityHardError {
		t.Fatalf("result=%+v, want hard error", result)
	}
	if !strings.Contains(result.Error, "key did:aw mismatch") {
		t.Fatalf("error=%q, want key did:aw mismatch", result.Error)
	}
}

func mustClient(t *testing.T, baseURL string) *Client {
	t.Helper()
	c, err := NewWithAPIKey(baseURL, "aw_sk_test")
	if err != nil {
		t.Fatal(err)
	}
	return c
}
