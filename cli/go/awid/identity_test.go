package awid

import (
	"context"
	"crypto/ed25519"
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

func TestChainResolverRejectsBareAliasWithoutQualifiedAddress(t *testing.T) {
	t.Parallel()

	cr := &ChainResolver{
		DIDKey:   &DIDKeyResolver{},
		Registry: NewRegistryResolver(nil, staticTXTResolver{}),
	}
	_, err := cr.Resolve(context.Background(), "researcher")
	if err == nil {
		t.Fatal("expected error for bare alias without qualified address")
	}
}

func TestChainResolverNoRegistry(t *testing.T) {
	t.Parallel()

	cr := &ChainResolver{
		DIDKey: &DIDKeyResolver{},
	}
	_, err := cr.Resolve(context.Background(), "researcher")
	if err == nil {
		t.Fatal("expected error when no registry resolver for address")
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

func TestRegistryResolverResolvesPersistentTeamMemberReference(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	currentPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := ComputeDIDKey(pub)
	currentDIDKey := ComputeDIDKey(currentPub)
	stableID := ComputeStableID(pub)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/teams/backend/members/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":        "backend:acme.com",
				"certificate_id": "cert-1",
				"member_did_key": memberDIDKey,
				"member_did_aw":  stableID,
				"member_address": "research.org/alice",
				"alias":          "alice",
				"lifetime":       "persistent",
				"issued_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": currentDIDKey,
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
	identity, err := resolver.Resolve(context.Background(), "backend:acme.com/alice")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != currentDIDKey {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.StableID != stableID {
		t.Fatalf("StableID=%q", identity.StableID)
	}
	if identity.Address != "research.org/alice" {
		t.Fatalf("Address=%q", identity.Address)
	}
	if identity.Handle != "alice" {
		t.Fatalf("Handle=%q", identity.Handle)
	}
	if identity.Lifetime != LifetimePersistent {
		t.Fatalf("Lifetime=%q", identity.Lifetime)
	}
	if identity.ResolvedVia != "registry" {
		t.Fatalf("ResolvedVia=%q", identity.ResolvedVia)
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
	if identity.RegistryURL != server.URL {
		t.Fatalf("RegistryURL=%q", identity.RegistryURL)
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
	c, err := New(baseURL)
	if err != nil {
		t.Fatal(err)
	}
	return c
}
