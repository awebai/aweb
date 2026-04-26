package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
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

func TestPinResolverByStableAddressReturnsCurrentDIDKey(t *testing.T) {
	t.Parallel()

	ps := NewPinStore()
	stableID := "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn"
	did := "did:key:z6MkpfXL8ijUSkuwevHQhYJaUwoD46EekWmdRc6jX7p5bmEm"
	ps.Pins[stableID] = &Pin{
		Address:  "juan.aweb.ai/randy",
		StableID: stableID,
		DIDKey:   did,
		Server:   "https://api.awid.ai",
	}
	ps.Addresses["juan.aweb.ai/randy"] = stableID

	r := &PinResolver{Store: ps}
	identity, err := r.Resolve(context.Background(), "juan.aweb.ai/randy")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q, want %q", identity.DID, did)
	}
	if identity.StableID != stableID {
		t.Fatalf("StableID=%q, want %q", identity.StableID, stableID)
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

func TestChainResolverFallsBackToPinWhenRegistryAddressMissing(t *testing.T) {
	t.Parallel()

	stableID := "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn"
	did := "did:key:z6MkpfXL8ijUSkuwevHQhYJaUwoD46EekWmdRc6jX7p5bmEm"
	address := "juan.aweb.ai/randy"

	var registryHits atomic.Int64
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		registryHits.Add(1)
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	ps := NewPinStore()
	ps.Pins[stableID] = &Pin{
		Address:  address,
		StableID: stableID,
		DIDKey:   did,
		Server:   server.URL,
	}
	ps.Addresses[address] = stableID

	registry := NewRegistryResolver(server.Client(), staticTXTResolver{})
	if err := registry.SetFallbackRegistryURL(server.URL); err != nil {
		t.Fatal(err)
	}
	cr := &ChainResolver{
		DIDKey:   &DIDKeyResolver{},
		Registry: registry,
		Pin:      &PinResolver{Store: ps},
	}

	identity, err := cr.Resolve(context.Background(), address)
	if err != nil {
		t.Fatal(err)
	}
	if registryHits.Load() == 0 {
		t.Fatal("registry was not tried before pin fallback")
	}
	if identity.ResolvedVia != "pin" {
		t.Fatalf("ResolvedVia=%q, want pin", identity.ResolvedVia)
	}
	if identity.DID != did {
		t.Fatalf("DID=%q, want %q", identity.DID, did)
	}
	if identity.StableID != stableID {
		t.Fatalf("StableID=%q, want %q", identity.StableID, stableID)
	}
}

func TestChainResolverDoesNotFallBackToPinOnRegistryHardError(t *testing.T) {
	t.Parallel()

	address := "juan.aweb.ai/randy"
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "registry unavailable", http.StatusInternalServerError)
	}))
	t.Cleanup(server.Close)

	ps := NewPinStore()
	ps.StorePin("did:key:z6MkpfXL8ijUSkuwevHQhYJaUwoD46EekWmdRc6jX7p5bmEm", address, "randy", server.URL)
	registry := NewRegistryResolver(server.Client(), staticTXTResolver{})
	if err := registry.SetFallbackRegistryURL(server.URL); err != nil {
		t.Fatal(err)
	}
	cr := &ChainResolver{
		DIDKey:   &DIDKeyResolver{},
		Registry: registry,
		Pin:      &PinResolver{Store: ps},
	}

	_, err := cr.Resolve(context.Background(), address)
	if err == nil {
		t.Fatal("expected registry hard error")
	}
	apiErr, ok := err.(*APIError)
	if !ok || apiErr.StatusCode != http.StatusInternalServerError {
		t.Fatalf("err=%T %v, want registry 500", err, err)
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

func TestRegistryResolverResolvesEphemeralTeamMemberReference(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := ComputeDIDKey(pub)

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/teams/backend/members/eve":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":        "backend:acme.com",
				"certificate_id": "cert-eve",
				"member_did_key": memberDIDKey,
				"member_did_aw":  "",
				"member_address": "",
				"alias":          "eve",
				"lifetime":       "ephemeral",
				"issued_at":      "2026-04-04T00:00:00Z",
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
	identity, err := resolver.Resolve(context.Background(), "backend:acme.com/eve")
	if err != nil {
		t.Fatal(err)
	}
	if identity.DID != memberDIDKey {
		t.Fatalf("DID=%q", identity.DID)
	}
	if identity.StableID != "" {
		t.Fatalf("StableID=%q", identity.StableID)
	}
	if identity.Address != "backend:acme.com/eve" {
		t.Fatalf("Address=%q", identity.Address)
	}
	if identity.Lifetime != LifetimeEphemeral {
		t.Fatalf("Lifetime=%q", identity.Lifetime)
	}
}

func TestRegistryResolverTeamMemberReferenceNotFound(t *testing.T) {
	t.Parallel()

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)

	resolver := NewRegistryResolver(server.Client(), staticTXTResolver{})
	resolver.registryCache["acme.com"] = cachedValue[DomainAuthority]{
		value:     DomainAuthority{RegistryURL: server.URL},
		expiresAt: time.Now().Add(time.Minute),
	}
	if _, err := resolver.Resolve(context.Background(), "backend:acme.com/missing"); err == nil {
		t.Fatal("expected error for missing team member reference")
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
				"reachability":    "nobody",
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

func TestRegistryResolverVerifyStableIdentityWalksFullLogOnFirstContact(t *testing.T) {
	t.Parallel()

	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	newPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)
	newDID := ComputeDIDKey(newPub)
	stableID := ComputeStableID(oldPub)

	createEntry := signedDidKeyResolution(t, oldPriv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: oldDID,
		LogHead: &DidKeyEvidence{
			Seq:          1,
			Operation:    "create",
			NewDIDKey:    oldDID,
			StateHash:    strings.Repeat("1", 64),
			AuthorizedBy: oldDID,
			Timestamp:    "2026-04-09T00:00:00Z",
		},
	}).LogHead
	prevHash := createEntry.EntryHash
	rotateEntry := signedDidKeyResolution(t, oldPriv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: newDID,
		LogHead: &DidKeyEvidence{
			Seq:            2,
			Operation:      "rotate_key",
			PreviousDIDKey: &oldDID,
			NewDIDKey:      newDID,
			PrevEntryHash:  &prevHash,
			StateHash:      strings.Repeat("2", 64),
			AuthorizedBy:   oldDID,
			Timestamp:      "2026-04-10T00:00:00Z",
		},
	}).LogHead

	var logCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": newDID,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": newDID,
				"log_head":        rotateEntry,
			})
		case "/v1/did/" + stableID + "/log":
			logCalls.Add(1)
			_ = json.NewEncoder(w).Encode([]DidKeyEvidence{*createEntry, *rotateEntry})
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
	if result == nil || result.Outcome != StableIdentityVerified {
		t.Fatalf("result=%+v, want verified", result)
	}
	if result.CurrentDIDKey != newDID {
		t.Fatalf("current_did_key=%q", result.CurrentDIDKey)
	}
	if logCalls.Load() != 1 {
		t.Fatalf("log_calls=%d, want 1", logCalls.Load())
	}

	result = resolver.VerifyStableIdentity(context.Background(), "acme.com/alice", stableID)
	if result == nil || result.Outcome != StableIdentityVerified {
		t.Fatalf("second result=%+v, want verified", result)
	}
	if logCalls.Load() != 1 {
		t.Fatalf("second log_calls=%d, want cached head reuse", logCalls.Load())
	}
}

func TestRegistryResolverVerifyStableIdentityWalksFullLogRejectsTailMismatch(t *testing.T) {
	t.Parallel()

	oldPub, oldPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	keyPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	logPub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	oldDID := ComputeDIDKey(oldPub)
	keyDID := ComputeDIDKey(keyPub)
	logDID := ComputeDIDKey(logPub)
	stableID := ComputeStableID(oldPub)

	createEntry := signedDidKeyResolution(t, oldPriv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: oldDID,
		LogHead: &DidKeyEvidence{
			Seq:          1,
			Operation:    "create",
			NewDIDKey:    oldDID,
			StateHash:    strings.Repeat("3", 64),
			AuthorizedBy: oldDID,
			Timestamp:    "2026-04-09T00:00:00Z",
		},
	}).LogHead
	prevHash := createEntry.EntryHash
	rotateEntry := signedDidKeyResolution(t, oldPriv, &DidKeyResolution{
		DIDAW:         stableID,
		CurrentDIDKey: logDID,
		LogHead: &DidKeyEvidence{
			Seq:            2,
			Operation:      "rotate_key",
			PreviousDIDKey: &oldDID,
			NewDIDKey:      logDID,
			PrevEntryHash:  &prevHash,
			StateHash:      strings.Repeat("4", 64),
			AuthorizedBy:   oldDID,
			Timestamp:      "2026-04-10T00:00:00Z",
		},
	}).LogHead

	var logCalls atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"address_id":      "addr-1",
				"domain":          "acme.com",
				"name":            "alice",
				"did_aw":          stableID,
				"current_did_key": keyDID,
				"reachability":    "public",
				"created_at":      "2026-04-04T00:00:00Z",
			})
		case "/v1/did/" + stableID + "/key":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": keyDID,
				"log_head":        rotateEntry,
			})
		case "/v1/did/" + stableID + "/log":
			logCalls.Add(1)
			_ = json.NewEncoder(w).Encode([]DidKeyEvidence{*createEntry, *rotateEntry})
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
	if !strings.Contains(result.Error, "audit log current did:key mismatch") {
		t.Fatalf("error=%q", result.Error)
	}
	if logCalls.Load() != 1 {
		t.Fatalf("log_calls=%d, want 1", logCalls.Load())
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
