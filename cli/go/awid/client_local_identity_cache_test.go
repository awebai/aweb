package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type localFreshResolver struct {
	cached   *ResolvedIdentity
	fresh    *ResolvedIdentity
	freshErr error
	freshes  int
}

func (r *localFreshResolver) Resolve(context.Context, string) (*ResolvedIdentity, error) {
	if r.cached == nil {
		return nil, errors.New("missing cached identity")
	}
	return r.cached, nil
}

func (r *localFreshResolver) ResolveFresh(context.Context, string) (*ResolvedIdentity, error) {
	r.freshes++
	if r.freshErr != nil {
		return nil, r.freshErr
	}
	if r.fresh == nil {
		return nil, errors.New("missing fresh identity")
	}
	return r.fresh, nil
}

func TestNormalizeSenderTrustVerifiesAuthoritativelyRefreshedLocalSender(t *testing.T) {
	c, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	pins := NewPinStore()
	c.SetPinStore(pins, "")
	resolver := &localFreshResolver{
		cached: &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: "did:key:current", Lifetime: LifetimeEphemeral, Custody: CustodySelf},
	}
	c.SetResolver(resolver)
	address := "default:acme.com/alice"

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:current", "", nil, nil, nil)
	if status != Verified || resolver.freshes != 1 {
		t.Fatalf("status=%q fresh resolves=%d, want verified/1", status, resolver.freshes)
	}
	if len(pins.Pins) != 0 || len(pins.Addresses) != 0 {
		t.Fatalf("stale pins were not purged: %+v", pins)
	}
	status, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:current", "", nil, nil, nil)
	if status != Verified || resolver.freshes != 2 {
		t.Fatalf("subsequent status=%q fresh resolves=%d, want verified/2", status, resolver.freshes)
	}
}

func TestNormalizeSenderTrustUsesAuthenticatedNoCacheTeamRosterRefresh(t *testing.T) {
	_, selfKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	currentSeed := make([]byte, ed25519.SeedSize)
	globalSeed := make([]byte, ed25519.SeedSize)
	for i := range currentSeed {
		currentSeed[i] = 71
		globalSeed[i] = 72
	}
	currentDID := ComputeDIDKey(ed25519.NewKeyFromSeed(currentSeed).Public().(ed25519.PublicKey))
	globalDID := ComputeDIDKey(ed25519.NewKeyFromSeed(globalSeed).Public().(ed25519.PublicKey))
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.URL.Path != "/v1/agents" {
			t.Fatalf("path=%q, want /v1/agents", r.URL.Path)
		}
		if !strings.HasPrefix(r.Header.Get("Authorization"), "DIDKey ") {
			t.Fatalf("Authorization=%q, want DIDKey auth", r.Header.Get("Authorization"))
		}
		if r.Header.Get("X-AWID-Team-Certificate") == "" {
			t.Fatal("missing X-AWID-Team-Certificate")
		}
		if r.Header.Get("Cache-Control") != "no-cache" {
			t.Fatalf("refresh Cache-Control=%q, want no-cache", r.Header.Get("Cache-Control"))
		}
		_ = json.NewEncoder(w).Encode(ListAgentsResponse{
			TeamID: "backend:acme.com",
			Agents: []AgentView{
				{Alias: "alice", DIDKey: currentDID, IdentityScope: IdentityModeLocal},
				{Alias: "grace", DIDKey: globalDID, DIDAW: "did:aw:grace", IdentityScope: IdentityModeGlobal},
			},
		})
	}))
	t.Cleanup(server.Close)

	client, err := NewWithCertificate(server.URL, selfKey, testTeamCertificate(t, selfKey, "bob"))
	if err != nil {
		t.Fatal(err)
	}
	client.SetAddress("backend:acme.com/bob")
	store := NewPinStore()
	client.SetPinStore(store, "")
	client.SetResolver(&ChainResolver{Team: &TeamRosterResolver{Client: client, TeamID: "backend:acme.com"}})

	if got, _ := client.NormalizeSenderTrust(context.Background(), Failed, "alice", currentDID, "", nil, nil, nil); got != Failed || requests != 0 {
		t.Fatalf("signature-failed status=%q requests=%d, want failed/0", got, requests)
	}
	if got, _ := client.NormalizeSenderTrust(context.Background(), Verified, "acme.com/alice", currentDID, "", nil, nil, nil); got != Verified {
		t.Fatalf("status=%q, want %q", got, Verified)
	}
	if requests != 1 || len(store.Pins) != 0 {
		t.Fatalf("local result requests=%d pins=%d, want 1/0", requests, len(store.Pins))
	}
	if got, _ := client.NormalizeSenderTrust(context.Background(), VerifiedLegacy, "alice", currentDID, "", nil, nil, nil); got != VerifiedLegacy {
		t.Fatalf("legacy local status=%q, want %q", got, VerifiedLegacy)
	}
	if got, _ := client.NormalizeSenderTrust(context.Background(), Verified, "acme.com/grace", globalDID, "did:aw:grace", nil, nil, nil); got != Verified {
		t.Fatalf("same-namespace global status=%q, want %q", got, Verified)
	}
	if requests != 3 || len(store.Pins) != 1 {
		t.Fatalf("global result requests=%d pins=%d, want 3/1", requests, len(store.Pins))
	}
}

func TestTeamRosterResolverRejectsClientWithoutCertificateAuth(t *testing.T) {
	client, err := New("http://example")
	if err != nil {
		t.Fatal(err)
	}
	resolver := &TeamRosterResolver{Client: client, TeamID: "backend:acme.com"}
	if _, err := resolver.ResolveFresh(context.Background(), "backend:acme.com/alice"); err == nil || !strings.Contains(err.Error(), "team-certificate authentication") {
		t.Fatalf("error=%v, want certificate-auth requirement", err)
	}
}

func TestNormalizeSenderTrustRejectsUnauthoritativeRosterRefreshes(t *testing.T) {
	makeDID := func(value byte) string {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = value
		}
		return ComputeDIDKey(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
	}
	currentDID := makeDID(73)
	differentDID := makeDID(74)
	cases := []struct {
		name         string
		statusCode   int
		agents       []AgentView
		fromStableID string
		status       VerificationStatus
		rawAddress   string
		want         VerificationStatus
	}{
		{name: "absent", agents: nil, want: IdentityMismatch},
		{name: "empty", agents: []AgentView{{Alias: "alice", IdentityScope: IdentityModeLocal}}, want: VerificationStale},
		{name: "malformed", agents: []AgentView{{Alias: "alice", DIDKey: "did:key:not-valid", IdentityScope: IdentityModeLocal}}, want: VerificationStale},
		{name: "non-local", agents: []AgentView{{Alias: "alice", DIDKey: currentDID, IdentityScope: IdentityModeGlobal}}, want: IdentityMismatch},
		{name: "different-key-with-forged-stable-id", agents: []AgentView{{Alias: "alice", DIDKey: differentDID, IdentityScope: IdentityModeLocal}}, fromStableID: "did:aw:forged", want: IdentityMismatch},
		{name: "verified-legacy-bare-alias", agents: []AgentView{{Alias: "alice", DIDKey: differentDID, IdentityScope: IdentityModeLocal}}, status: VerifiedLegacy, rawAddress: "alice", want: IdentityMismatch},
		{name: "unavailable", statusCode: http.StatusServiceUnavailable, want: VerificationStale},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, selfKey, err := ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				if !strings.HasPrefix(r.Header.Get("Authorization"), "DIDKey ") || r.Header.Get("X-AWID-Team-Certificate") == "" {
					t.Fatal("roster request was not certificate authenticated")
				}
				if r.Header.Get("Cache-Control") != "no-cache" {
					t.Fatalf("refresh Cache-Control=%q, want no-cache", r.Header.Get("Cache-Control"))
				}
				if tc.statusCode != 0 {
					w.WriteHeader(tc.statusCode)
					return
				}
				_ = json.NewEncoder(w).Encode(ListAgentsResponse{TeamID: "backend:acme.com", Agents: tc.agents})
			}))
			t.Cleanup(server.Close)
			client, err := NewWithCertificate(server.URL, selfKey, testTeamCertificate(t, selfKey, "bob"))
			if err != nil {
				t.Fatal(err)
			}
			client.SetAddress("backend:acme.com/bob")
			client.SetPinStore(NewPinStore(), "")
			client.SetResolver(&ChainResolver{Team: &TeamRosterResolver{Client: client, TeamID: "backend:acme.com"}})
			status := tc.status
			if status == "" {
				status = Verified
			}
			rawAddress := tc.rawAddress
			if rawAddress == "" {
				rawAddress = "acme.com/alice"
			}
			if got, _ := client.NormalizeSenderTrust(context.Background(), status, rawAddress, currentDID, tc.fromStableID, nil, nil, nil); got != tc.want {
				t.Fatalf("refresh status=%q, want %q", got, tc.want)
			}
		})
	}
}

func TestNormalizeSenderTrustDoesNotReconcileLegacyRecipientBindingMismatch(t *testing.T) {
	c, _ := New("http://example")
	c.did = "did:key:self"
	pins := NewPinStore()
	c.SetPinStore(pins, "")
	resolver := &localFreshResolver{
		cached: &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: "did:key:current", Lifetime: LifetimeEphemeral, Custody: CustodySelf},
	}
	c.SetResolver(resolver)
	address := "default:acme.com/alice"
	pins.StorePin("did:key:old", address, "", "")

	bindingStatus := c.NormalizeRecipientBinding(VerifiedLegacy, "did:key:wrong", "")
	if bindingStatus != IdentityMismatch {
		t.Fatalf("legacy recipient-binding status=%q, want %q", bindingStatus, IdentityMismatch)
	}
	status, _ := c.NormalizeSenderTrust(context.Background(), bindingStatus, address, "did:key:current", "", nil, nil, nil)
	if status != IdentityMismatch {
		t.Fatalf("recipient-binding status=%q, want %q", status, IdentityMismatch)
	}
	if resolver.freshes != 0 {
		t.Fatalf("recipient mismatch triggered local sender reconciliation: fresh resolves=%d", resolver.freshes)
	}
	if len(pins.Pins) == 0 || len(pins.Addresses) == 0 {
		t.Fatalf("recipient mismatch purged sender pins: %+v", pins)
	}
}

func TestNormalizeSenderTrustPreservesMismatchForLocalRosterKeyDifference(t *testing.T) {
	c, _ := New("http://example")
	c.SetPinStore(NewPinStore(), "")
	c.SetResolver(&localFreshResolver{
		cached: &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		fresh:  &ResolvedIdentity{DID: "did:key:roster", Lifetime: LifetimeEphemeral, Custody: CustodySelf},
	})
	address := "default:acme.com/alice"
	_, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:attacker", "", nil, nil, nil)
	if status != IdentityMismatch {
		t.Fatalf("attacker status=%q, want %q", status, IdentityMismatch)
	}
}

func TestNormalizeSenderTrustPreservesMismatchWhenLocalSenderAbsent(t *testing.T) {
	c, _ := New("http://example")
	c.SetPinStore(NewPinStore(), "")
	c.SetResolver(&localFreshResolver{
		cached:   &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		freshErr: &APIError{StatusCode: http.StatusNotFound},
	})
	address := "default:acme.com/alice"
	_, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:attacker", "", nil, nil, nil)
	if status != IdentityMismatch {
		t.Fatalf("absent attacker status=%q, want %q", status, IdentityMismatch)
	}
}

func TestNormalizeSenderTrustReportsStaleWhenLocalRefreshUnavailable(t *testing.T) {
	c, _ := New("http://example")
	c.SetPinStore(NewPinStore(), "")
	c.SetResolver(&localFreshResolver{
		cached:   &ResolvedIdentity{DID: "did:key:old", Lifetime: LifetimePersistent, Custody: CustodySelf},
		freshErr: errors.New("network unavailable"),
	})
	address := "default:acme.com/alice"
	_, _ = c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:old", "", nil, nil, nil)

	status, _ := c.NormalizeSenderTrust(context.Background(), Verified, address, "did:key:changed", "", nil, nil, nil)
	if status != VerificationStale {
		t.Fatalf("unavailable refresh status=%q, want %q", status, VerificationStale)
	}
}
