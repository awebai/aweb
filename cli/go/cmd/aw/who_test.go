package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// whoVectors are the frozen identity-tree vectors aw who reads its fixtures
// from: the keys and the alice -> coordinator chain under example.com.
type whoVectors struct {
	Keys map[string]struct {
		SeedHex string `json:"seed_hex"`
		DIDKey  string `json:"did_key"`
		DIDAW   string `json:"did_aw"`
	} `json:"keys"`
	Certificates map[string]struct {
		Signed map[string]any `json:"signed"`
	} `json:"certificates"`
}

func loadWhoVectors(t *testing.T) whoVectors {
	t.Helper()
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v whoVectors
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// whoIdentity makes workingDir's identity the frozen coordinator: a local
// agent whose ID is its did:key, with its own key. chained installs its
// alice -> coordinator chain. global instead gives it the coordinator's
// did:aw and address.
func whoIdentity(t *testing.T, v whoVectors, chained, global bool) string {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	dir := t.TempDir()
	coordinator := v.Keys["coordinator"]
	seed, err := hex.DecodeString(coordinator.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	identity := &awconfig.WorktreeIdentity{DID: coordinator.DIDKey, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, CreatedAt: "2026-10-26T00:00:00Z"}
	if global {
		identity.StableID, identity.Address, identity.IdentityScope = coordinator.DIDAW, "example.com/coordinator", awid.IdentityModeGlobal
		identity.RegistryURL, identity.RegistryStatus = "https://registry.example.com", "registered"
	}
	aw := dir + "/.aw"
	if err := awconfig.SaveWorktreeIdentityTo(aw+"/identity.yaml", identity); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(aw+"/signing.key", ed25519.NewKeyFromSeed(seed)); err != nil {
		t.Fatal(err)
	}
	if chained {
		chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}
		if err := awconfig.SaveInstalledIDChain(aw, chain); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A local identity with no chain is a legacy identity: nothing to ask.
func TestWhoReportsAChainlessLocalIdentityAsUnknown(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, false, false)
	out, err := executeWho(context.Background(), whoOptions{WorkingDir: dir, TXTResolver: staticTXTResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != v.Keys["coordinator"].DIDKey || out.Outcome != "unknown" || out.Reason != "legacy_no_chain" || out.HumanID != nil || out.Chain != nil {
		t.Fatalf("out %+v", out)
	}
}

// A global ID without an installed chain is still asked about: an enrolled
// ID cannot become a legacy one by leaving its chain out.
func TestWhoAsksAboutAChainlessGlobalID(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, false, true)
	out, err := executeWho(context.Background(), whoOptions{WorkingDir: dir, TXTResolver: staticTXTResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if out.ID != v.Keys["coordinator"].DIDAW || out.Outcome != "unavailable" || out.Reason != "evidence_unavailable" || out.HumanID != nil || out.Chain != nil {
		t.Fatalf("out %+v", out)
	}
}

// Without current status the chain is not shown: an installed chain is only
// a claim until it verifies.
func TestWhoShowsNoChainWithoutCurrentStatus(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, true, false)
	out, err := executeWho(context.Background(), whoOptions{WorkingDir: dir, TXTResolver: staticTXTResolver{}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Domain != "example.com" || out.Outcome != "unavailable" || out.Reason != "evidence_unavailable" || out.HumanID != nil || out.IdentityValid != nil || out.Chain != nil {
		t.Fatalf("out %+v", out)
	}
}

// The real AWID fixture cannot resolve the domain's _awid record, so it
// answers that status is unavailable: aw who reports exactly that, never the
// human the installed chain names.
func TestWhoReportsTheRegistrysUnavailableStatus(t *testing.T) {
	v := loadWhoVectors(t)
	registryURL := realAWIDFixture(t)
	dir := whoIdentity(t, v, true, false)
	resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "")}}
	out, err := executeWho(context.Background(), whoOptions{WorkingDir: dir, RegistryURL: registryURL, TXTResolver: resolver})
	if err != nil {
		t.Fatal(err)
	}
	if out.Outcome != "unavailable" || out.Reason != "evidence_unavailable" || out.HumanID != nil || out.Chain != nil {
		t.Fatalf("out %+v", out)
	}
}

// A --registry that contradicts the registry the domain's record names is
// refused, not quietly reported as unavailable status.
func TestWhoRefusesARegistryTheDomainDoesNotName(t *testing.T) {
	v := loadWhoVectors(t)
	dir := whoIdentity(t, v, true, false)
	resolver := staticTXTResolver{"_awid.example.com": {idCreateDNSRecordValue(v.Keys["root"].DIDKey, "https://registry.example.com")}}
	out, err := executeWho(context.Background(), whoOptions{WorkingDir: dir, RegistryURL: "https://registry.other.example", TXTResolver: resolver})
	if err == nil || out.Outcome != "" {
		t.Fatalf("out %+v err %v", out, err)
	}
}

func TestWhoShowsTheVerifiedChainRootFirst(t *testing.T) {
	human, valid, kind := "did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w", true, "agent"
	out := whoOutput{
		ID: "did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4", Domain: "example.com",
		IDChainResult: awid.IDChainResult{Outcome: "nearest_human", HumanID: &human, IdentityValid: &valid, Kind: &kind, Reason: "verified"},
		Chain:         []whoLink{{ID: human, Kind: "human"}, {ID: "did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4", Kind: "agent"}},
	}
	want := "did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4\nNearest human: did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w\nChain: example.com -> did:aw:3YDAM5ZLRKg7eHH1Zs6sSMwkga8w (human) -> did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4 (agent)\n"
	if got := formatWho(out); got != want {
		t.Fatalf("got %q", got)
	}
	out.IDChainResult = awid.IDChainResult{Outcome: "unknown", Reason: "revoked"}
	out.Chain = nil
	if got := formatWho(out); got != "did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4\nHuman: unknown (revoked)\n" {
		t.Fatalf("got %q", got)
	}
}
