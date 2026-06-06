package awid

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type atomicAddressClaimVector struct {
	Operation          string `json:"operation"`
	Domain             string `json:"domain"`
	AddressName        string `json:"address_name"`
	DIDAW              string `json:"did_aw"`
	CurrentDIDKey      string `json:"current_did_key"`
	RegistryURL        string `json:"registry_url"`
	RegistryURLAliases []struct {
		Input     string `json:"input"`
		Canonical string `json:"canonical"`
	} `json:"registry_url_aliases"`
	Timestamp          string `json:"timestamp"`
	DryRun             bool   `json:"dry_run"`
	IdentityCustody    string `json:"identity_custody"`
	NamespaceCustody   string `json:"namespace_custody"`
	IdentitySignature  string `json:"identity_signature"`
	IdentityProofHash  string `json:"identity_proof_hash"`
	IdentityCanonical  string `json:"identity_canonical"`
	NamespaceCanonical string `json:"namespace_canonical"`
}

type atomicAddressClaimConflictCodeVector struct {
	Codes []string `json:"codes"`
}

func readDocsVector(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestAtomicAddressClaimCanonicalFixture(t *testing.T) {
	t.Parallel()

	data := readDocsVector(t, "atomic-address-claim-v1.json")
	var vector atomicAddressClaimVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	fields := AtomicAddressClaimFields{
		Operation:        vector.Operation,
		Domain:           vector.Domain,
		AddressName:      vector.AddressName,
		DIDAW:            vector.DIDAW,
		CurrentDIDKey:    vector.CurrentDIDKey,
		RegistryURL:      vector.RegistryURL,
		Timestamp:        vector.Timestamp,
		DryRun:           vector.DryRun,
		IdentityCustody:  vector.IdentityCustody,
		NamespaceCustody: vector.NamespaceCustody,
	}
	identityCanonical, err := AtomicAddressClaimIdentityCanonical(fields)
	if err != nil {
		t.Fatal(err)
	}
	if identityCanonical != vector.IdentityCanonical {
		t.Fatalf("identity canonical mismatch:\n got: %s\nwant: %s", identityCanonical, vector.IdentityCanonical)
	}
	identityProofHash, err := AtomicAddressClaimIdentityProofHash(identityCanonical, vector.IdentitySignature)
	if err != nil {
		t.Fatal(err)
	}
	if identityProofHash != vector.IdentityProofHash {
		t.Fatalf("identity proof hash=%q want %q", identityProofHash, vector.IdentityProofHash)
	}
	namespaceCanonical, err := AtomicAddressClaimNamespaceCanonical(fields, identityProofHash)
	if err != nil {
		t.Fatal(err)
	}
	if namespaceCanonical != vector.NamespaceCanonical {
		t.Fatalf("namespace canonical mismatch:\n got: %s\nwant: %s", namespaceCanonical, vector.NamespaceCanonical)
	}
	for _, alias := range vector.RegistryURLAliases {
		got, err := canonicalRegistryServerOrigin(alias.Input)
		if err != nil {
			t.Fatalf("canonicalRegistryServerOrigin(%q): %v", alias.Input, err)
		}
		if got != alias.Canonical {
			t.Fatalf("canonicalRegistryServerOrigin(%q)=%q want %q", alias.Input, got, alias.Canonical)
		}
	}
}

func TestAtomicAddressClaimConflictCodesMatchSharedVector(t *testing.T) {
	t.Parallel()

	data := readDocsVector(t, "atomic-address-claim-conflict-codes-v1.json")
	var vector atomicAddressClaimConflictCodeVector
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.Codes) != len(AtomicAddressClaimConflictCodes) {
		t.Fatalf("codes len=%d want %d", len(AtomicAddressClaimConflictCodes), len(vector.Codes))
	}
	for i := range vector.Codes {
		if got, want := AtomicAddressClaimConflictCodes[i], vector.Codes[i]; got != want {
			t.Fatalf("code[%d]=%q want %q", i, got, want)
		}
	}
}

func TestAtomicAddressClaimRejectsHostedDIDSelfNamespaceCombination(t *testing.T) {
	t.Parallel()

	_, err := AtomicAddressClaimIdentityCanonical(AtomicAddressClaimFields{
		Operation:        AtomicAddressClaimOperation,
		Domain:           "example.com",
		AddressName:      "alice",
		DIDAW:            "did:aw:zQmAtomicClaimFixtureStableID111111111111111111111",
		CurrentDIDKey:    "did:key:z6MkhAtomicClaimFixtureCurrentKey1111111111111111111",
		RegistryURL:      "https://api.awid.ai",
		Timestamp:        "2026-06-06T09:30:00Z",
		IdentityCustody:  string(AddressClaimCustodyHostedCustodial),
		NamespaceCustody: string(AddressClaimCustodySelf),
	})
	if err == nil {
		t.Fatal("expected hosted-DID/self-namespace custody combination to fail")
	}
}
