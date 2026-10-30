package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
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

// No registry answers at the --registry origin, so status is unavailable:
// aw who reports exactly that, never the human the installed chain names.
// Nothing here resolves a name.
func TestWhoReportsUnavailableStatusFromItsRegistry(t *testing.T) {
	v := loadWhoVectors(t)
	registryURL := "http://127.0.0.1:1"
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
	if exitCode(err) != 2 || out.Outcome != "" {
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

func TestWhoReceivedChainBindsTheAuthenticatedSender(t *testing.T) {
	v := loadWhoVectors(t)
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}
	msg := awid.InboxMessage{FromDID: v.Keys["bob"].DIDKey, IDChain: chain, VerificationStatus: awid.Verified}
	out, err := executeWhoReceived(context.Background(), msg, whoOptions{TXTResolver: staticTXTResolver{}})
	if err != nil || out.Reason != "subject_mismatch" || out.HumanID != nil {
		t.Fatalf("out %+v err %v", out, err)
	}
	msg.FromDID = v.Keys["coordinator"].DIDKey
	msg.IDChain = nil
	out, err = executeWhoReceived(context.Background(), msg, whoOptions{TXTResolver: staticTXTResolver{}})
	if err != nil || out.Reason != "legacy_no_chain" {
		t.Fatalf("out %+v err %v", out, err)
	}
	msg.IDChain = chain
	msg.VerificationStatus = awid.Failed
	out, err = executeWhoReceived(context.Background(), msg, whoOptions{TXTResolver: staticTXTResolver{}})
	if err != nil || out.HumanID != nil || out.Reason != "subject_mismatch" {
		t.Fatalf("out %+v err %v", out, err)
	}
}

func TestWhoSenderMatchesOnlyTheSenderAndDIDsAreCaseSensitive(t *testing.T) {
	msg := awid.InboxMessage{FromAlias: "sender", FromAddress: "example.com/sender", FromStableID: "did:aw:AbC", ToAlias: "receiver", ToStableID: "did:aw:abc"}
	for _, tc := range []struct {
		target string
		want   bool
	}{{"sender", true}, {"example.com/sender", true}, {"did:aw:AbC", true}, {"receiver", false}, {"did:aw:abc", false}} {
		if got := whoSenderMatches(msg, tc.target); got != tc.want {
			t.Fatalf("%s: %v", tc.target, got)
		}
	}
}

type whoFixedStatus struct{ evidence *awid.IDChainEvidence }

func (s whoFixedStatus) IDChainEvidence(context.Context, map[string]any, awid.IDChainSubject, string) *awid.IDChainEvidence {
	return s.evidence
}

func TestWhoReceivedUsesSharedCurrentStatus(t *testing.T) {
	raw, err := os.ReadFile("../../../../docs/vectors/id-certificates-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Cases []struct {
			Name    string   `json:"name"`
			Chain   []string `json:"chain"`
			Status  string   `json:"status"`
			Subject struct {
				ID     string `json:"id"`
				DIDKey string `json:"did_key"`
			} `json:"subject"`
			Expected awid.IDChainResult `json:"expected"`
		} `json:"verification_cases"`
		Status map[string]map[string]any `json:"status_fixtures"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	fixtures := loadWhoVectors(t)
	selected := map[string]bool{"local-child-nearest-human": true, "registered-agent": true, "humanless-root-agent": true, "human-revocation-cascades-to-registered-agent": true, "root-replacement-registered-agent-refuses": true, "root-local-old-key-after-rotation": true}
	count := 0
	for _, c := range v.Cases {
		if !selected[c.Name] {
			continue
		}
		count++
		t.Run(c.Name, func(t *testing.T) {
			certs := []any{}
			for _, name := range c.Chain {
				certs = append(certs, fixtures.Certificates[name].Signed)
			}
			status := v.Status[c.Status]
			ns := status["namespace"].(map[string]any)
			epochs := ns["epochs"].([]any)
			epoch := epochs[len(epochs)-1].(map[string]any)
			age := float64(0)
			evidence := &awid.IDChainEvidence{Status: status, NamespaceAuthority: map[string]any{"domain": status["domain"], "dns_name": "_awid.example.com", "inherited": false, "controller_key": epoch["did_key"]}, AgeSeconds: &age}
			msg := awid.InboxMessage{FromDID: c.Subject.DIDKey, IDChain: map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certs}, VerificationStatus: awid.Verified}
			if c.Subject.ID != c.Subject.DIDKey {
				msg.FromStableID = c.Subject.ID
			}
			out, err := executeWhoReceived(context.Background(), msg, whoOptions{Status: whoFixedStatus{evidence}, TXTResolver: staticTXTResolver{}})
			if err != nil || out.Outcome != c.Expected.Outcome || out.Reason != c.Expected.Reason {
				t.Fatalf("out %+v expected %+v err %v", out, c.Expected, err)
			}
			if c.Expected.HumanID != nil && (out.HumanID == nil || *out.HumanID != *c.Expected.HumanID) {
				t.Fatalf("wrong human %+v", out)
			}
			if c.Expected.HumanID == nil && out.HumanID != nil {
				t.Fatalf("unexpected human %+v", out)
			}
		})
	}
	if count != len(selected) {
		t.Fatalf("missing fixture: found %d of %d", count, len(selected))
	}
}

func TestWhoStoredBogusParentSignatureNeverNamesHuman(t *testing.T) {
	v := loadWhoVectors(t)
	v.Certificates["alice"].Signed["signature"] = strings.Repeat("A", 86)
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{v.Certificates["alice"].Signed, v.Certificates["coordinator"].Signed}}
	out, err := executeWhoReceived(context.Background(), awid.InboxMessage{FromDID: v.Keys["coordinator"].DIDKey, IDChain: chain, VerificationStatus: awid.Verified}, whoOptions{TXTResolver: staticTXTResolver{}})
	if err != nil || out.Reason != "invalid_signature" || out.HumanID != nil || len(out.Chain) != 0 {
		t.Fatalf("out %+v err %v", out, err)
	}
}

func TestWhoAddresslessGlobalUsesVerifiedDeliveryRegistryEnrollment(t *testing.T) {
	v := loadWhoVectors(t)
	msg := awid.InboxMessage{FromDID: v.Keys["alice"].DIDKey, FromStableID: v.Keys["alice"].DIDAW, VerificationStatus: awid.Verified}
	calls := 0
	options := whoOptions{TXTResolver: staticTXTResolver{}, ReceivedEnrollment: func(_ context.Context, id, key string) awid.IDTreeEnrollmentResult {
		calls++
		if id != msg.FromStableID || key != msg.FromDID {
			t.Fatal("wrong independently verified subject")
		}
		return awid.IDTreeEnrollmentResult{State: "not_enrolled"}
	}}
	out, err := executeWhoReceived(context.Background(), msg, options)
	if err != nil || out.Reason != "unregistered_identity" || out.Outcome != "unknown" || out.HumanID != nil || calls != 1 {
		t.Fatalf("out %+v err %v calls %d", out, err, calls)
	}
	msg.VerificationStatus = awid.Failed
	_, _ = executeWhoReceived(context.Background(), msg, options)
	if calls != 1 {
		t.Fatal("unverified sender must not read enrollment")
	}
}
