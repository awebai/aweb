package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
	Statuses map[string]map[string]any `json:"status_fixtures"`
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

type whoRecordedStatus struct{ domains *[]string }

func (s whoRecordedStatus) IDChainEvidence(_ context.Context, _ map[string]any, _ awid.IDChainSubject, domain string) *awid.IDChainEvidence {
	*s.domains = append(*s.domains, domain)
	return nil
}

// A global ID without an installed chain is still asked about: an enrolled
// ID cannot become a legacy one by leaving its chain out. Enrollment is read
// fresh from the identity's key route, never from its address: here the
// address names another domain, and that domain has no tree root.
func TestWhoAsksTheKeyRouteAboutAChainlessGlobalID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		tree    any
		omit    bool
		key     string
		outcome string
		reason  string
		status  []string
	}{
		{name: "not enrolled", tree: map[string]any{"enrolled": false}, outcome: "unknown", reason: "unregistered_identity"},
		{name: "enrolled", tree: map[string]any{"enrolled": true, "domain": "example.com"}, outcome: "unavailable", reason: "evidence_unavailable", status: []string{"example.com"}},
		{name: "unknown", omit: true, outcome: "unavailable", reason: "evidence_unavailable"},
		{name: "malformed", tree: map[string]any{"enrolled": "false"}, outcome: "unavailable", reason: "evidence_unavailable"},
		{name: "key not current", tree: map[string]any{"enrolled": false}, key: "alice", outcome: "unavailable", reason: "evidence_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := loadWhoVectors(t)
			dir := whoIdentity(t, v, false, true)
			currentKey := v.Keys["coordinator"].DIDKey
			if tc.key != "" {
				currentKey = v.Keys[tc.key].DIDKey
			}
			keyReads := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/did/"+v.Keys["coordinator"].DIDAW+"/key" {
					t.Errorf("unexpected authority request: %s %s", r.Method, r.URL.Path)
					http.NotFound(w, r)
					return
				}
				keyReads++
				response := map[string]any{"did_aw": v.Keys["coordinator"].DIDAW, "current_did_key": currentKey}
				if !tc.omit {
					response["id_tree"] = tc.tree
				}
				_ = json.NewEncoder(w).Encode(response)
			}))
			defer server.Close()
			path := filepath.Join(dir, ".aw", "identity.yaml")
			identity, err := awconfig.LoadWorktreeIdentityFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			identity.RegistryURL, identity.Address = server.URL, "signup-owner.example.com/coordinator"
			if err := awconfig.SaveWorktreeIdentityTo(path, identity); err != nil {
				t.Fatal(err)
			}
			var statusDomains []string
			out, err := executeWho(context.Background(), whoOptions{WorkingDir: dir, Status: whoRecordedStatus{&statusDomains}, TXTResolver: staticTXTResolver{}})
			if err != nil {
				t.Fatal(err)
			}
			if out.ID != v.Keys["coordinator"].DIDAW || out.Outcome != tc.outcome || out.Reason != tc.reason || out.HumanID != nil || out.Chain != nil {
				t.Fatalf("out %+v", out)
			}
			if tc.reason == "unregistered_identity" && out.IdentityValid != nil {
				t.Fatalf("an unenrolled identity is not judged: %+v", out)
			}
			if keyReads != 1 {
				t.Fatalf("key reads=%d, want 1", keyReads)
			}
			if strings.Join(statusDomains, ",") != strings.Join(tc.status, ",") {
				t.Fatalf("status read for %v, want %v", statusDomains, tc.status)
			}
		})
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

func TestWhoInstalledGlobalChainIsIndependentOfAddressDomain(t *testing.T) {
	v := loadWhoVectors(t)
	for _, tc := range []struct {
		name, address, status, outcome, reason string
		certificates                           []string
	}{
		{"same-domain", "example.com/child", "normal", "nearest_human", "verified", []string{"alice", "global-agent"}},
		{"alias-nearest-human", "signup-owner.example.com/child", "normal", "nearest_human", "verified", []string{"alice", "global-agent"}},
		{"alias-no-human", "signup-owner.example.com/child", "registered-root-agent-rotated", "no_human", "verified", []string{"registered-root-agent"}},
		{"alias-revoked", "signup-owner.example.com/child", "alice-revoked-now", "unknown", "revoked", []string{"alice", "global-agent"}},
		{"alias-unavailable", "signup-owner.example.com/child", "", "unavailable", "evidence_unavailable", []string{"alice", "global-agent"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := whoIdentity(t, v, false, false)
			key := v.Keys["global_agent"]
			seed, err := hex.DecodeString(key.SeedHex)
			if err != nil {
				t.Fatal(err)
			}
			home := dir + "/.aw"
			identity := &awconfig.WorktreeIdentity{DID: key.DIDKey, StableID: key.DIDAW, Address: tc.address, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal}
			if err := awconfig.SaveWorktreeIdentityTo(home+"/identity.yaml", identity); err != nil {
				t.Fatal(err)
			}
			if err := awid.SaveSigningKey(home+"/signing.key", ed25519.NewKeyFromSeed(seed)); err != nil {
				t.Fatal(err)
			}
			certificates := []any{}
			for _, name := range tc.certificates {
				certificates = append(certificates, v.Certificates[name].Signed)
			}
			if err := awconfig.SaveInstalledIDChain(home, map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": certificates}); err != nil {
				t.Fatal(err)
			}
			evidence := &awid.IDChainEvidence{}
			if tc.status != "" {
				status := v.Statuses[tc.status]
				epochs := status["namespace"].(map[string]any)["epochs"].([]any)
				epoch := epochs[len(epochs)-1].(map[string]any)
				age := float64(0)
				evidence = &awid.IDChainEvidence{Status: status, NamespaceAuthority: map[string]any{"domain": "example.com", "dns_name": "_awid.example.com", "inherited": false, "controller_key": epoch["did_key"]}, AgeSeconds: &age}
			}
			out, err := executeWho(t.Context(), whoOptions{WorkingDir: dir, Status: whoFixedStatus{evidence}, TXTResolver: staticTXTResolver{}})
			if err != nil || out.ID != key.DIDAW || out.Domain != "example.com" || out.Outcome != tc.outcome || out.Reason != tc.reason {
				t.Fatalf("address %s: out %+v err %v", tc.address, out, err)
			}
			if tc.reason == "verified" {
				if out.IdentityValid == nil || !*out.IdentityValid || len(out.Chain) != len(tc.certificates) {
					t.Fatalf("verified chain missing: %+v", out)
				}
			} else if out.HumanID != nil || out.Chain != nil {
				t.Fatalf("unverified ancestry displayed: %+v", out)
			}
			if tc.outcome == "nearest_human" && (out.HumanID == nil || *out.HumanID != v.Keys["alice"].DIDAW) {
				t.Fatalf("wrong human: %+v", out)
			}
		})
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
			// Exercise the HTTP JSON representation, rather than handing the
			// verifier the vector loader's integer-preserving in-memory map.
			wire, err := json.Marshal(msg)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(wire, &msg); err != nil {
				t.Fatal(err)
			}
			var chat awid.ChatMessage
			if err := json.Unmarshal(wire, &chat); err != nil {
				t.Fatal(err)
			}
			if _, err := awid.IDStatusRequest(chat.IDChain, awid.IDChainSubject{ID: c.Subject.ID, DIDKey: c.Subject.DIDKey}, ""); err != nil {
				t.Fatalf("chat wire chain refused: %v", err)
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
