package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// Immediate init issues directly (docs/id-certificates.md §6): the same
// certificate the CSR exchange would sign, with no request or invitation.
// The frozen responses fix the exact chain each parent must produce.

func (x idChildExchange) directChild(t *testing.T, request string) awid.IDChild {
	t.Helper()
	r := x.requests[request].Signed["request"].(map[string]any)
	return awid.IDChild{ID: r["id"].(string), Domain: r["domain"].(string), Parent: r["parent"].(map[string]any), Kind: r["kind"].(string)}
}

func (x idChildExchange) frozenChain(t *testing.T, response string) string {
	t.Helper()
	parsed, err := awid.ParseIDCertificateResponse([]byte(x.responses[response].CanonicalUTF8))
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := awid.CanonicalJSONValue(parsed["chain"])
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func at(t *testing.T, stamp string) time.Time {
	t.Helper()
	now, err := time.Parse(time.RFC3339, stamp)
	if err != nil {
		t.Fatal(err)
	}
	return now
}

func TestIDChildDirectIssueProducesTheFrozenChain(t *testing.T) {
	x := loadIDChildExchange(t)
	for _, tc := range []struct {
		name, request, response, signer, issuedAt string
		parentChain                               bool
	}{
		{"the namespace root issues its first human", "root-human-issue", "root-human-issued", "root", "2026-10-26T00:00:00Z", false},
		{"a human issues a human", "human-issue", "human-issued", "alice", "2026-10-26T00:02:00Z", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			child := x.directChild(t, tc.request)
			var parentChain []any
			if tc.parentChain {
				parentChain = x.parentChain(t, "normal", child.Parent["id"].(string))
			}
			issuance := newIssuedStore(t, x.v)
			calls := 0
			bundle, err := awid.IssueIDChild(issuance, child, parentChain, x.evidence("normal"), vectorSigner(t, x.v, tc.signer, &calls), at(t, tc.issuedAt))
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.CanonicalJSONValue(bundle)
			if err != nil {
				t.Fatal(err)
			}
			if encoded != x.frozenChain(t, tc.response) {
				t.Fatalf("chain differs from frozen %s:\n%s", tc.response, encoded)
			}
			certificates := bundle["certificates"].([]any)
			leaf := certificates[len(certificates)-1].(map[string]any)
			id, err := awid.IDCertificateID(leaf["certificate"].(map[string]any))
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !issuance.has(id) {
				t.Fatalf("calls=%d recorded=%v", calls, issuance.has(id))
			}
		})
	}
}

func TestIDChildDirectIssueRefusals(t *testing.T) {
	x := loadIDChildExchange(t)
	refused := func(t *testing.T, err error, reason string) {
		t.Helper()
		if got := awid.IDCertificateErrorCode(err); got != reason {
			t.Fatalf("reason=%q (%v) want %q", got, err, reason)
		}
	}
	human := x.directChild(t, "human-issue")
	root := x.directChild(t, "root-human-issue")
	aliceChain := func(t *testing.T) []any { return x.parentChain(t, "normal", human.Parent["id"].(string)) }

	refusesUnsigned := func(t *testing.T, child awid.IDChild, chain []any, evidence *awid.IDChainEvidence, signer, reason string) {
		t.Helper()
		issuance := newIssuedStore(t, x.v)
		calls := 0
		bundle, err := awid.IssueIDChild(issuance, child, chain, evidence, vectorSigner(t, x.v, signer, &calls), at(t, "2026-10-26T00:02:00Z"))
		if reason != "" {
			refused(t, err, reason)
		} else if err == nil {
			t.Fatal("issued")
		}
		if bundle != nil || calls != 0 || issuance.writes != 0 {
			t.Fatalf("calls=%d writes=%d", calls, issuance.writes)
		}
	}

	t.Run("an agent parent never issues a human", func(t *testing.T) {
		child := human
		child.Parent = map[string]any{"kind": "identity", "id": x.v.Keys["global_agent"].DIDAW}
		chain := append(aliceChain(t), x.parentChain(t, "normal", x.v.Keys["global_agent"].DIDAW)...)
		refusesUnsigned(t, child, chain, x.evidence("normal"), "global_agent", "human_issuer_is_agent")
	})
	t.Run("a revoked parent issues nothing", func(t *testing.T) {
		refusesUnsigned(t, human, aliceChain(t), x.evidence("alice-revoked-now"), "alice", "")
	})
	t.Run("no evidence", func(t *testing.T) {
		refusesUnsigned(t, human, aliceChain(t), nil, "alice", "evidence_unavailable")
		refusesUnsigned(t, root, nil, nil, "root", "evidence_unavailable")
	})
	t.Run("evidence past the fresh bound", func(t *testing.T) {
		stale := resignFixture{status: x.v.Statuses["normal"]}.evidence(61)
		refusesUnsigned(t, human, aliceChain(t), stale, "alice", "status_expired")
		refusesUnsigned(t, root, nil, stale, "root", "status_expired")
	})
	t.Run("the parent chain must end in the parent", func(t *testing.T) {
		refusesUnsigned(t, human, x.parentChain(t, "normal", x.v.Keys["bob"].DIDAW), x.evidence("normal"), "alice", "")
	})
	t.Run("a namespace parent presents no parent chain", func(t *testing.T) {
		refusesUnsigned(t, root, aliceChain(t), x.evidence("normal"), "root", "request_binding_mismatch")
	})
	t.Run("a namespace parent for another domain", func(t *testing.T) {
		child := root
		child.Parent = map[string]any{"kind": "namespace", "id": "example.org"}
		refusesUnsigned(t, child, nil, x.evidence("normal"), "root", "domain_mismatch")
	})
	t.Run("a signer that is not the current key", func(t *testing.T) {
		issuance := newIssuedStore(t, x.v)
		calls := 0
		bundle, err := awid.IssueIDChild(issuance, root, nil, x.evidence("normal"), vectorSigner(t, x.v, "alice", &calls), at(t, "2026-10-26T00:00:00Z"))
		refused(t, err, "issuer_key_not_current")
		if bundle != nil || issuance.writes != 0 {
			t.Fatal("recorded a certificate signed by the wrong key")
		}
	})
	t.Run("nothing is returned unless the issuance is recorded", func(t *testing.T) {
		issuance := newIssuedStore(t, x.v)
		issuance.failWrite = 1
		calls := 0
		bundle, err := awid.IssueIDChild(issuance, root, nil, x.evidence("normal"), vectorSigner(t, x.v, "root", &calls), at(t, "2026-10-26T00:00:00Z"))
		if err == nil || bundle != nil {
			t.Fatalf("bundle=%v err=%v", bundle != nil, err)
		}
	})
}

// The root admits an agent directly: a root→agent chain, which verifies as
// no_human (§3), byte-identical to the frozen root-agent certificate.
func TestIDChildDirectIssueRootAgentIsNoHuman(t *testing.T) {
	x := loadIDChildExchange(t)
	frozen := x.v.Certificates["root-agent"].Signed
	certificate := frozen["certificate"].(map[string]any)
	child := awid.IDChild{ID: certificate["id"].(string), Domain: "example.com", Parent: map[string]any{"kind": "namespace", "id": "example.com"}, Kind: "agent"}
	issuance := newIssuedStore(t, x.v)
	calls := 0
	bundle, err := awid.IssueIDChild(issuance, child, nil, x.evidence("normal"), vectorSigner(t, x.v, "root", &calls), at(t, certificate["issued_at"].(string)))
	if err != nil {
		t.Fatal(err)
	}
	got, err := awid.CanonicalJSONValue(bundle["certificates"].([]any)[0])
	if err != nil {
		t.Fatal(err)
	}
	want, err := awid.CanonicalJSONValue(frozen)
	if err != nil {
		t.Fatal(err)
	}
	if got != want || calls != 1 {
		t.Fatalf("calls=%d certificate:\n%s\nwant:\n%s", calls, got, want)
	}
	subject := awid.IDChainSubject{ID: child.ID, DIDKey: child.ID, TeamMemberDIDKey: child.ID}
	verdict := awid.VerifyIDChain(bundle, subject, x.evidence("normal"), "example.com")
	if verdict.Outcome != "no_human" || verdict.IdentityValid == nil || !*verdict.IdentityValid {
		t.Fatalf("verdict %+v", verdict)
	}
}

// addKey adds a deterministic key named name to the vectors' keys.
func (x idChildExchange) addKey(name string) {
	seed := sha256.Sum256([]byte(name))
	public := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	x.v.Keys[name] = struct {
		SeedHex string `json:"seed_hex"`
		DIDKey  string `json:"did_key"`
		DIDAW   string `json:"did_aw"`
	}{hex.EncodeToString(seed[:]), awid.ComputeDIDKey(public), awid.ComputeStableID(public)}
}

// registeredLine issues a line of length did:aw agents under alice, each by
// the one before it over IssueIDChild, and registers each in status "line",
// a copy of "normal", as the registry records a registered identity: one
// signed register_did entry and its certificate. It returns the key names
// from alice down and each one's own chain.
func (x idChildExchange) registeredLine(t *testing.T, length int) ([]string, map[string][]any) {
	t.Helper()
	raw, err := json.Marshal(x.v.Statuses["normal"])
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var status map[string]any
	if err := d.Decode(&status); err != nil {
		t.Fatal(err)
	}
	x.v.Statuses["line"] = status
	names := []string{"alice"}
	chains := map[string][]any{"alice": x.parentChain(t, "normal", x.v.Keys["alice"].DIDAW)}
	for n := 1; n <= length; n++ {
		parent, name := names[len(names)-1], fmt.Sprintf("line-%d", n)
		x.addKey(name)
		key := x.v.Keys[name]
		calls := 0
		child := awid.IDChild{ID: key.DIDAW, Domain: "example.com", Parent: map[string]any{"kind": "identity", "id": x.v.Keys[parent].DIDAW}, Kind: "agent"}
		bundle, err := awid.IssueIDChild(newIssuedStore(t, x.v), child, chains[parent], x.evidence("line"), vectorSigner(t, x.v, parent, &calls), at(t, "2026-10-26T00:05:00Z"))
		if err != nil {
			t.Fatalf("%s issues %s: %v", parent, name, err)
		}
		certificates := bundle["certificates"].([]any)
		signed := certificates[len(certificates)-1].(map[string]any)
		certificateID, err := awid.IDCertificateID(signed["certificate"].(map[string]any))
		if err != nil {
			t.Fatal(err)
		}
		stateHash := sha256.Sum256([]byte(fmt.Sprintf(`{"current_did_key":%q,"did_aw":%q}`, key.DIDKey, key.DIDAW)))
		entry := awid.DidKeyEvidence{Seq: 1, Operation: "register_did", NewDIDKey: key.DIDKey, StateHash: hex.EncodeToString(stateHash[:]), AuthorizedBy: key.DIDKey, Timestamp: "2026-10-26T00:05:00Z"}
		payload := awid.CanonicalDidLogPayload(key.DIDAW, &entry)
		entryHash := sha256.Sum256([]byte(payload))
		seed, err := hex.DecodeString(key.SeedHex)
		if err != nil {
			t.Fatal(err)
		}
		registeredAt := fmt.Sprintf("2026-10-26T00:%02d:00.000000Z", 5+n)
		status["identities"] = append(status["identities"].([]any), map[string]any{
			"id": key.DIDAW, "current_certificate_id": certificateID, "current_key_seq": json.Number("1"),
			"key_history": []any{map[string]any{"entry": map[string]any{
				"seq": json.Number("1"), "operation": "register_did", "previous_did_key": nil, "new_did_key": key.DIDKey,
				"prev_entry_hash": nil, "entry_hash": hex.EncodeToString(entryHash[:]), "state_hash": entry.StateHash,
				"authorized_by": key.DIDKey, "signature": base64.RawStdEncoding.EncodeToString(ed25519.Sign(ed25519.NewKeyFromSeed(seed), []byte(payload))),
				"timestamp": entry.Timestamp,
			}, "registered_at": registeredAt}},
			"certificates": []any{map[string]any{"signed": signed, "registered_at": registeredAt, "superseded_at": nil, "issuer_key_seq": json.Number("1")}},
			"revocation":   nil,
		})
		names = append(names, name)
		chains[name] = certificates
	}
	return names, chains
}

// A verifier accepts at most eight certificates (docs/id-certificates.md
// §5), so a registered parent whose own chain already has eight issues
// nothing, over either issuance path: its child's chain could never verify.
// One level up the same line, a parent issues a child whose
// eight-certificate chain verifies.
func TestIDChildIssueRefusesPastTheMaximumDepth(t *testing.T) {
	x := loadIDChildExchange(t)
	names, chains := x.registeredLine(t, awid.IDChainMaxDepth-1)
	for _, tc := range []struct {
		signer, child string
		refused       bool
	}{
		{names[len(names)-2], "leaf-under-seven", false},
		{names[len(names)-1], "leaf-under-eight", true},
	} {
		x.addKey(tc.child)
		parent := map[string]any{"kind": "identity", "id": x.v.Keys[tc.signer].DIDAW}
		childID := x.v.Keys[tc.child].DIDKey
		parentChain := chains[tc.signer]
		issued := func(t *testing.T, bundle map[string]any, err error, calls, writes int) {
			t.Helper()
			if tc.refused {
				if got := awid.IDCertificateErrorCode(err); got != "depth_exceeded" || bundle != nil || calls != 0 || writes != 0 {
					t.Fatalf("reason=%q (%v) calls=%d writes=%d", got, err, calls, writes)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			subject := awid.IDChainSubject{ID: childID, DIDKey: childID, TeamMemberDIDKey: childID}
			verdict := awid.VerifyIDChain(bundle, subject, x.evidence("line"), "example.com")
			if len(bundle["certificates"].([]any)) != awid.IDChainMaxDepth || verdict.IdentityValid == nil || !*verdict.IdentityValid {
				t.Fatalf("verdict %+v", verdict)
			}
		}
		t.Run(fmt.Sprintf("direct issue under a chain of %d", len(parentChain)), func(t *testing.T) {
			issuance := newIssuedStore(t, x.v)
			calls := 0
			child := awid.IDChild{ID: childID, Domain: "example.com", Parent: parent, Kind: "agent"}
			bundle, err := awid.IssueIDChild(issuance, child, parentChain, x.evidence("line"), vectorSigner(t, x.v, tc.signer, &calls), at(t, "2026-10-26T00:20:00Z"))
			issued(t, bundle, err, calls, issuance.writes)
		})
		t.Run(fmt.Sprintf("invitation approval under a chain of %d", len(parentChain)), func(t *testing.T) {
			r, request := x.issueUnder(t, parent, parentChain, tc.signer, tc.child, childID, "agent")
			r.status = "line"
			if _, err := r.receive(request); err != nil {
				t.Fatal(err)
			}
			response, err := r.approve(t, "20000000-0000-4000-8000-0000000000a1", awid.IDHumanApproval{})
			var bundle map[string]any
			if err == nil {
				parsed, perr := awid.ParseIDCertificateResponse(response)
				if perr != nil {
					t.Fatal(perr)
				}
				bundle = parsed["chain"].(map[string]any)
			} else if response != nil {
				t.Fatal("a refused approval returned a response")
			}
			issued(t, bundle, err, r.calls, r.issuance.writes)
			if tc.refused && r.invitation(t, "10000000-0000-4000-8000-0000000000a1").Request.State == awid.IDRequestIssued {
				t.Fatal("a refused approval marked the request issued")
			}
		})
	}
}
