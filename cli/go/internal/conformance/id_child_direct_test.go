package conformance_test

import (
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
