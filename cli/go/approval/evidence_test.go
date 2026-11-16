package approval

import (
	proof "github.com/awebai/approval-service/verify"
	"testing"
)

func creationFixture(t *testing.T) (map[string]any, *proof.Trust) {
	t.Helper()
	c := find(t, cases(t, "issuer-service-enrollment"), func(c map[string]any) bool { return c["id"] == "activation-valid" })
	a := c["activation"].(map[string]any)
	v := c["trust"].(map[string]any)
	trust := &proof.Trust{Person: v["person"].(string), Organisation: v["organisation"].(string), IdentityKey: v["identity_key"].(string), Certificate: v["certificate"].(string), Issuer: v["issuer"].(string), IssuerPublicKey: decoded(t, v["issuer_public_key"].(string)), ObservedAt: num(v["observed_at"])}
	return a, trust
}
func TestCreationEvidenceReportsIssuerProofAndCurrentnessSeparately(t *testing.T) {
	a, trust := creationFixture(t)
	link := Link{ID: trust.Person, Certificate: trust.Certificate, Key: trust.IdentityKey}
	statement := a["evidence"].(map[string]any)
	receipt := a["creation_receipt"].(map[string]any)
	checked := CheckCreationEvidence(link, statement, receipt, trust, trust, 1100)
	if checked.Statement.Status != "valid" || checked.Proof.Status != "valid" || checked.IssuerAuthenticatedGrade == nil || *checked.IssuerAuthenticatedGrade != "passkey_uv" || checked.ProofBindsGrade == nil || !*checked.ProofBindsGrade || checked.Currentness != "current" {
		t.Fatalf("pinned creation not reported: %+v", checked)
	}
	missing := CheckCreationEvidence(link, statement, nil, trust, nil, 9999)
	if missing.Statement.Status != "valid" || missing.Proof.Status != "unavailable" || missing.Proof.Reason != "absent_proof" || missing.IssuerAuthenticatedGrade == nil || missing.ProofBindsGrade != nil {
		t.Fatalf("missing C erased issuer facts: %+v", missing)
	}
	historical := CheckCreationEvidence(link, statement, receipt, trust, nil, 9999)
	if historical.Proof.Status != "valid" || historical.Currentness != "not_evaluated" {
		t.Fatalf("live deadline erased historical proof: %+v", historical)
	}
	absent := CheckCreationEvidence(link, nil, nil, nil, nil, 1100)
	if absent.Presence != "absent" || absent.Statement.Reason != "missing_statement" || absent.IssuerAuthenticatedGrade != nil {
		t.Fatalf("absence gained grade: %+v", absent)
	}
	if text := FormatEvidence(missing); text == "" || text == FormatEvidence(checked) {
		t.Fatal("issuer statement must not render as checked creation")
	}
}
