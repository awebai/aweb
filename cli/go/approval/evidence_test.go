package approval

import (
	"crypto/ed25519"
	"encoding/base64"
	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
	"strings"
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

func TestCreationEvidenceContinuityFollowsCurrentSubject(t *testing.T) {
	a, trust := creationFixture(t)
	link := Link{ID: trust.Person, Certificate: trust.Certificate, Key: trust.IdentityKey}
	statement := a["evidence"].(map[string]any)
	receipt := a["creation_receipt"].(map[string]any)
	checked := CheckCreationEvidence(link, statement, receipt, trust, trust, 1100)
	if checked.Continuity != "unbroken" {
		t.Fatalf("unchanged current subject: %+v", checked)
	}
	changed := *trust
	changed.IdentityKey = "another key"
	later := CheckCreationEvidence(link, statement, receipt, trust, &changed, 1100)
	if later.Continuity != "unknown" {
		t.Fatalf("transition not followed: %+v", later)
	}
}
func TestCreationEvidenceHardwareTextAttributesGradeToIssuer(t *testing.T) {
	grade := "certified_hardware"
	yes := true
	r := EvidenceReport{Link: Link{ID: "person"}, Statement: Check{"valid", "checked"}, Proof: Check{"valid", "checked"}, IssuerAuthenticatedGrade: &grade, ProofBindsGrade: &yes, Currentness: "current", Continuity: "unbroken"}
	text := FormatEvidence(r)
	if !strings.Contains(text, "issuer attests certified hardware; creation proof checked") || strings.Contains(text, "created with certified hardware") {
		t.Fatal(text)
	}
}

func TestCreationEvidenceCurrentSubjectWithoutCheckedProofHasUnknownContinuity(t *testing.T) {
	a, trust := creationFixture(t)
	link := Link{ID: trust.Person, Certificate: trust.Certificate, Key: trust.IdentityKey}
	statement := a["evidence"].(map[string]any)
	raw, err := proof.Canonical(a["creation_receipt"])
	if err != nil {
		t.Fatal(err)
	}
	invalid, err := proof.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	invalid["assertion"].(map[string]any)["signature"] = "AA"
	for _, tc := range []struct {
		name        string
		receipt     map[string]any
		proofStatus string
	}{
		{"absent", nil, "unavailable"},
		{"invalid", invalid, "invalid"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			report := CheckCreationEvidence(link, statement, tc.receipt, trust, trust, 1100)
			if report.Statement.Status != "valid" || report.Currentness != "current" || report.Proof.Status != tc.proofStatus {
				t.Fatalf("wrong neighboring case: %+v", report)
			}
			if report.Continuity != "unknown" || !strings.Contains(FormatEvidence(report), "continuity unknown") {
				t.Fatalf("unchecked creation claimed continuity: %+v", report)
			}
		})
	}
}

func TestCreationEvidenceTransitionProfileIsUnsupportedNotInvalid(t *testing.T) {
	for _, mode := range []string{"unbroken", "assisted", "recreated"} {
		t.Run(mode, func(t *testing.T) {
			a, trust := creationFixture(t)
			link := Link{ID: trust.Person, Certificate: trust.Certificate, Key: trust.IdentityKey}
			statement := a["evidence"].(map[string]any)
			statement["evidence"].(map[string]any)["transition"] = map[string]any{"mode": mode}
			report := CheckCreationEvidence(link, statement, a["creation_receipt"].(map[string]any), trust, trust, 1100)
			if report.Statement.Status != "unsupported" || report.Statement.Reason != "unsupported_profile" || report.Continuity != "unknown" || report.IssuerAuthenticatedGrade != nil {
				t.Fatalf("transition misreported: %+v", report)
			}
			if text := FormatEvidence(report); !strings.Contains(text, "profile unsupported") || strings.Contains(text, "invalid") {
				t.Fatal(text)
			}
		})
	}
}

// No registry reader is constructed or passed: this is an as-of Trust input
// and the actual shared creation proof, with no separately acquired first key.
func TestCreationEvidenceFirstKeyCheckNeedsNoRegistryReader(t *testing.T) {
	a, trust := creationFixture(t)
	link := Link{ID: trust.Person, Certificate: trust.Certificate, Key: trust.IdentityKey}
	report := CheckCreationEvidence(link, a["evidence"].(map[string]any), a["creation_receipt"].(map[string]any), trust, trust, 1100)
	if report.Statement.Status != "valid" || report.Proof.Status != "valid" || report.Continuity != "unbroken" {
		t.Fatalf("offline genesis check: %+v", report)
	}
}
func TestCreationEvidenceRejectsSubjectKeyWhoseStableIDDiffers(t *testing.T) {
	a, trust := creationFixture(t)
	// A stable ID anchored in another first key, but a current subject key
	// equal to this fixture's key: an issuer cannot label that initial creation.
	issuerPub, issuerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	trust.Person = awid.ComputeStableID(issuerPub)
	trust.Issuer = awid.ComputeDIDKey(issuerPub)
	trust.IssuerPublicKey = issuerPub
	statement := a["evidence"].(map[string]any)
	body := statement["evidence"].(map[string]any)
	body["subject"].(map[string]any)["id"] = trust.Person
	body["issuer"] = trust.Issuer
	raw, err := proof.Canonical(body)
	if err != nil {
		t.Fatal(err)
	}
	statement["signature"] = base64.RawURLEncoding.EncodeToString(ed25519.Sign(issuerKey, append([]byte("aweb.human-id-evidence/1\n"), raw...)))
	link := Link{ID: trust.Person, Certificate: trust.Certificate, Key: trust.IdentityKey}
	report := CheckCreationEvidence(link, statement, a["creation_receipt"].(map[string]any), trust, trust, 1100)
	if report.Statement.Status != "invalid" || report.Statement.Reason != "creation_key_inconsistent" || report.Continuity == "unbroken" {
		t.Fatalf("inconsistent initial creation: %+v", report)
	}
}
