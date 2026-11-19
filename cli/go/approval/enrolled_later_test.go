package approval

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	proof "github.com/awebai/approval-service/verify"
)

// Consume the issuer's signed public corpus with its explicit historical trust
// input. This tests report semantics, not a live registry or hardware claim.
func TestLaterEnrollmentReportsApprovalSinceWithoutChangingCreation(t *testing.T) {
	root, err := exec.Command("go", "list", "-m", "-f", "{{.Dir}}", "github.com/awebai/approval-service").Output()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(strings.TrimSpace(string(root)), "vectors", "later-enrollment-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Cases []map[string]any `json:"cases"`
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&corpus); err != nil {
		t.Fatal(err)
	}
	c := corpus.Cases[0]
	if c["id"] != "existing-person-activates" {
		t.Fatal("missing later-enrollment neighbor")
	}
	v := c["trust"].(map[string]any)
	key, err := base64.RawURLEncoding.DecodeString(v["issuer_public_key"].(string))
	if err != nil {
		t.Fatal(err)
	}
	now, err := v["observed_at"].(json.Number).Int64()
	if err != nil {
		t.Fatal(err)
	}
	trust := &proof.Trust{Person: v["person"].(string), Organisation: v["organisation"].(string), IdentityKey: v["identity_key"].(string), Certificate: v["certificate"].(string), Issuer: v["issuer"].(string), IssuerPublicKey: key, ObservedAt: now}
	trust.NamespaceIssuer, _ = v["namespace_issuer"].(string)
	activation := c["activation"].(map[string]any)
	statement := activation["evidence"].(map[string]any)
	before, err := proof.Canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	for _, withProof := range []bool{false, true} {
		var receipt map[string]any
		if withProof {
			receipt = activation["confirmation_receipt"].(map[string]any)
		}
		report := CheckHumanEvidence(Link{ID: trust.Person, Key: trust.IdentityKey, Certificate: trust.Certificate}, statement, receipt, trust, trust, now)
		if report.Statement.Status != "valid" || report.IssuerAuthenticatedGrade == nil || *report.IssuerAuthenticatedGrade != "passkey_uv" {
			t.Fatalf("report=%+v", report)
		}
		if (report.Proof.Status == "valid") != withProof {
			t.Fatalf("proof=%+v", report.Proof)
		}
		line := FormatEvidence(report)
		if !strings.Contains(line, "can approve since") || !strings.Contains(line, "grade passkey_uv (issuer's statement)") || strings.Contains(line, "created with") || strings.Contains(line, "creation proof") {
			t.Fatal(line)
		}
		if strings.Contains(line, "confirmation proof checked") != withProof {
			t.Fatal(line)
		}
		after, err := proof.Canonical(statement)
		if err != nil || !bytes.Equal(before, after) {
			t.Fatal("reader rewrote the statement")
		}
	}
}

// The signed public corpus is checked first; each refusal changes one input
// on the actual shared verifier path without replacing its proof policy.
func TestLaterEnrollmentKeepsUnsupportedAndInvalidEvidenceDistinct(t *testing.T) {
	vector := find(t, cases(t, "later-enrollment"), func(value map[string]any) bool {
		return value["id"] == "existing-person-activates"
	})
	trustInput := vector["trust"].(map[string]any)
	trust := &proof.Trust{
		Person: trustInput["person"].(string), Organisation: trustInput["organisation"].(string),
		IdentityKey: trustInput["identity_key"].(string), Certificate: trustInput["certificate"].(string),
		Issuer: trustInput["issuer"].(string), IssuerPublicKey: decoded(t, trustInput["issuer_public_key"].(string)),
		NamespaceIssuer: trustInput["namespace_issuer"].(string), ObservedAt: num(trustInput["observed_at"]),
	}
	link := Link{ID: trust.Person, Certificate: trust.Certificate, Key: trust.IdentityKey}
	activation := vector["activation"].(map[string]any)
	statement := activation["evidence"].(map[string]any)
	valid := CheckHumanEvidence(link, statement, nil, trust, trust, trust.ObservedAt)
	if valid.Statement != (Check{Status: "valid", Reason: "checked"}) || valid.IssuerAuthenticatedGrade == nil {
		t.Fatalf("signed valid neighbor: %+v", valid)
	}
	raw, err := proof.Canonical(statement)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name string
		edit func(map[string]any)
		want Check
	}{
		{"unsupported_version", func(e map[string]any) { e["evidence"].(map[string]any)["version"] = json.Number("2") }, Check{"unsupported", "enrollment_evidence_unsupported"}},
		{"invalid_body", func(e map[string]any) { delete(e["evidence"].(map[string]any), "enrollment") }, Check{"invalid", "enrollment_evidence_invalid"}},
		{"invalid_signature", func(e map[string]any) { e["signature"] = "AA" }, Check{"invalid", "signature_invalid"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed, err := proof.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			test.edit(changed)
			report := CheckHumanEvidence(link, changed, nil, trust, trust, trust.ObservedAt)
			if report.Statement != test.want || report.IssuerAuthenticatedGrade != nil || report.ApprovalSince != nil || report.Continuity != "unknown" || report.Proof != (Check{"not_evaluated", "statement_unverified"}) {
				t.Fatalf("evidence refusal: %+v, want %+v without authenticated facts", report, test.want)
			}
		})
	}
}
