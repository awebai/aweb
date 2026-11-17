package approval

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	proof "github.com/awebai/approval-service/verify"
	"github.com/awebai/aw/awid"
)

type Link struct {
	Position    int    `json:"position"`
	ID          string `json:"id"`
	Certificate string `json:"certificate"`
	Key         string `json:"key,omitempty"`
}
type Check struct {
	Status string `json:"status"`
	Reason string `json:"reason"`
}
type EvidenceReport struct {
	Link                     Link    `json:"link"`
	Presence                 string  `json:"presence"`
	Statement                Check   `json:"statement"`
	Proof                    Check   `json:"proof"`
	IssuerAuthenticatedGrade *string `json:"issuer_authenticated_grade"`
	ProofBindsGrade          *bool   `json:"proof_binds_grade"`
	Credential               *string `json:"credential"`
	SnapshotRef              *string `json:"snapshot_ref"`
	Currentness              string  `json:"currentness"`
	Continuity               string  `json:"continuity"`
	AsOf                     *int64  `json:"as_of,omitempty"`
	Profile                  string  `json:"profile,omitempty"`
	ApprovalSince            *int64  `json:"can_approve_since,omitempty"`
}

// CheckHumanEvidence keeps later enrollment separate from creation. The shared
// approval verifier authenticates its statement and optional confirmation proof;
// neither result supplies trust or changes the independently checked ID chain.
func CheckHumanEvidence(link Link, statement, receipt map[string]any, trust, current *proof.Trust, now int64) EvidenceReport {
	if stringValue(objectValue(statement, "evidence"), "kind") != "human_enrolled_later" {
		return CheckCreationEvidence(link, statement, receipt, trust, current, now)
	}
	r := CheckCreationEvidence(link, nil, nil, nil, nil, now)
	r.Presence, r.Profile = "present", "human_enrolled_later"
	r.Proof = Check{"not_evaluated", "statement_unverified"}
	if trust == nil {
		r.Statement = Check{"unavailable", "trust_input_unavailable"}
		return r
	}
	if trust.Person != link.ID || trust.Certificate != link.Certificate || trust.IdentityKey != link.Key {
		r.Statement = Check{"invalid", "binding_mismatch"}
		return r
	}
	claimed, err := proof.VerifyEnrollmentEvidence(statement, nil, *trust)
	if err != nil {
		status := "invalid"
		if err.Error() == "enrollment_evidence_unsupported" {
			status = "unsupported"
		}
		r.Statement = Check{status, err.Error()}
		return r
	}
	r.Statement = Check{"valid", "checked"}
	r.IssuerAuthenticatedGrade, r.Credential, r.ApprovalSince = &claimed.Grade, &claimed.Credential, &claimed.Since
	r.AsOf = &trust.ObservedAt
	if current != nil {
		r.Currentness = "unknown"
		if current.Person == link.ID && current.ObservedAt >= 0 && now >= current.ObservedAt && now-current.ObservedAt <= 60 {
			r.Currentness = "not_current"
			if current.IdentityKey == link.Key && current.Certificate == link.Certificate && current.Issuer == trust.Issuer {
				r.Currentness = "current"
			}
		}
	}
	if receipt == nil {
		r.Proof = Check{"unavailable", "absent_proof"}
		return r
	}
	_, err = proof.VerifyEnrollmentEvidence(statement, receipt, *trust)
	if err != nil {
		r.Proof = Check{"invalid", err.Error()}
		no := false
		r.ProofBindsGrade = &no
		return r
	}
	r.Proof = Check{"valid", "checked"}
	yes := true
	r.ProofBindsGrade = &yes
	return r
}

func integer(value any) (int64, bool) {
	switch v := value.(type) {
	case json.Number:
		n, e := v.Int64()
		return n, e == nil
	case int:
		return int64(v), true
	case int64:
		return v, true
	}
	return 0, false
}
func closed(value map[string]any, fields ...string) bool {
	if len(value) != len(fields) {
		return false
	}
	for _, key := range fields {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}
func objectValue(m map[string]any, key string) map[string]any {
	v, _ := m[key].(map[string]any)
	return v
}
func stringValue(m map[string]any, key string) string { v, _ := m[key].(string); return v }
func same(a, b any) bool {
	x, e := proof.Canonical(a)
	y, f := proof.Canonical(b)
	return e == nil && f == nil && bytes.Equal(x, y)
}
func commitmentString(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value[7:])
	return err == nil
}

// CheckCreationEvidence checks the initial human-creation profile. Trust and
// current are independently acquired inputs, never receipt/statement fields.
// A missing C preserves authenticated issuer facts. Neither result authorizes
// an effect or asserts an unobserved approval-continuity history.
func CheckCreationEvidence(link Link, statement, receipt map[string]any, trust, current *proof.Trust, now int64) EvidenceReport {
	r := EvidenceReport{Link: link, Presence: "absent", Statement: Check{"not_evaluated", "missing_statement"}, Proof: Check{"not_evaluated", "missing_statement"}, Currentness: "not_evaluated", Continuity: "unknown"}
	if statement == nil {
		return r
	}
	r.Presence = "present"
	r.Proof = Check{"not_evaluated", "statement_unverified"}
	fail := func(status, reason string) EvidenceReport { r.Statement = Check{status, reason}; return r }
	body := objectValue(statement, "evidence")
	version, ok := integer(body["version"])
	if !ok {
		return fail("invalid", "malformed")
	}
	if version != 1 || stringValue(body, "kind") != "human" {
		return fail("unsupported", "unsupported_version")
	}
	if _, transition := body["transition"]; transition {
		return fail("unsupported", "unsupported_profile")
	}
	subject, creation := objectValue(body, "subject"), objectValue(body, "creation")
	if !closed(statement, "evidence", "signature") || !closed(body, "version", "kind", "organisation", "subject", "issuer", "binding_commitment", "creation") || !closed(subject, "id", "certificate", "key") || !closed(creation, "credential", "grade", "receipt_commitment") {
		return fail("invalid", "malformed")
	}
	grade := stringValue(creation, "grade")
	credentialID := stringValue(creation, "credential")
	credentialBytes, credentialErr := base64.RawURLEncoding.Strict().DecodeString(credentialID)
	if (grade != "passkey_uv" && grade != "certified_hardware") || credentialErr != nil || len(credentialBytes) == 0 || base64.RawURLEncoding.EncodeToString(credentialBytes) != credentialID || !commitmentString(stringValue(body, "binding_commitment")) || !commitmentString(stringValue(creation, "receipt_commitment")) || !commitmentString(stringValue(subject, "certificate")) {
		return fail("invalid", "malformed")
	}
	if trust == nil {
		return fail("unavailable", "trust_input_unavailable")
	}
	if trust.Person != link.ID || trust.Certificate != link.Certificate || trust.IdentityKey != link.Key || stringValue(subject, "id") != link.ID || stringValue(subject, "certificate") != link.Certificate || stringValue(subject, "key") != link.Key || stringValue(body, "issuer") != trust.Issuer || stringValue(body, "organisation") != trust.Organisation {
		return fail("invalid", "binding_mismatch")
	}
	issuer, e := awid.ExtractPublicKey(trust.Issuer)
	if e != nil || !bytes.Equal(issuer, trust.IssuerPublicKey) {
		return fail("unavailable", "trust_input_unavailable")
	}
	canonical, e := proof.Canonical(body)
	if e != nil {
		return fail("invalid", "malformed")
	}
	sig, e := base64.RawURLEncoding.Strict().DecodeString(stringValue(statement, "signature"))
	if e != nil || base64.RawURLEncoding.EncodeToString(sig) != stringValue(statement, "signature") {
		return fail("invalid", "signature_invalid")
	}
	// The existing generic signature verifier authenticates the exact shared
	// domain-prefixed canonical bytes; the approval SDK owns receipt verification.
	verified, e := awid.VerifySignedPayload("aweb.human-id-evidence/1\n"+string(canonical), base64.RawStdEncoding.EncodeToString(sig), trust.Issuer, trust.Issuer)
	if e != nil || verified != awid.Verified {
		return fail("invalid", "signature_invalid")
	}
	subjectKey, err := awid.ExtractPublicKey(link.Key)
	if err != nil || awid.ComputeStableID(subjectKey) != link.ID {
		return fail("invalid", "creation_key_inconsistent")
	}
	r.Statement = Check{"valid", "checked"}
	r.IssuerAuthenticatedGrade = &grade
	credential := stringValue(creation, "credential")
	r.Credential = &credential
	observedAt := trust.ObservedAt
	r.AsOf = &observedAt
	if current != nil {
		r.Currentness = "unknown"
		if current.Person == link.ID && current.ObservedAt >= 0 && now >= current.ObservedAt && now-current.ObservedAt <= 60 {
			r.Currentness = "not_current"
			if current.IdentityKey == link.Key && current.Certificate == link.Certificate && current.Issuer == trust.Issuer {
				r.Currentness = "current"
			}
		}
	}
	if receipt == nil {
		r.Proof = Check{"unavailable", "absent_proof"}
		return r
	}
	if version, ok := integer(receipt["version"]); ok && version != 1 {
		r.Proof = Check{"unsupported", "unsupported_version"}
		return r
	}
	r.Proof = Check{"invalid", "malformed"}
	no := false
	r.ProofBindsGrade = &no
	requestBytes, e := base64.RawURLEncoding.Strict().DecodeString(stringValue(receipt, "request_bytes"))
	if e != nil {
		return r
	}
	request, e := proof.Parse(requestBytes)
	if e != nil {
		return r
	}
	checked, e := proof.VerifyHistorical(receipt, request, *trust)
	if e != nil {
		reason := e.Error()
		switch reason {
		case "issuer_signature_invalid", "assertion_invalid":
			reason = "signature_invalid"
		case "binding_mismatch", "person_mismatch", "credential_not_enrolled":
			reason = "binding_mismatch"
		default:
			reason = "malformed"
		}
		r.Proof = Check{"invalid", reason}
		return r
	}
	if e = proof.CheckDefinition(request); e != nil {
		return r
	}
	target := objectValue(objectValue(request, "act"), "target")
	bh, e := proof.Commitment("binding_commitment", receipt["binding"])
	if e != nil {
		return r
	}
	ch, e := proof.Commitment("receipt_commitment", receipt)
	if e != nil {
		return r
	}
	expected := map[string]any{"person": link.ID, "certificate": link.Certificate, "identity_key": link.Key, "binding_commitment": bh}
	if stringValue(request, "purpose") != "enrollment_confirmation" || !same(target, expected) || bh != stringValue(body, "binding_commitment") || ch != stringValue(creation, "receipt_commitment") || checked.Credential != credential || checked.Grade != grade {
		r.Proof = Check{"invalid", "binding_mismatch"}
		return r
	}
	r.Proof = Check{"valid", "checked"}
	if r.Currentness == "current" {
		r.Continuity = "unbroken"
	}
	yes := true
	r.ProofBindsGrade = &yes
	binding := objectValue(objectValue(receipt, "binding"), "binding")
	credentials, _ := binding["credentials"].([]any)
	for _, entry := range credentials {
		c, _ := entry.(map[string]any)
		if stringValue(c, "id") == checked.Credential {
			if s, ok := c["snapshot"].(string); ok {
				r.SnapshotRef = &s
			}
		}
	}
	return r
}
func FormatEvidence(r EvidenceReport) string {
	quoted := strconv.QuoteToASCII(r.Link.ID)
	line := quoted[1:len(quoted)-1] + ": "
	switch r.Statement.Status {
	case "not_evaluated":
		return line + "no evidence"
	case "unsupported":
		if r.Statement.Reason == "unsupported_profile" {
			return line + "evidence profile unsupported"
		}
		return line + "evidence version unsupported"
	case "invalid":
		return line + "evidence invalid: " + r.Statement.Reason
	case "unavailable":
		return line + "evidence unavailable: " + r.Statement.Reason
	}
	if r.IssuerAuthenticatedGrade == nil {
		return line + "issuer statement checked; grade unavailable; proof " + r.Proof.Status
	}
	if r.Profile == "human_enrolled_later" && r.ApprovalSince != nil {
		line += fmt.Sprintf("can approve since %s (issuer's statement), grade %s (issuer's statement)", time.Unix(*r.ApprovalSince, 0).UTC().Format(time.RFC3339), *r.IssuerAuthenticatedGrade)
		if r.Proof.Status == "valid" {
			line += "; confirmation proof checked"
		} else if r.Proof.Reason == "absent_proof" {
			line += "; proof not presented"
		} else {
			line += "; proof " + r.Proof.Status + ": " + r.Proof.Reason
		}
		if r.Currentness != "current" {
			line += "; currentness " + strings.ReplaceAll(r.Currentness, "_", " ")
		}
		return line
	}
	grade := "a passkey and user verification"
	if *r.IssuerAuthenticatedGrade == "certified_hardware" {
		grade = "certified hardware"
	}
	if r.Proof.Status == "valid" && r.ProofBindsGrade != nil && *r.ProofBindsGrade {
		if *r.IssuerAuthenticatedGrade == "certified_hardware" {
			line += "issuer attests certified hardware; creation proof checked"
		} else {
			line += "created with " + grade + "; proof checked"
		}
	} else {
		line += "issuer states " + grade + "; "
		switch r.Proof.Reason {
		case "absent_proof":
			line += "proof not presented"
		case "statement_unverified":
			line += "proof not checked"
		default:
			line += "proof " + r.Proof.Status + ": " + r.Proof.Reason
		}
	}
	if r.Currentness != "current" {
		switch r.Currentness {
		case "not_current":
			line += "; not current"
		case "not_evaluated":
			line += "; currentness not checked"
		default:
			line += "; " + strings.ReplaceAll("currentness "+r.Currentness, "_", " ")
		}
	}
	if r.Continuity != "unbroken" {
		line += fmt.Sprintf("; continuity %s", r.Continuity)
	}
	return line
}
