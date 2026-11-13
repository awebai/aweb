package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func testHolderExport() holderCredentialExport {
	return holderCredentialExport{
		V: 1, Type: holderExportType, AppID: "secrets", OwnerActsOrigin: "https://console.secrets.example.com",
		InstallationID: "2c5f39cb-3fb2-4e4c-b4f6-f02ac6b8744c", TeamID: "demo:example.com", Role: "secrets.owner",
		Principal: "did:aw:2Zf4Lq8m3VYb9nKc5RjTs7Hd",
		Credential: awid.HumanCredential{
			CredentialID: "4JfIjlyIKLJDVdeJfuog5cGToI0WmfjaCWe5vL-gMWE",
			PublicKey:    "pQECAyYgASFYIDdAr0MPhR2zWr8mK9uGw6vPhjJxlYYxSmvw55sMv-UzIlggxBAB4c3MR1h7N2F3EFw2_NVwwZ5Ul4Tm02OFXvSzzxs",
			RPID:         "console.secrets.example.com",
		},
		Certificate: "eyJ0ZWFtX2lkIjoiZGVtbzpleGFtcGxlLmNvbSJ9",
		IDChain:     map[string]any{"v": float64(1), "type": "aweb.id-chain", "certificates": []any{}},
	}
}

func writeTestHolderExport(t *testing.T, value any) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "export.json")
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAHolderExportRoundTrips(t *testing.T) {
	want := testHolderExport()
	got, err := readHolderExport(writeTestHolderExport(t, want))
	if err != nil {
		t.Fatal(err)
	}
	if got.Credential != want.Credential || got.Principal != want.Principal || got.Certificate != want.Certificate {
		t.Fatalf("export %+v", got)
	}
}

func TestAHolderExportRefusesAnythingElse(t *testing.T) {
	var doc map[string]any
	data, _ := json.Marshal(testHolderExport())
	_ = json.Unmarshal(data, &doc)
	for name, edit := range map[string]func(map[string]any){
		"another type":    func(d map[string]any) { d["type"] = "aweb.something" },
		"another version": func(d map[string]any) { d["v"] = 2 },
		"an extra field":  func(d map[string]any) { d["fingerprint"] = "x" },
		"no certificate":  func(d map[string]any) { delete(d, "certificate") },
		"no credential":   func(d map[string]any) { delete(d, "credential") },
	} {
		copied := map[string]any{}
		for k, v := range doc {
			copied[k] = v
		}
		edit(copied)
		if _, err := readHolderExport(writeTestHolderExport(t, copied)); errorCodeOf(err) != "holder_export_invalid" {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

func TestAHolderExportBindsOnlyItsOwnHolding(t *testing.T) {
	e := testHolderExport()
	expected := holderBinding{
		AppID: e.AppID, OwnerActsOrigin: e.OwnerActsOrigin, InstallationID: e.InstallationID,
		TeamID: e.TeamID, Role: e.Role, Principal: e.Principal,
	}
	if err := e.bindsTo(expected); err != nil {
		t.Fatal(err)
	}
	for name, edit := range map[string]func(*holderBinding){
		"another app":          func(b *holderBinding) { b.AppID = "logs" },
		"another origin":       func(b *holderBinding) { b.OwnerActsOrigin = "https://console.logs.example.com" },
		"another installation": func(b *holderBinding) { b.InstallationID = "1b4e28ba-2fa1-4d3b-a3f5-ef19b5a7633b" },
		"another team":         func(b *holderBinding) { b.TeamID = "other:example.com" },
		"another role":         func(b *holderBinding) { b.Role = "secrets.auditor" },
		"another principal":    func(b *holderBinding) { b.Principal = "did:aw:3Zf4Lq8m3VYb9nKc5RjTs7Hd" },
	} {
		b := expected
		edit(&b)
		if err := e.bindsTo(b); errorCodeOf(err) != "holder_export_mismatch" {
			t.Errorf("%s: err %v", name, err)
		}
	}
}

// signedHolderChain is a real one-certificate human ID chain, with the
// integer version every issuer writes, and the subject it names.
func signedHolderChain(t *testing.T) (map[string]any, awid.IDChainSubject) {
	t.Helper()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	certificate := map[string]any{
		"v": 1, "type": "aweb.id-certificate", "id": awid.ComputeStableID(pub), "domain": "example.com",
		"parent": map[string]any{"kind": "namespace", "id": "example.com"}, "kind": "human",
		"issuer_key": awid.ComputeDIDKey(pub), "issued_at": "2026-11-13T00:00:00Z",
	}
	payload, err := awid.IDCertificateSigningBytes(certificate)
	if err != nil {
		t.Fatal(err)
	}
	_, signature, _ := awid.KeySigner(key)(payload)
	chain := map[string]any{"v": 1, "type": "aweb.id-chain", "certificates": []any{
		map[string]any{"certificate": certificate, "signature": base64.RawURLEncoding.EncodeToString(signature)},
	}}
	return chain, awid.IDChainSubject{ID: certificate["id"].(string), DIDKey: awid.ComputeDIDKey(pub)}
}

// readBackChainReason writes the export as JSON, edited by edit, reads it
// with readHolderExport and returns VerifyIDChain's refusal reason for the
// chain it read. No status evidence is supplied, so a chain whose shape and
// signatures hold stops at the evidence step.
func readBackChainReason(t *testing.T, edit func(doc map[string]any)) string {
	t.Helper()
	chain, subject := signedHolderChain(t)
	e := testHolderExport()
	e.IDChain = chain
	data, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	edit(doc)
	got, err := readHolderExport(writeTestHolderExport(t, doc))
	if err != nil {
		t.Fatal(err)
	}
	return awid.VerifyIDChain(got.IDChain, subject, nil, "example.com").Reason
}

func TestAHolderExportKeepsItsIDChainVerifiable(t *testing.T) {
	if reason := readBackChainReason(t, func(map[string]any) {}); reason != "evidence_unavailable" {
		t.Fatalf("a signed chain read back from its export is refused before evidence: %s", reason)
	}
}

func TestAHolderExportStillRefusesAMalformedOrTamperedChain(t *testing.T) {
	first := func(doc map[string]any) map[string]any {
		return doc["id_chain"].(map[string]any)["certificates"].([]any)[0].(map[string]any)
	}
	for name, tc := range map[string]struct {
		edit   func(map[string]any)
		reason string
	}{
		"a fractional chain version": {func(doc map[string]any) {
			doc["id_chain"].(map[string]any)["v"] = json.Number("1.5")
		}, "invalid_shape"},
		"a fractional certificate version": {func(doc map[string]any) {
			first(doc)["certificate"].(map[string]any)["v"] = json.Number("1.0")
		}, "invalid_shape"},
		"a certificate changed after signing": {func(doc map[string]any) {
			first(doc)["certificate"].(map[string]any)["kind"] = "agent"
		}, "invalid_signature"},
	} {
		if reason := readBackChainReason(t, tc.edit); reason != tc.reason {
			t.Errorf("%s: reason %q, want %q", name, reason, tc.reason)
		}
	}
}
