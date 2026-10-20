package awid

import (
	"encoding/json"
	"os"
	"testing"
)

func TestCredentialLifetimesCrossLanguageVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/certificate-lifetimes-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		TeamDIDKey   string `json:"team_did_key"`
		Certificates []struct {
			Canonical   string          `json:"canonical"`
			Certificate json.RawMessage `json:"certificate"`
		} `json:"certificates"`
		Policy struct {
			Record       map[string]any `json:"record"`
			Signature    string         `json:"signature"`
			SigningBytes string         `json:"signing_bytes"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	key, err := ExtractPublicKey(vector.TeamDIDKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range vector.Certificates {
		var cert TeamCertificate
		if err := json.Unmarshal(item.Certificate, &cert); err != nil {
			t.Fatal(err)
		}
		if err := VerifyTeamCertificate(&cert, key); err != nil {
			t.Fatal(err)
		}
		cert.ExpiresAt = "2098-01-01T00:00:00Z"
		if VerifyTeamCertificate(&cert, key) == nil {
			t.Fatal("accepted expiry tampering")
		}
	}
	if err := VerifyTeamCredentialPolicy(vector.Policy.Record, vector.Policy.Signature, "ops:example.test", vector.TeamDIDKey); err != nil {
		t.Fatal(err)
	}
	canonical, err := CanonicalJSONValue(vector.Policy.Record)
	if err != nil {
		t.Fatal(err)
	}
	if "aweb.team-credential-policy/1\n"+canonical != vector.Policy.SigningBytes {
		t.Fatal("policy canonical mismatch")
	}
	vector.Policy.Record["identity_grant"] = float64(1)
	if VerifyTeamCredentialPolicy(vector.Policy.Record, vector.Policy.Signature, "ops:example.test", vector.TeamDIDKey) == nil {
		t.Fatal("accepted policy tampering")
	}
}
