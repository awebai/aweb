package awid

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func TestCredentialLifetimesCrossLanguageVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/certificate-lifetimes-v2.json")
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Now          string `json:"now"`
		TeamDIDKey   string `json:"team_did_key"`
		Certificates []struct {
			Name        string          `json:"name"`
			Expected    string          `json:"expected"`
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
	now, err := time.Parse(time.RFC3339, vector.Now)
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range vector.Certificates {
		t.Run(item.Name, func(t *testing.T) {
			var cert TeamCertificate
			err := json.Unmarshal(item.Certificate, &cert)
			if err == nil {
				actual := canonicalCertificatePayload(cert.CertificateID, cert.Team, cert.TeamDIDKey, cert.MemberDIDKey, cert.MemberDIDAW, cert.MemberAddress, cert.Alias, cert.IdentityScope, cert.IssuedAt, false)
				if cert.Version == 2 {
					actual, err = certificateV2Payload(&cert)
				}
				if err != nil {
					t.Fatal(err)
				}
				if actual != item.Canonical && item.Expected != "certificate_malformed" {
					t.Fatalf("canonical bytes mismatch: %s", actual)
				}
				err = verifyTeamCertificateAt(&cert, key, now)
			}
			if item.Expected == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if item.Expected == "signature_invalid" {
				if err == nil || !strings.Contains(err.Error(), "signature") {
					t.Fatalf("wanted signature refusal, got %v", err)
				}
			} else if err == nil || !strings.Contains(err.Error(), item.Expected) {
				t.Fatalf("wanted %s, got %v", item.Expected, err)
			}
		})
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
