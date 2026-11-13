package awid

import (
	"encoding/json"
	"os"
	"testing"
)

const ownerActDeliveryVectorPath = "../../../docs/vectors/owner-act-delivery-v1.json"

func TestHumanCredentialHashAndFingerprintMatchTheVectors(t *testing.T) {
	data, err := os.ReadFile(ownerActDeliveryVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		CredentialCases []struct {
			Name             string          `json:"name"`
			Credential       HumanCredential `json:"credential"`
			CredentialSHA256 string          `json:"credential_sha256"`
			Fingerprint      string          `json:"fingerprint"`
		} `json:"credential_cases"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.CredentialCases) == 0 {
		t.Fatal("no credential_cases")
	}
	for _, tc := range vectors.CredentialCases {
		t.Run(tc.Name, func(t *testing.T) {
			digest, err := tc.Credential.SHA256()
			if err != nil {
				t.Fatal(err)
			}
			if digest != tc.CredentialSHA256 {
				t.Fatalf("sha256 %s want %s", digest, tc.CredentialSHA256)
			}
			if got := CredentialFingerprint(digest); got != tc.Fingerprint {
				t.Fatalf("fingerprint %q want %q", got, tc.Fingerprint)
			}
		})
	}
}

func TestAHumanCredentialRefusesFieldsOutsideItsEncoding(t *testing.T) {
	for name, c := range map[string]HumanCredential{
		"padded id":        {CredentialID: "AAAA=", PublicKey: "AAAA", RPID: "console.example.com"},
		"standard base64":  {CredentialID: "AA+/", PublicKey: "AAAA", RPID: "console.example.com"},
		"empty public key": {CredentialID: "AAAA", PublicKey: "", RPID: "console.example.com"},
		"empty rp_id":      {CredentialID: "AAAA", PublicKey: "AAAA", RPID: ""},
	} {
		if _, err := c.SHA256(); err == nil {
			t.Errorf("%s: hashed", name)
		}
	}
}
