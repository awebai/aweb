package awid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type teamControlVectors struct {
	SeedHex     string `json:"seed_hex"`
	Signer      string `json:"signer_did_key"`
	ImportCases []struct {
		Signature string `json:"signature"`
	} `json:"import_cases"`
	ClaimCases []struct {
		Name     string                  `json:"name"`
		Input    UnownedTeamClaimRequest `json:"input"`
		Payload  string                  `json:"canonical_payload"`
		Artifact json.RawMessage         `json:"artifact"`
	} `json:"claim_cases"`
}

func loadTeamControlVectors(t *testing.T) teamControlVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "team-control-requests-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors teamControlVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.ImportCases) != 4 || len(vectors.ClaimCases) != 2 {
		t.Fatal("missing shared cases")
	}
	return vectors
}

func TestTeamControlClaimArtifactVectors(t *testing.T) {
	vectors := loadTeamControlVectors(t)
	seed, err := hex.DecodeString(vectors.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors.ClaimCases {
		t.Run(tc.Name, func(t *testing.T) {
			payload, err := tc.Input.SigningBytes()
			if err != nil {
				t.Fatal(err)
			}
			if string(payload) != tc.Payload {
				t.Fatalf("payload = %q", payload)
			}
			artifact, err := tc.Input.Sign(ed25519.NewKeyFromSeed(seed))
			if err != nil {
				t.Fatal(err)
			}
			expected, err := ParseUnownedTeamClaim(tc.Artifact)
			if err != nil {
				t.Fatal(err)
			}
			if artifact != expected {
				t.Fatal("signed artifact differs from shared vector")
			}
			raw, err := json.Marshal(artifact)
			if err != nil {
				t.Fatal(err)
			}
			parsed, err := ParseUnownedTeamClaim(raw)
			if err != nil || parsed != artifact {
				t.Fatalf("roundtrip: %v", err)
			}
			if err := parsed.VerifyIntegrity(); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"team", "email", "username", "timestamp"} {
				changed := artifact
				switch field {
				case "team":
					changed.Request.AWIDTeamID = "other:acme.com"
				case "email":
					changed.Request.Email = "other@example.com"
				case "username":
					changed.Request.Username = "other-owner"
				case "timestamp":
					changed.Request.Timestamp = "2026-05-09T12:00:01Z"
				}
				if err := changed.VerifyIntegrity(); err == nil || !strings.HasSuffix(err.Error(), "regenerate it with the controller key and retry") {
					t.Fatalf("accepted changed %s: %v", field, err)
				}
			}
			proof := teamClaimSignature{signerDIDKey: vectors.Signer, signature: vectors.ImportCases[0].Signature}
			if err := artifact.Request.verifySignature(proof); err == nil {
				t.Fatal("accepted an import signature as a claim")
			}
			spaced := append([]byte(" \n"), raw...)
			spaced = append(spaced, '\n')
			if _, err := ParseUnownedTeamClaim(spaced); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestTeamControlClaimReaderRefusesAmbiguousArtifacts(t *testing.T) {
	vectors := loadTeamControlVectors(t)
	valid := vectors.ClaimCases[0].Artifact
	invalid := [][]byte{
		[]byte(`[]`), []byte(`null`), []byte(`{} {}`), []byte(`{"request":{},"request":{}}`),
		bytes.Replace(valid, []byte(`"request":`), []byte(`"authorized_controller":true,"request":`), 1),
		bytes.Replace(valid, []byte(`"claim_unowned_team"`), []byte(`"byoidt_import"`), 1),
		bytes.Replace(valid, []byte(`"owner@example.com"`), []byte(`null`), 1),
		bytes.Replace(valid, []byte(`owner@example.com`), []byte(`\ud800`), 1),
		bytes.Replace(valid, []byte(`owner@example.com`), []byte{0xff}, 1),
		append(append([]byte{}, valid...), []byte(` {}`)...),
	}
	for index, raw := range invalid {
		if _, err := ParseUnownedTeamClaim(raw); err == nil || !strings.HasSuffix(err.Error(), "regenerate the artifact and retry") {
			t.Fatalf("case %d: %v", index, err)
		}
	}
}

func TestTeamControlRefusesInvalidSigningKey(t *testing.T) {
	request := loadTeamControlVectors(t).ClaimCases[0].Input
	if _, err := request.Sign(nil); err == nil {
		t.Fatal("accepted invalid signing key")
	}
}

func TestTeamControlClaimUnicodeEscapesPreserveSignature(t *testing.T) {
	vectors := loadTeamControlVectors(t)
	valid := vectors.ClaimCases[0].Artifact
	for _, text := range []string{`owner+\u96ea\ud83d\ude00@example.com`, `owner+\\ud800@example.com`} {
		raw := bytes.Replace(valid, []byte("owner@example.com"), []byte(text), 1)
		artifact, err := ParseUnownedTeamClaim(raw)
		if err != nil {
			t.Fatal(err)
		}
		seed, err := hex.DecodeString(vectors.SeedHex)
		if err != nil {
			t.Fatal(err)
		}
		signed, err := artifact.Request.Sign(ed25519.NewKeyFromSeed(seed))
		if err != nil {
			t.Fatal(err)
		}
		serialized, err := json.Marshal(signed)
		if err != nil {
			t.Fatal(err)
		}
		roundtrip, err := ParseUnownedTeamClaim(serialized)
		if err != nil {
			t.Fatal(err)
		}
		if err := roundtrip.VerifyIntegrity(); err != nil {
			t.Fatal(err)
		}
		if roundtrip.Request.Email != artifact.Request.Email {
			t.Fatal("lossy Unicode decoding")
		}
	}
}
