package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"testing"

	awid "github.com/awebai/aw/awid"
)

type attestationRecordsVector struct {
	Keys map[string]struct {
		SeedHex string `json:"seed_hex"`
		DIDKey  string `json:"did_key"`
	} `json:"keys"`
	Records []struct {
		Name            string         `json:"name"`
		Record          map[string]any `json:"record"`
		SigningBytesB64 string         `json:"signing_bytes_b64url"`
		Signature       string         `json:"signature"`
	} `json:"records"`
	RecordNegativeCases []struct {
		Name          string         `json:"name"`
		Record        map[string]any `json:"record"`
		Signature     string         `json:"signature"`
		TeamDIDKey    string         `json:"team_did_key"`
		ExpectedError string         `json:"expected_error"`
	} `json:"record_negative_cases"`
}

func loadAttestationRecordsVector(t *testing.T) attestationRecordsVector {
	t.Helper()
	var vector attestationRecordsVector
	decoder := json.NewDecoder(bytes.NewReader(readRootVector(t, "principal-attestation-v1.json")))
	decoder.UseNumber()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func TestAttestationRecordVectorSignerIsByteIdentical(t *testing.T) {
	vector := loadAttestationRecordsVector(t)
	teamKey := seedKey(t, vector.Keys["team"].SeedHex)
	if got := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)); got != vector.Keys["team"].DIDKey {
		t.Fatalf("team did:key = %s, want %s", got, vector.Keys["team"].DIDKey)
	}
	for _, tc := range vector.Records {
		t.Run(tc.Name, func(t *testing.T) {
			signingBytes, err := awid.AttestationRecordSigningBytes(tc.Record)
			if err != nil {
				t.Fatal(err)
			}
			if got := base64.RawURLEncoding.EncodeToString(signingBytes); got != tc.SigningBytesB64 {
				t.Fatalf("signing bytes = %s, want %s", got, tc.SigningBytesB64)
			}
			signature, err := awid.SignAttestationRecord(teamKey, tc.Record)
			if err != nil {
				t.Fatal(err)
			}
			if signature != tc.Signature {
				t.Fatalf("signature = %s, want %s", signature, tc.Signature)
			}
			if err := awid.VerifyAttestationRecord(tc.Record, tc.Signature, vector.Keys["team"].DIDKey); err != nil {
				t.Fatalf("verify: %v", err)
			}
		})
	}
}

func TestAttestationRecordVectorRefusals(t *testing.T) {
	vector := loadAttestationRecordsVector(t)
	if len(vector.RecordNegativeCases) == 0 {
		t.Fatal("vector has no record refusals")
	}
	for _, tc := range vector.RecordNegativeCases {
		t.Run(tc.Name, func(t *testing.T) {
			err := awid.VerifyAttestationRecord(tc.Record, tc.Signature, tc.TeamDIDKey)
			if got := awid.AttestationRecordErrorCode(err); got != tc.ExpectedError {
				t.Fatalf("err = %v (code %q), want %s", err, got, tc.ExpectedError)
			}
		})
	}
}

func TestAttestationRecordVerifyRefusesAnotherTeamKey(t *testing.T) {
	vector := loadAttestationRecordsVector(t)
	record := vector.Records[0]
	err := awid.VerifyAttestationRecord(record.Record, record.Signature, vector.Keys["new_team"].DIDKey)
	if awid.AttestationRecordErrorCode(err) != "record_invalid" {
		t.Fatalf("err = %v, want record_invalid", err)
	}
}
