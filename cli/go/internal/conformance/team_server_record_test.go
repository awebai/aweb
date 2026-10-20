package conformance_test

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	awid "github.com/awebai/aw/awid"
)

type teamServerVector struct {
	DomainPrefix    string                 `json:"domain_prefix"`
	TeamID          string                 `json:"team_id"`
	TeamKeySeedHex  string                 `json:"team_key_seed_hex"`
	TeamDIDKey      string                 `json:"team_did_key"`
	OtherKeySeedHex string                 `json:"other_key_seed_hex"`
	OtherDIDKey     string                 `json:"other_did_key"`
	Valid           []teamServerVectorCase `json:"valid"`
	Invalid         []teamServerVectorCase `json:"invalid"`
}

type teamServerVectorCase struct {
	Name            string         `json:"name"`
	Record          map[string]any `json:"record"`
	SigningBytesB64 string         `json:"signing_bytes_b64"`
	Signature       string         `json:"signature"`
	Code            string         `json:"code"`
	RequiresStored  string         `json:"requires_stored"`
}

func loadTeamServerVector(t *testing.T) teamServerVector {
	t.Helper()
	var vector teamServerVector
	decoder := json.NewDecoder(bytes.NewReader(readRootVector(t, "team-server-record-v1.json")))
	decoder.UseNumber()
	if err := decoder.Decode(&vector); err != nil {
		t.Fatal(err)
	}
	return vector
}

func seedKey(t *testing.T, seedHex string) ed25519.PrivateKey {
	t.Helper()
	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatal(err)
	}
	return ed25519.NewKeyFromSeed(seed)
}

var teamServerVectorNow = time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

func TestTeamServerRecordVectorSignerIsByteIdentical(t *testing.T) {
	vector := loadTeamServerVector(t)
	teamKey := seedKey(t, vector.TeamKeySeedHex)
	if got := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey)); got != vector.TeamDIDKey {
		t.Fatalf("team did:key = %s, want %s", got, vector.TeamDIDKey)
	}
	if vector.DomainPrefix != awid.TeamServerSigningPrefix {
		t.Fatalf("domain prefix = %q, want %q", awid.TeamServerSigningPrefix, vector.DomainPrefix)
	}
	for _, tc := range vector.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			issuedAt, err := time.Parse(time.RFC3339, tc.Record["issued_at"].(string))
			if err != nil {
				t.Fatal(err)
			}
			record := awid.NewTeamServerRecord(tc.Record["team_id"].(string), tc.Record["team_did_key"].(string), tc.Record["server_url"].(string), issuedAt)
			signingBytes, err := awid.TeamServerRecordSigningBytes(record)
			if err != nil {
				t.Fatal(err)
			}
			if got := base64.StdEncoding.EncodeToString(signingBytes); got != tc.SigningBytesB64 {
				t.Fatalf("signing bytes = %s, want %s", got, tc.SigningBytesB64)
			}
			signature, err := awid.SignTeamServerRecord(teamKey, record)
			if err != nil {
				t.Fatal(err)
			}
			if signature != tc.Signature {
				t.Fatalf("signature = %s, want %s", signature, tc.Signature)
			}
			verified, err := awid.VerifyTeamServerRecord(tc.Record, tc.Signature, vector.TeamID, vector.TeamDIDKey, teamServerVectorNow)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if verified.ServerURL != tc.Record["server_url"] {
				t.Fatalf("server_url = %s", verified.ServerURL)
			}
		})
	}
}

func TestTeamServerRecordVectorRefusalsMatchCodes(t *testing.T) {
	vector := loadTeamServerVector(t)
	for _, tc := range vector.Invalid {
		if tc.RequiresStored != "" {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			_, err := awid.VerifyTeamServerRecord(tc.Record, tc.Signature, vector.TeamID, vector.TeamDIDKey, teamServerVectorNow)
			if err == nil {
				t.Fatal("record verified, want refusal")
			}
			if got := awid.TeamServerRecordErrorCode(err); got != tc.Code {
				t.Fatalf("code = %q (%v), want %q", got, err, tc.Code)
			}
		})
	}
}
