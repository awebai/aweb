package awid

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"testing"
)

func TestIdentityGrantAuthVector(t *testing.T) {
	path := filepath.Join("..", "..", "..", "test-vectors", "identity-grant-auth-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		SeedHex              string `json:"seed_hex"`
		Method               string `json:"method"`
		URL                  string `json:"url"`
		GrantID              string `json:"grant_id"`
		Body                 string `json:"body"`
		Timestamp            string `json:"timestamp"`
		DIDKey               string `json:"did_key"`
		BodySHA256           string `json:"body_sha256"`
		CanonicalPayload     string `json:"canonical_payload"`
		Authorization        string `json:"authorization"`
		XAwebGrantID         string `json:"x_aweb_grant_id"`
		XAwebTimestamp       string `json:"x_aweb_timestamp"`
		XAwebSignedPayload   string `json:"x_aweb_signed_payload"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vector.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	target, err := url.Parse(vector.URL)
	if err != nil {
		t.Fatal(err)
	}
	credential, err := SignIdentityGrantCredential(ed25519.NewKeyFromSeed(seed), vector.Method, target, vector.GrantID, []byte(vector.Body), vector.Timestamp)
	if err != nil {
		t.Fatal(err)
	}
	checks := map[string][2]string{
		"did_key": {credential.DIDKey, vector.DIDKey},
		"body_sha256": {credential.BodySHA256, vector.BodySHA256},
		"canonical_payload": {credential.CanonicalPayload, vector.CanonicalPayload},
		"authorization": {credential.Headers.Get("Authorization"), vector.Authorization},
		"x_aweb_grant_id": {credential.Headers.Get("X-AWEB-Grant-ID"), vector.XAwebGrantID},
		"x_aweb_timestamp": {credential.Headers.Get("X-AWEB-Timestamp"), vector.XAwebTimestamp},
		"x_aweb_signed_payload": {credential.Headers.Get("X-AWEB-Signed-Payload"), vector.XAwebSignedPayload},
	}
	for name, pair := range checks {
		if pair[0] != pair[1] {
			t.Fatalf("%s mismatch\ngot  %q\nwant %q", name, pair[0], pair[1])
		}
	}
}
