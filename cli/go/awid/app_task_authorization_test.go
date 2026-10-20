package awid

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

type appTaskAuthorizationVectors struct {
	Keys struct {
		Member struct {
			SeedHex string `json:"seed_hex"`
			DIDKey  string `json:"did_key"`
		} `json:"member"`
	} `json:"keys"`
	Valid []struct {
		Name           string         `json:"name"`
		Task           map[string]any `json:"task"`
		TaskBodySHA256 string         `json:"task_body_sha256"`
		Payload        map[string]any `json:"payload"`
		SigningBytes   string         `json:"signing_bytes"`
		Signature      string         `json:"signature"`
	} `json:"valid"`
}

func loadAppTaskAuthorizationVectors(t *testing.T) appTaskAuthorizationVectors {
	t.Helper()
	raw, err := os.ReadFile("../../../docs/vectors/app-task-authorization-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var vectors appTaskAuthorizationVectors
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Valid) == 0 {
		t.Fatal("no valid task authorization vectors")
	}
	return vectors
}

func TestAppTaskAuthorizationVectors(t *testing.T) {
	vectors := loadAppTaskAuthorizationVectors(t)
	seed, err := hex.DecodeString(vectors.Keys.Member.SeedHex)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	if got := ComputeDIDKey(key.Public().(ed25519.PublicKey)); got != vectors.Keys.Member.DIDKey {
		t.Fatalf("member did:key = %s, want %s", got, vectors.Keys.Member.DIDKey)
	}
	for _, tc := range vectors.Valid {
		t.Run(tc.Name, func(t *testing.T) {
			digest, err := TaskBodySHA256(tc.Task)
			if err != nil {
				t.Fatal(err)
			}
			if digest != tc.TaskBodySHA256 {
				t.Fatalf("task body digest = %s, want %s", digest, tc.TaskBodySHA256)
			}
			signing, err := AppTaskAuthorizationSigningBytes(tc.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if string(signing) != tc.SigningBytes {
				t.Fatalf("signing bytes = %q, want %q", signing, tc.SigningBytes)
			}
			signature, err := SignAppTaskAuthorization(key, tc.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if signature != tc.Signature {
				t.Fatalf("signature = %s, want %s", signature, tc.Signature)
			}
		})
	}
}
