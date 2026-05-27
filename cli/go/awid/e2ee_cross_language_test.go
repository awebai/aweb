package awid

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type e2eeCrossLanguageFixture struct {
	Identities         map[string]e2eeCrossLanguageIdentity `json:"identities"`
	PythonMailEnvelope E2EEMessageEnvelope                  `json:"python_mail_envelope"`
}

type e2eeCrossLanguageIdentity struct {
	Address       string                  `json:"address"`
	DID           string                  `json:"did"`
	StableID      string                  `json:"stable_id"`
	TeamID        string                  `json:"team_id"`
	X25519Private string                  `json:"x25519_private"`
	EncryptionKey *EncryptionKeyAssertion `json:"encryption_key"`
}

func TestGoDecryptsPythonEncryptedV2Fixture(t *testing.T) {
	t.Parallel()

	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "e2ee-v2-cross-language.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture e2eeCrossLanguageFixture
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	bob := fixture.Identities["bob"]
	rawPrivate, err := base64.RawStdEncoding.DecodeString(bob.X25519Private)
	if err != nil {
		t.Fatal(err)
	}
	privateKey, err := ecdh.X25519().NewPrivateKey(rawPrivate)
	if err != nil {
		t.Fatal(err)
	}

	plain, err := DecryptE2EEMessage(&fixture.PythonMailEnvelope, E2EEDecryptIdentity{
		Address:         bob.Address,
		DID:             bob.DID,
		StableID:        bob.StableID,
		EncryptionKeyID: bob.EncryptionKey.EncryptionKeyID,
		PrivateKey:      privateKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	if plain.Subject != "python fixture subject" || plain.Body != "python fixture body" {
		t.Fatalf("plain subject/body=%q/%q", plain.Subject, plain.Body)
	}
	if strings.Contains(string(data), "python fixture body") {
		t.Fatal("fixture envelope leaked plaintext body")
	}
	if bob.EncryptionKey.Custody != EncryptionKeyCustodySelf {
		t.Fatalf("custody=%q want self", bob.EncryptionKey.Custody)
	}
}
