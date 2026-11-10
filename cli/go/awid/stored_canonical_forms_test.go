package awid

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The custody request digest and proof are computed by the worker and
// recomputed by the resident custody service, two aw processes that can be
// different builds. These digests were computed at commit 8e8d008c8.
func TestCustodyDigestsOfTextWithLineSeparatorsAreStable(t *testing.T) {
	lineSeparator, paragraphSeparator := string(rune(0x2028)), string(rune(0x2029))
	request := &PlainMessageSignRequest{
		Version: 1, Operation: "sign_plain_message", GrantID: "g", SessionDIDKey: "s", TeamID: "t", SubjectDIDKey: "k", Audience: "a",
		Envelope: MessageEnvelope{Subject: "line" + lineSeparator + "separator", Body: "paragraph" + paragraphSeparator + "separator <&>"},
	}
	digest, err := custodyRequestDigest(request)
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:a58a1bfd93744df7af45c68002caf51deff31375845d03266ab045dd3c67bbd5"; digest != want {
		t.Fatalf("plain message request digest = %s, want %s", digest, want)
	}
	digest, err = custodyDigestValue("op", map[string]any{"body": "a" + lineSeparator + "b" + paragraphSeparator + "c"})
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:dcd6322cdc6e8bbfce58121c42efd3f6a5aaad90fbac25b6e5ed5d6d0f65bbd5"; digest != want {
		t.Fatalf("custody digest value = %s, want %s", digest, want)
	}
}

// A certificate whose name holds both separators, signed at commit 8e8d008c8
// with the all-zero seed, verifies over the bytes idCertificateCanonical
// produces.
func TestIDCertificateSignatureOverLineSeparatorsVerifies(t *testing.T) {
	const signature = "0+X1fMk9bOlpaXLiUsJhqo6Rs5LBICn5/ghjaq2aV1jRKw4rOf56hw+Jg/ntCOUGu9jqXQQACZJlkl3SyThlCg"
	certificate := map[string]any{"name": "a" + string(rune(0x2028)) + "b" + string(rune(0x2029)) + "c"}
	signingBytes, err := idCertificateCanonical(certificate)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)).Public().(ed25519.PublicKey)
	if !ed25519.Verify(public, signingBytes, raw) {
		t.Fatalf("signature does not verify over %q", signingBytes)
	}
}

// An encrypted mail produced at commit 8e8d008c8, whose inner payload writes
// U+2028 and U+2029 as six-character escapes, decrypts to the same text: the
// recipient parses the decrypted bytes and recomputes only the header hash.
func TestE2EEEnvelopeWithEscapedLineSeparatorsDecrypts(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("testdata", "e2ee_envelope_escaped_line_separators.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Envelope  E2EEMessageEnvelope `json:"envelope"`
		Recipient struct {
			Address         string `json:"address"`
			DID             string `json:"did"`
			StableID        string `json:"stable_id"`
			EncryptionKeyID string `json:"encryption_key_id"`
			PrivateKey      string `json:"x25519_private_key_b64"`
		} `json:"recipient"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	rawPrivate, err := base64.RawStdEncoding.DecodeString(fixture.Recipient.PrivateKey)
	if err != nil {
		t.Fatal(err)
	}
	private, err := ecdh.X25519().NewPrivateKey(rawPrivate)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptE2EEMessage(&fixture.Envelope, E2EEDecryptIdentity{
		Address: fixture.Recipient.Address, DID: fixture.Recipient.DID, StableID: fixture.Recipient.StableID,
		EncryptionKeyID: fixture.Recipient.EncryptionKeyID, PrivateKey: private,
	})
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	lineSeparator, paragraphSeparator := string(rune(0x2028)), string(rune(0x2029))
	if want := "line" + lineSeparator + "separator"; inner.Subject != want {
		t.Fatalf("subject = %q, want %q", inner.Subject, want)
	}
	if want := "paragraph" + paragraphSeparator + "separator <&>"; inner.Body != want {
		t.Fatalf("body = %q, want %q", inner.Body, want)
	}

	// The fixture's plaintext is the escaped form: each separator takes six
	// bytes there and three as UTF-8, and AES-GCM adds a 16-byte tag.
	utf8Form, err := StrictCanonicalJSON(e2eeInnerPayloadMap(*inner, true))
	if err != nil {
		t.Fatal(err)
	}
	separators := strings.Count(string(utf8Form), lineSeparator) + strings.Count(string(utf8Form), paragraphSeparator)
	if separators != 2 {
		t.Fatalf("inner payload holds %d separators, want 2", separators)
	}
	if want := len(utf8Form) + 3*separators + 16; fixture.Envelope.Crypto.CiphertextSize != want {
		t.Fatalf("ciphertext size = %d, want %d for the escaped form", fixture.Envelope.Crypto.CiphertextSize, want)
	}
}
