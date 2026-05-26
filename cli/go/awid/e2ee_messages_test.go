package awid

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type e2eeTestIdentity struct {
	pub       ed25519.PublicKey
	priv      ed25519.PrivateKey
	did       string
	stableID  string
	address   string
	xPriv     *ecdh.PrivateKey
	assertion *EncryptionKeyAssertion
}

func newE2EETestIdentity(t *testing.T, address string) e2eeTestIdentity {
	t.Helper()
	pub, priv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	xPriv, rawPub, err := GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)
	stableID := ComputeStableID(pub)
	assertion, err := BuildEncryptionKeyAssertion(priv, did, stableID, rawPub, "", time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	return e2eeTestIdentity{
		pub:       pub,
		priv:      priv,
		did:       did,
		stableID:  stableID,
		address:   address,
		xPriv:     xPriv,
		assertion: assertion,
	}
}

func TestE2EEMailEncryptDecryptRecipientAndSenderCopy(t *testing.T) {
	alice := newE2EETestIdentity(t, "example.com/alice")
	bob := newE2EETestIdentity(t, "example.com/bob")

	env, err := EncryptE2EEMail(E2EEEncryptMailParams{
		Sender: E2EESenderKey{
			Address:       alice.address,
			DID:           alice.did,
			StableID:      alice.stableID,
			EncryptionKey: alice.assertion,
			SigningKey:    alice.priv,
		},
		Recipients: []E2EERecipientKey{{
			Address:       bob.address,
			DID:           bob.did,
			StableID:      bob.stableID,
			EncryptionKey: bob.assertion,
		}},
		Subject:        "secret subject",
		Body:           "secret body",
		MessageID:      "11111111-1111-4111-8111-111111111111",
		ConversationID: "22222222-2222-4222-8222-222222222222",
		CreatedAt:      time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("EncryptE2EEMail: %v", err)
	}
	if env.Ciphertext == "" || env.Signature == "" {
		t.Fatalf("missing ciphertext/signature: %#v", env)
	}
	if strings.Contains(env.Ciphertext, "secret") {
		t.Fatalf("ciphertext contains plaintext")
	}
	if len(env.KeyWraps) != 2 {
		t.Fatalf("key wraps=%d want 2", len(env.KeyWraps))
	}

	bobPlain, err := DecryptE2EEMessage(env, E2EEDecryptIdentity{
		Address:         bob.address,
		DID:             bob.did,
		StableID:        bob.stableID,
		EncryptionKeyID: bob.assertion.EncryptionKeyID,
		PrivateKey:      bob.xPriv,
	})
	if err != nil {
		t.Fatalf("bob decrypt: %v", err)
	}
	alicePlain, err := DecryptE2EEMessage(env, E2EEDecryptIdentity{
		Address:         alice.address,
		DID:             alice.did,
		StableID:        alice.stableID,
		EncryptionKeyID: alice.assertion.EncryptionKeyID,
		PrivateKey:      alice.xPriv,
	})
	if err != nil {
		t.Fatalf("alice self-copy decrypt: %v", err)
	}
	if bobPlain.Subject != "secret subject" || bobPlain.Body != "secret body" {
		t.Fatalf("bob plaintext mismatch: %#v", bobPlain)
	}
	if alicePlain.Subject != bobPlain.Subject || alicePlain.Body != bobPlain.Body {
		t.Fatalf("self-copy plaintext mismatch: alice=%#v bob=%#v", alicePlain, bobPlain)
	}
}

func TestE2EEMailDecryptRejectsNonRecipientAndTamper(t *testing.T) {
	alice := newE2EETestIdentity(t, "example.com/alice")
	bob := newE2EETestIdentity(t, "example.com/bob")
	carol := newE2EETestIdentity(t, "example.com/carol")

	env, err := EncryptE2EEMail(E2EEEncryptMailParams{
		Sender: E2EESenderKey{
			Address:       alice.address,
			DID:           alice.did,
			StableID:      alice.stableID,
			EncryptionKey: alice.assertion,
			SigningKey:    alice.priv,
		},
		Recipients: []E2EERecipientKey{{
			Address:       bob.address,
			DID:           bob.did,
			StableID:      bob.stableID,
			EncryptionKey: bob.assertion,
		}},
		Subject:        "secret subject",
		Body:           "secret body",
		MessageID:      "33333333-3333-4333-8333-333333333333",
		ConversationID: "44444444-4444-4444-8444-444444444444",
		CreatedAt:      time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("EncryptE2EEMail: %v", err)
	}
	if _, err := DecryptE2EEMessage(env, E2EEDecryptIdentity{
		Address:         carol.address,
		DID:             carol.did,
		StableID:        carol.stableID,
		EncryptionKeyID: carol.assertion.EncryptionKeyID,
		PrivateKey:      carol.xPriv,
	}); err == nil || !strings.Contains(err.Error(), "not a recipient") {
		t.Fatalf("non-recipient error=%v", err)
	}

	tampered := *env
	tampered.Ciphertext = strings.TrimSuffix(env.Ciphertext, "A") + "A"
	if tampered.Ciphertext == env.Ciphertext {
		tampered.Ciphertext = strings.TrimSuffix(env.Ciphertext, "B") + "B"
	}
	if _, err := DecryptE2EEMessage(&tampered, E2EEDecryptIdentity{
		Address:         bob.address,
		DID:             bob.did,
		StableID:        bob.stableID,
		EncryptionKeyID: bob.assertion.EncryptionKeyID,
		PrivateKey:      bob.xPriv,
	}); err == nil {
		t.Fatalf("tampered ciphertext should fail")
	}
}

func TestE2EEMailEncryptRejectsSubstitutedRecipientAssertion(t *testing.T) {
	alice := newE2EETestIdentity(t, "example.com/alice")
	bob := newE2EETestIdentity(t, "example.com/bob")
	carol := newE2EETestIdentity(t, "example.com/carol")

	_, err := EncryptE2EEMail(E2EEEncryptMailParams{
		Sender: E2EESenderKey{
			Address:       alice.address,
			DID:           alice.did,
			StableID:      alice.stableID,
			EncryptionKey: alice.assertion,
			SigningKey:    alice.priv,
		},
		Recipients: []E2EERecipientKey{{
			Address:       bob.address,
			DID:           bob.did,
			StableID:      bob.stableID,
			EncryptionKey: carol.assertion,
		}},
		Subject:        "secret subject",
		Body:           "secret body",
		MessageID:      "55555555-5555-4555-8555-555555555555",
		ConversationID: "66666666-6666-4666-8666-666666666666",
		CreatedAt:      time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	})
	if err == nil || !strings.Contains(err.Error(), "recipient encryption key assertion") {
		t.Fatalf("err=%v, want recipient assertion rejection", err)
	}
}

func TestE2EEMailDecryptRejectsInvalidOuterSignature(t *testing.T) {
	alice := newE2EETestIdentity(t, "example.com/alice")
	bob := newE2EETestIdentity(t, "example.com/bob")

	env := encryptE2EETestMessage(t, alice, bob, "77777777-7777-4777-8777-777777777777", "88888888-8888-4888-8888-888888888888")
	tampered := *env
	tampered.Routing.To = "example.com/carol"
	if _, err := DecryptE2EEMessage(&tampered, E2EEDecryptIdentity{
		Address:         bob.address,
		DID:             bob.did,
		StableID:        bob.stableID,
		EncryptionKeyID: bob.assertion.EncryptionKeyID,
		PrivateKey:      bob.xPriv,
	}); err == nil || !strings.Contains(err.Error(), "invalid e2ee envelope signature") {
		t.Fatalf("err=%v, want invalid signature", err)
	}
}

func TestE2EEMailDecryptRejectsInnerHeaderMismatch(t *testing.T) {
	alice := newE2EETestIdentity(t, "example.com/alice")
	bob := newE2EETestIdentity(t, "example.com/bob")

	env := encryptE2EETestMessage(t, alice, bob, "99999999-9999-4999-8999-999999999999", "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa")
	tampered := *env
	tampered.KeyWraps = append([]E2EEKeyWrap(nil), env.KeyWraps...)
	tampered.Recipients = append([]E2EERecipientRef(nil), env.Recipients...)

	cek, err := openE2EEKeyWrap(&tampered.KeyWraps[0], tampered.MessageID, tampered.ConversationID, tampered.From, E2EEDecryptIdentity{
		Address:         bob.address,
		DID:             bob.did,
		StableID:        bob.stableID,
		EncryptionKeyID: bob.assertion.EncryptionKeyID,
		PrivateKey:      bob.xPriv,
	})
	if err != nil {
		t.Fatalf("open wrap: %v", err)
	}
	inner := E2EEInnerPayload{
		InnerVersion:   E2EEMessageVersion,
		Kind:           "mail",
		MessageID:      "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
		ConversationID: tampered.ConversationID,
		CreatedAt:      tampered.CreatedAt,
		From:           tampered.From,
		Recipients:     []E2EEIdentityRef{{Address: bob.address, DID: bob.did, StableID: bob.stableID}},
		Subject:        "secret subject",
		Body:           "secret body",
	}
	innerHeaderHash, err := e2eeInnerHeaderHash(inner)
	if err != nil {
		t.Fatal(err)
	}
	innerBytes, err := e2eeInnerPayloadCanonical(inner)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Crypto.InnerHeaderHash = innerHeaderHash
	nonce, err := base64.RawStdEncoding.DecodeString(tampered.Crypto.ContentNonce)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := e2eeContentAAD(&tampered)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := aesGCMSeal(cek, nonce, innerBytes, aad)
	if err != nil {
		t.Fatal(err)
	}
	tampered.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
	tampered.Crypto.CiphertextHash = e2eeHashBytes(ciphertext)
	resignE2EETestEnvelope(t, &tampered, alice.priv)

	if _, err := DecryptE2EEMessage(&tampered, E2EEDecryptIdentity{
		Address:         bob.address,
		DID:             bob.did,
		StableID:        bob.stableID,
		EncryptionKeyID: bob.assertion.EncryptionKeyID,
		PrivateKey:      bob.xPriv,
	}); err == nil || !strings.Contains(err.Error(), "inner header does not match outer envelope") {
		t.Fatalf("err=%v, want inner header mismatch", err)
	}
}

func TestClientSendMessageE2EEPostsOpaqueEnvelopeOnly(t *testing.T) {
	alice := newE2EETestIdentity(t, "example.com/alice")
	bob := newE2EETestIdentity(t, "example.com/bob")

	var posted SendMessageRequest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			http.NotFound(w, r)
			return
		}
		if err := json.NewDecoder(r.Body).Decode(&posted); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		_ = json.NewEncoder(w).Encode(SendMessageResponse{
			MessageID:      posted.MessageID,
			ConversationID: posted.ConversationID,
			Status:         "delivered",
			DeliveredAt:    "2026-05-26T12:00:00Z",
		})
	}))
	t.Cleanup(server.Close)

	c, err := NewWithIdentity(server.URL, alice.priv, alice.did)
	if err != nil {
		t.Fatal(err)
	}
	c.SetStableID(alice.stableID)
	c.SetAddress(alice.address)
	c.SetE2EEKey(alice.assertion, alice.xPriv)
	c.SetResolver(stubIdentityResolver{resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
		if identifier != bob.address {
			t.Fatalf("resolve identifier=%q want %q", identifier, bob.address)
		}
		return &ResolvedIdentity{
			DID:           bob.did,
			StableID:      bob.stableID,
			Address:       bob.address,
			EncryptionKey: bob.assertion,
		}, nil
	}})

	_, err = c.SendMessageByIdentity(context.Background(), &SendMessageRequest{
		ToAddress:   bob.address,
		Subject:     "plain subject",
		Body:        "plain body",
		EncryptE2EE: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if posted.ContentMode != ContentModeEncryptedV2 || posted.MessageVersion != E2EEMessageVersion {
		t.Fatalf("posted mode/version = %q/%d", posted.ContentMode, posted.MessageVersion)
	}
	if posted.Subject != "" || posted.Body != "" {
		t.Fatalf("plaintext leaked in request: subject=%q body=%q", posted.Subject, posted.Body)
	}
	if posted.Encrypted == nil || posted.Encrypted.Ciphertext == "" {
		t.Fatalf("missing encrypted envelope: %#v", posted.Encrypted)
	}
	if strings.Contains(mustJSON(t, posted.Encrypted), "plain subject") || strings.Contains(mustJSON(t, posted.Encrypted), "plain body") {
		t.Fatalf("encrypted envelope contains plaintext")
	}
}

func encryptE2EETestMessage(t *testing.T, alice, bob e2eeTestIdentity, messageID, conversationID string) *E2EEMessageEnvelope {
	t.Helper()
	env, err := EncryptE2EEMail(E2EEEncryptMailParams{
		Sender: E2EESenderKey{
			Address:       alice.address,
			DID:           alice.did,
			StableID:      alice.stableID,
			EncryptionKey: alice.assertion,
			SigningKey:    alice.priv,
		},
		Recipients: []E2EERecipientKey{{
			Address:       bob.address,
			DID:           bob.did,
			StableID:      bob.stableID,
			EncryptionKey: bob.assertion,
		}},
		Subject:        "secret subject",
		Body:           "secret body",
		MessageID:      messageID,
		ConversationID: conversationID,
		CreatedAt:      time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
	})
	if err != nil {
		t.Fatalf("EncryptE2EEMail: %v", err)
	}
	return env
}

func resignE2EETestEnvelope(t *testing.T, env *E2EEMessageEnvelope, signingKey ed25519.PrivateKey) {
	t.Helper()
	payload, err := e2eeEnvelopeCanonical(env, false, true, true)
	if err != nil {
		t.Fatal(err)
	}
	env.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(signingKey, payload))
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
