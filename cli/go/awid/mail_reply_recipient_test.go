package awid

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestMailReplyRecipientBindsSource(t *testing.T) {
	for _, scenario := range []string{"addressless", "expired", "missing", "invalid-assertion", "forged", "outer-id", "byot", "binding-mismatch", "no-published-key", "rotated-key"} {
		t.Run(scenario, func(t *testing.T) {
			self := newE2EETestLocalIdentity(t)
			sender := newE2EETestIdentity(t, "")
			addressed := scenario == "byot" || scenario == "binding-mismatch" || scenario == "no-published-key" || scenario == "rotated-key"
			if addressed {
				sender.address = "example.com/alice"
			}
			if scenario == "expired" {
				sender.assertion.ExpiresAt = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)
				if err := SignEncryptionKeyAssertion(sender.assertion, sender.priv); err != nil {
					t.Fatal(err)
				}
			}
			envelope, err := EncryptE2EEMail(E2EEEncryptMailParams{
				Sender:     E2EESenderKey{DID: sender.did, StableID: sender.stableID, Address: sender.address, EncryptionKey: sender.assertion, SigningKey: sender.priv},
				Recipients: []E2EERecipientKey{{DID: self.did, EncryptionKey: self.assertion}},
				MessageID:  "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222",
				Subject: "source", Body: "private", CreatedAt: time.Date(2026, 5, 26, 12, 0, 0, 0, time.UTC),
			})
			if err != nil {
				t.Fatal(err)
			}
			// Alterations signed by the sender still cannot grant key authority.
			// Assertions are also AEAD-bound, so rebuild ciphertext after changes
			// below through the same content key used by the valid recipient.
			if scenario == "missing" || scenario == "invalid-assertion" {
				identity := E2EEDecryptIdentity{DID: self.did, EncryptionKeyID: self.assertion.EncryptionKeyID, PrivateKey: self.xPriv}
				wrap, err := selectE2EEKeyWrap(envelope, identity)
				if err != nil {
					t.Fatal(err)
				}
				cek, err := openE2EEKeyWrap(wrap, envelope.MessageID, envelope.ConversationID, envelope.From, identity)
				if err != nil {
					t.Fatal(err)
				}
				oldAAD, err := e2eeContentAAD(envelope)
				if err != nil {
					t.Fatal(err)
				}
				ciphertext, _ := base64.RawStdEncoding.DecodeString(envelope.Ciphertext)
				nonce, _ := base64.RawStdEncoding.DecodeString(envelope.Crypto.ContentNonce)
				inner, err := aesGCMOpen(cek, nonce, ciphertext, oldAAD)
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "missing" {
					envelope.SenderEncryptionKey = nil
				} else {
					envelope.SenderEncryptionKey.Signature = "invalid"
				}
				aad, err := e2eeContentAAD(envelope)
				if err != nil {
					t.Fatal(err)
				}
				ciphertext, err = aesGCMSeal(cek, nonce, inner, aad)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Ciphertext = base64.RawStdEncoding.EncodeToString(ciphertext)
				envelope.Crypto.CiphertextHash = e2eeHashBytes(ciphertext)
				signed, err := e2eeEnvelopeCanonical(envelope, false, true, true)
				if err != nil {
					t.Fatal(err)
				}
				envelope.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(sender.priv, signed))
			}
			if scenario == "forged" {
				envelope.From.Address = "attacker.example/alice"
			}
			source := InboxMessage{VerificationStatus: Verified, MessageID: envelope.MessageID, ConversationID: envelope.ConversationID, Encrypted: envelope,
				// These unsigned display fields must never redirect a reply.
				FromAddress: "attacker.example/alice", FromDID: "did:key:attacker", FromStableID: "did:aw:attacker"}

			if scenario == "outer-id" {
				source.ConversationID = "33333333-3333-4333-8333-333333333333"
			}
			c, err := NewWithIdentity("http://unused.invalid", self.priv, self.did)
			if err != nil {
				t.Fatal(err)
			}
			c.SetE2EEKey(self.assertion, self.xPriv)
			resolutions := 0
			current := sender
			if scenario == "rotated-key" {
				current = newE2EETestIdentity(t, sender.address)
				current.stableID = sender.stableID
				current.assertion.IdentityStableID = &sender.stableID
				if err := SignEncryptionKeyAssertion(current.assertion, current.priv); err != nil {
					t.Fatal(err)
				}
			}
			c.SetResolver(stubIdentityResolver{resolve: func(_ context.Context, identifier string) (*ResolvedIdentity, error) {
				resolutions++
				if !addressed || identifier != sender.address {
					t.Fatalf("unexpected resolution %q", identifier)
				}
				result := &ResolvedIdentity{DID: current.did, StableID: current.stableID, Address: current.address, EncryptionKey: current.assertion}
				if scenario == "binding-mismatch" {
					result.StableID = "did:aw:other"
				}
				if scenario == "no-published-key" {
					result.EncryptionKey = nil
				}
				return result, nil
			}})
			got, err := c.MailReplyRecipient(context.Background(), source)
			wantError := map[string]string{"expired": "send a new message", "missing": "send a new message", "invalid-assertion": "send a new message", "forged": "signature", "outer-id": "does not match", "binding-mismatch": "source sender identity", "no-published-key": "no published E2E encryption key"}[scenario]
			if wantError != "" {
				if err == nil || !strings.Contains(err.Error(), wantError) {
					t.Fatalf("error=%v, want %q", err, wantError)
				}
				if got.EncryptionKey != nil {
					t.Fatal("refusal returned a usable key")
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if got.DID != current.did || got.StableID != sender.stableID || got.EncryptionKey != current.assertion {
					t.Fatalf("wrong recipient: %+v", got)
				}
			}
			if addressed && resolutions != 1 {
				t.Fatalf("address resolution count=%d", resolutions)
			}
			if !addressed && resolutions != 0 {
				t.Fatal("addressless reply attempted first-contact discovery")
			}
		})
	}
}

// An older custody host must fail with a worker-side upgrade remedy, never
// downgrade the reply or silently reroute it through first-contact discovery.
type oldReplyCustody struct{ fakeE2EECustody }

func (f *oldReplyCustody) CreateE2EEEnvelope(_ context.Context, req *E2EEEnvelopeCreateRequest) (*E2EEEnvelopeCreateResponse, error) {
	f.createReq = req
	return nil, errors.New("recipient_binding_unavailable")
}
func TestGrantMailReplyRequiresCurrentCustodyHost(t *testing.T) {
	resident := newE2EETestIdentity(t, "example.com/resident")
	human := newE2EETestIdentity(t, "")
	_, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	c, err := NewWithGrant("http://unused.invalid", key, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	c.SetGrantSubject("test:example.com", resident.stableID, resident.did, resident.address, "resident")
	custody := &oldReplyCustody{}
	c.SetPlainMessageSigner(custody)
	_, err = c.SendMessage(context.Background(), &SendMessageRequest{
		ToDID: human.did, ConversationID: "22222222-2222-4222-8222-222222222222", ReplyToMessageID: "33333333-3333-4333-8333-333333333333",
		EncryptE2EE: true, Body: "reply", E2EERecipient: &E2EERecipientKey{DID: human.did, StableID: human.stableID, EncryptionKey: human.assertion},
	})
	if err == nil || !strings.Contains(err.Error(), "custody host must be aw >= 1.36.30") {
		t.Fatalf("missing upgrade guidance: %v", err)
	}
	if custody.createReq == nil || custody.createReq.ReplyToMessageID != "33333333-3333-4333-8333-333333333333" {
		t.Fatal("source id not sent to custody")
	}
	if err := VerifyE2EECreateCustodyProof(custody.createReq); err != nil {
		t.Fatal(err)
	}
}
