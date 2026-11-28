package awid

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"
)

var benchmarkBody = strings.Repeat("x", 256<<10)

// A read verifies the envelope once; compare ns/op across changes to the read
// path.
func BenchmarkClientReadActiveKey(b *testing.B) {
	recipient := newRotatedRecipient(b)
	client := rotatedRecipientClient(b, recipient, "http://127.0.0.1:1")
	envelope := sealedMailTo(b, recipient, recipient.active, benchmarkBody)
	for b.Loop() {
		if _, err := client.DecryptE2EEEnvelope(envelope); err != nil {
			b.Fatal(err)
		}
	}
}

// A reply to an addressless sender verifies the source's signature once and
// opens the verified envelope.
func BenchmarkMailReplyRecipientAddressless(b *testing.B) {
	recipient := newRotatedRecipient(b)
	client := rotatedRecipientClient(b, recipient, "http://127.0.0.1:1")
	senderPub, senderKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}
	senderDID, senderStableID := ComputeDIDKey(senderPub), ComputeStableID(senderPub)
	envelope, err := EncryptE2EEMail(E2EEEncryptMailParams{
		Sender:         E2EESenderKey{DID: senderDID, StableID: senderStableID, EncryptionKey: testEncryptionAssertion(b, senderKey, senderDID, senderStableID), SigningKey: senderKey},
		Recipients:     []E2EERecipientKey{{Address: "receiver.example/bob", DID: recipient.did, StableID: recipient.stableID, EncryptionKey: recipient.active}},
		Subject:        "source",
		Body:           benchmarkBody,
		MessageID:      "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
		ConversationID: "eeeeeeee-eeee-4eee-8eee-eeeeeeeeeeee",
		CreatedAt:      time.Now().UTC(),
	})
	if err != nil {
		b.Fatal(err)
	}
	source := InboxMessage{MessageID: envelope.MessageID, ConversationID: envelope.ConversationID, Encrypted: envelope}
	ctx := context.Background()
	for b.Loop() {
		if _, err := client.MailReplyRecipient(ctx, source); err != nil {
			b.Fatal(err)
		}
	}
}
