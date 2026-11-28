package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A custody reply-source check verifies the stored source's signature once,
// before its delivery checks, and opens that verified envelope.
func BenchmarkCustodyStoredMailReplySource(b *testing.B) {
	resident := newCustodyE2EETestIdentity(b, "example.com/resident")
	human := newCustodyE2EETestIdentity(b, "example.com/human")
	human.address = ""
	_, sessionKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		b.Fatal(err)
	}
	svc := testCustodyE2EEService(b, resident, human, sessionKey)
	req := signedE2EECreateRequest(b, sessionKey, resident, human)
	req.ReplyToMessageID = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
	source, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
		Sender:     awid.E2EESenderKey{DID: human.did, StableID: human.stableID, EncryptionKey: human.assertion, SigningKey: human.signKey},
		Recipients: []awid.E2EERecipientKey{{DID: resident.did, StableID: resident.stableID, Address: resident.address, EncryptionKey: resident.assertion}},
		MessageID:  req.ReplyToMessageID, ConversationID: req.ConversationID, Body: strings.Repeat("x", 256<<10), CreatedAt: time.Now().UTC(),
	})
	if err != nil {
		b.Fatal(err)
	}
	svc.readStoredMailReply = func(context.Context, string) (*awid.InboxMessage, error) {
		return &awid.InboxMessage{MessageID: source.MessageID, ConversationID: source.ConversationID, FromAgentID: "human-actor", Encrypted: source}, nil
	}
	ctx := context.Background()
	for b.Loop() {
		if _, err := svc.storedMailReplyRecipient(ctx, req); err != nil {
			b.Fatal(err)
		}
	}
}
