package chat

import (
	"context"
	"crypto/ecdh"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

type e2eeParty struct {
	parityKey
	stableID  string
	xPriv     *ecdh.PrivateKey
	assertion *awid.EncryptionKeyAssertion
}

func newE2EEParty(t *testing.T) e2eeParty {
	t.Helper()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	xPriv, rawPub, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	assertion, err := awid.BuildEncryptionKeyAssertion(priv, did, stableID, rawPub, "", time.Now().Add(-time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SignEncryptionKeyAssertion(assertion, priv); err != nil {
		t.Fatal(err)
	}
	return e2eeParty{parityKey: parityKey{did: did, priv: priv}, stableID: stableID, xPriv: xPriv, assertion: assertion}
}

// An encrypted message whose outer identifiers disagree with the ones its
// envelope authenticates is shown as failed, as chat history shows it; the
// wait goes on to the reply.
func TestStreamShowsAnEncryptedMessageWithForeignIdentifiersAsFailed(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name       string
		outerID    string
		wantFailed bool
	}{
		{name: "outer message id differs", outerID: "20000000-0000-4000-8000-0000000000aa", wantFailed: true},
		{name: "identifiers match", outerID: "20000000-0000-4000-8000-000000000001", wantFailed: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			reader, bob := newE2EEParty(t), newE2EEParty(t)
			envelope, err := awid.EncryptE2EEChat(awid.E2EEEncryptMessageParams{
				Sender:         awid.E2EESenderKey{DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion, SigningKey: bob.priv},
				Recipients:     []awid.E2EERecipientKey{{DID: reader.did, StableID: reader.stableID, EncryptionKey: reader.assertion}},
				Body:           "encrypted body",
				MessageID:      "20000000-0000-4000-8000-000000000001",
				ConversationID: paritySessionID,
				CreatedAt:      time.Now(),
			})
			if err != nil {
				t.Fatal(err)
			}
			row := map[string]any{
				"type": "message", "session_id": paritySessionID, "conversation_id": paritySessionID,
				"message_id": tc.outerID, "from_agent": "bob", "body": "",
				"content_mode": awid.ContentModeEncryptedV2, "message_version": awid.E2EEMessageVersion,
				"encrypted_envelope": envelope, "timestamp": "2026-11-18T00:00:00Z",
			}
			finalEnv := &awid.MessageEnvelope{
				From: "myco/carol", FromDID: bob.did, To: "myco/alice", ToDID: reader.did, Type: "chat",
				Body: "done", Timestamp: "2026-11-18T00:00:01Z",
				MessageID: "20000000-0000-4000-8000-0000000000ff", ConversationID: paritySessionID,
			}
			finalReply := signedParityRow(t, bob.parityKey, finalEnv, map[string]any{"from_agent": "carol", "from_address": "myco/carol", "to_address": "myco/alice"})
			url := parityServer(t, []map[string]any{row}, finalReply)

			c := parityReader(t, url, reader.parityKey, bob.parityKey)
			c.SetE2EEKey(reader.assertion, reader.xPriv)
			result, err := Send(context.Background(), c, "alice", []string{"carol"}, "hello", SendOptions{Wait: 5}, nil)
			if err != nil {
				t.Fatalf("the wait ended with an error: %v", err)
			}
			if result.Status != "replied" || result.Reply != "done" {
				t.Fatalf("status=%s reply=%q", result.Status, result.Reply)
			}
			var got *Event
			for i := range result.Events {
				if result.Events[i].MessageID == tc.outerID {
					got = &result.Events[i]
				}
			}
			if got == nil {
				t.Fatalf("encrypted event missing from %+v", result.Events)
			}
			if failed := got.VerificationStatus == awid.Failed; failed != tc.wantFailed {
				t.Fatalf("verification_status=%s, want failed=%v", got.VerificationStatus, tc.wantFailed)
			}
			if !tc.wantFailed && got.Body != "encrypted body" {
				t.Fatalf("body=%q, want the decrypted body", got.Body)
			}
		})
	}
}
