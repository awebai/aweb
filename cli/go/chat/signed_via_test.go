package chat

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func TestSignedPayloadSurvivesChatEventProjections(t *testing.T) {
	public, private, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	env := &awid.MessageEnvelope{From: "alice", FromDID: awid.ComputeDIDKey(public), To: "bob", Type: "chat", Body: "body", Timestamp: "2026-10-26T00:00:00Z", Via: "telegram"}
	signature, err := awid.SignMessage(private, env)
	if err != nil {
		t.Fatal(err)
	}
	raw := awid.CanonicalJSON(env)
	data, _ := json.Marshal(map[string]any{"from_agent": "alice", "from_did": env.FromDID, "body": env.Body, "timestamp": env.Timestamp, "signature": signature, "signed_payload": raw, "via": "msteams"})
	streamed := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: string(data)})
	if streamed.VerificationStatus != awid.Verified {
		t.Fatalf("streamed signature failed: %s", streamed.VerificationStatus)
	}
	messages := buildMessages([]awid.ChatMessage{{FromAgent: "alice", FromDID: env.FromDID, Body: env.Body, Signature: signature, SignedPayload: raw, VerificationStatus: awid.Verified}})
	for _, event := range []Event{streamed, messages[0]} {
		encoded, _ := json.Marshal(event)
		var projected map[string]any
		if err := json.Unmarshal(encoded, &projected); err != nil {
			t.Fatal(err)
		}
		if projected["signed_payload"] != raw {
			t.Fatal("chat event dropped original payload")
		}
		if projected["via"] != "telegram" {
			t.Fatalf("chat event trusted wrapper or lost via: %v", projected["via"])
		}
	}
}

func TestEncryptedViaIgnoresUnrelatedPlaintextArtifact(t *testing.T) {
	alicePublic, alicePrivate, _ := awid.GenerateKeypair()
	bobPublic, bobPrivate, _ := awid.GenerateKeypair()
	aliceDID, bobDID := awid.ComputeDIDKey(alicePublic), awid.ComputeDIDKey(bobPublic)
	_, aliceEncryption, _ := awid.GenerateX25519Keypair()
	bobKey, bobEncryption, _ := awid.GenerateX25519Keypair()
	aliceAssertion, err := awid.BuildEncryptionKeyAssertion(alicePrivate, aliceDID, "", aliceEncryption, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	bobAssertion, err := awid.BuildEncryptionKeyAssertion(bobPrivate, bobDID, "", bobEncryption, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := awid.EncryptE2EEMessage(awid.E2EEEncryptMessageParams{Kind: "chat", Via: "telegram",
		Sender:     awid.E2EESenderKey{DID: aliceDID, EncryptionKey: aliceAssertion, SigningKey: alicePrivate},
		Recipients: []awid.E2EERecipientKey{{DID: bobDID, EncryptionKey: bobAssertion}}, Body: "sealed body",
		MessageID: "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	client, err := awid.NewWithIdentity("http://unused.example", bobPrivate, bobDID)
	if err != nil {
		t.Fatal(err)
	}
	client.SetE2EEKey(bobAssertion, bobKey)
	// This signature really verifies, but protects a different plaintext artifact.
	other := &awid.MessageEnvelope{Type: "chat", FromDID: aliceDID, Via: "msteams", Body: "other artifact"}
	signature, err := awid.SignMessage(alicePrivate, other)
	if err != nil {
		t.Fatal(err)
	}
	raw := awid.CanonicalJSON(other)
	data, _ := json.Marshal(map[string]any{"type": "message", "session_id": envelope.ConversationID,
		"conversation_id": envelope.ConversationID, "message_id": envelope.MessageID, "content_mode": awid.ContentModeEncryptedV2,
		"message_version": 2, "encrypted_envelope": envelope, "from_did": aliceDID, "signature": signature, "signed_payload": raw,
		"ingress": map[string]string{"platform": "msteams", "presence_kind": "shared", "input_origin": "external_human", "confidentiality": "hosted_readable"}})
	event := parseSSEEvent(&awid.SSEEvent{Event: "message", Data: string(data)})
	if event.Via != "" || event.VerificationStatus == awid.Verified {
		t.Errorf("outer plaintext artifact verified before decrypt: %#v", event)
	}
	if err := decryptChatEvent(client, &event); err != nil {
		t.Fatal(err)
	}
	if event.Ingress == nil || event.Ingress.Platform != "msteams" {
		t.Fatal("decryption lost original server ingress")
	}
	if event.Via != "telegram" {
		t.Errorf("decrypt did not supply inner via: %q", event.Via)
	}
	projected := buildMessages([]awid.ChatMessage{{ContentMode: awid.ContentModeEncryptedV2, MessageVersion: 2, Encrypted: envelope,
		Via: event.Via, Ingress: event.Ingress, VerificationStatus: awid.Verified, SignedPayload: raw, Signature: signature}})[0]
	if projected.Ingress == nil || projected.Ingress.Platform != "msteams" {
		t.Fatal("history lost original server ingress")
	}
	if projected.Via != "telegram" {
		t.Errorf("unrelated plaintext artifact forged decrypted via: %q", projected.Via)
	}
}
