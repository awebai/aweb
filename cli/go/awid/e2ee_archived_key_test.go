package awid

import (
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

type rotatedRecipient struct {
	did, stableID string
	signingKey    ed25519.PrivateKey
	archived      *EncryptionKeyAssertion
	archivedKey   *ecdh.PrivateKey
	active        *EncryptionKeyAssertion
	activeKey     *ecdh.PrivateKey
}

func newRotatedRecipient(t *testing.T) rotatedRecipient {
	t.Helper()
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := rotatedRecipient{did: ComputeDIDKey(pub), stableID: ComputeStableID(pub), signingKey: key}
	created := time.Now().UTC().Add(-time.Hour)
	var raw []byte
	if r.archivedKey, raw, err = GenerateX25519Keypair(); err != nil {
		t.Fatal(err)
	}
	if r.archived, err = BuildEncryptionKeyAssertion(key, r.did, r.stableID, raw, "", created); err != nil {
		t.Fatal(err)
	}
	if r.activeKey, raw, err = GenerateX25519Keypair(); err != nil {
		t.Fatal(err)
	}
	if r.active, err = BuildEncryptionKeyAssertion(key, r.did, r.stableID, raw, r.archived.EncryptionKeyID, created.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	return r
}

func sealedMailTo(t *testing.T, recipient rotatedRecipient, key *EncryptionKeyAssertion, body string) *E2EEMessageEnvelope {
	t.Helper()
	senderPub, senderKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	senderDID, senderStableID := ComputeDIDKey(senderPub), ComputeStableID(senderPub)
	messageID, err := GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	conversationID, err := GenerateUUID4()
	if err != nil {
		t.Fatal(err)
	}
	envelope, err := EncryptE2EEMail(E2EEEncryptMailParams{
		Sender:         E2EESenderKey{Address: "sender.example/alice", DID: senderDID, StableID: senderStableID, EncryptionKey: testEncryptionAssertion(t, senderKey, senderDID, senderStableID), SigningKey: senderKey},
		Recipients:     []E2EERecipientKey{{Address: "receiver.example/bob", DID: recipient.did, StableID: recipient.stableID, EncryptionKey: key}},
		Subject:        "sealed",
		Body:           body,
		MessageID:      messageID,
		ConversationID: conversationID,
		CreatedAt:      time.Now().UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

// docs/e2e-messaging-contract.md "Key Loss And Rotation": the reader uses the
// key id named by the matching wrap, not by trying every key.
func TestDecryptOpensArchivedWrapWithTheKeyItNames(t *testing.T) {
	recipient := newRotatedRecipient(t)
	client, err := NewWithIdentity("http://127.0.0.1:1", recipient.signingKey, recipient.did)
	if err != nil {
		t.Fatal(err)
	}
	client.SetStableID(recipient.stableID)
	client.SetAddress("receiver.example/bob")
	client.SetE2EEKey(recipient.active, recipient.activeKey)
	var requested []string
	client.SetE2EEArchivedKeyLoader(func(keyID string) (*ecdh.PrivateKey, error) {
		requested = append(requested, keyID)
		if keyID == recipient.archived.EncryptionKeyID {
			return recipient.archivedKey, nil
		}
		return nil, errors.New("not in the archive")
	})

	plain, err := client.DecryptE2EEEnvelope(sealedMailTo(t, recipient, recipient.active, "to the active key"))
	if err != nil || plain.Body != "to the active key" || len(requested) != 0 {
		t.Fatalf("active-key read: body=%v err=%v archive requests=%v", plain, err, requested)
	}
	plain, err = client.DecryptE2EEEnvelope(sealedMailTo(t, recipient, recipient.archived, "to the archived key"))
	if err != nil || plain.Body != "to the archived key" || len(requested) != 1 || requested[0] != recipient.archived.EncryptionKeyID {
		t.Fatalf("archived-key read: body=%v err=%v archive requests=%v", plain, err, requested)
	}

	client.SetE2EEArchivedKeyLoader(func(string) (*ecdh.PrivateKey, error) { return nil, errors.New("archive lost") })
	_, err = client.DecryptE2EEEnvelope(sealedMailTo(t, recipient, recipient.archived, "lost"))
	var decryption *DecryptionError
	if !errors.As(err, &decryption) || decryption.Code != "encryption_key_missing" {
		t.Fatalf("lost archived key: err=%v, want encryption_key_missing", err)
	}
}

// A listing derives decrypt_error locally; a server cannot set it.
func TestListingsIgnoreServerSuppliedDecryptErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/messages/inbox":
			_, _ = w.Write([]byte(`{"messages":[{"message_id":"m1","conversation_id":"c1","from_alias":"alice","subject":"s","body":"plain body","decrypt_error":"decrypt_failed","created_at":"2026-11-27T00:00:00Z"}]}`))
		case "/v1/chat/pending":
			_, _ = w.Write([]byte(`{"pending":[{"session_id":"s1","participants":["alice","bob"],"last_message":"plain preview","last_decrypt_error":"decrypt_failed","last_from":"alice","unread_count":1,"last_activity":"2026-11-27T00:00:00Z","sender_waiting":false,"time_remaining_seconds":null}],"messages_waiting":1}`))
		case "/v1/chat/sessions/s1/messages":
			_, _ = w.Write([]byte(`{"messages":[{"message_id":"m2","conversation_id":"s1","from_agent":"alice","body":"plain chat","decrypt_error":"decrypt_failed","timestamp":"2026-11-27T00:00:00Z"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewWithIdentity(server.URL, key, ComputeDIDKey(key.Public().(ed25519.PublicKey)))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	inbox, err := client.Inbox(ctx, InboxParams{KeepUndecryptable: true})
	if err != nil || inbox.Messages[0].DecryptError != "" || inbox.Messages[0].Body != "plain body" {
		t.Fatalf("inbox kept a server decrypt_error: %+v err=%v", inbox, err)
	}
	pending, err := client.ChatPendingWithParams(ctx, ChatPendingParams{KeepUndecryptable: true})
	if err != nil || pending.Pending[0].LastDecryptError != "" || pending.Pending[0].LastMessage != "plain preview" {
		t.Fatalf("pending kept a server last_decrypt_error: %+v err=%v", pending, err)
	}
	history, err := client.ChatHistory(ctx, ChatHistoryParams{SessionID: "s1", KeepUndecryptable: true})
	if err != nil || history.Messages[0].DecryptError != "" || history.Messages[0].Body != "plain chat" {
		t.Fatalf("history kept a server decrypt_error: %+v err=%v", history, err)
	}
}

type failingUnwrapCustody struct{ fakeE2EECustody }

func (f *failingUnwrapCustody) UnwrapE2EEMessage(context.Context, *E2EEUnwrapRequest) (*E2EEUnwrapResponse, error) {
	return nil, errors.New("grant_revoked")
}

// Only a row-local decryption failure becomes a placeholder; a custody
// authority failure still fails the listing.
func TestListingCustodyFailureStillFailsTheListing(t *testing.T) {
	resident := newE2EETestIdentity(t, "acme.com/alice")
	_, sessionKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	env := &E2EEMessageEnvelope{MessageVersion: E2EEMessageVersion, EnvelopeType: E2EEEnvelopeType, Kind: "mail", MessageID: "msg-1", ConversationID: "conv-1", From: E2EEIdentityRef{DID: "did:key:zSender"}, Policy: E2EEPolicy{RequiresE2EE: true}}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/messages/inbox" {
			_ = json.NewEncoder(w).Encode(InboxResponse{Messages: []InboxMessage{{MessageID: "msg-1", ConversationID: "conv-1", ContentMode: ContentModeEncryptedV2, MessageVersion: E2EEMessageVersion, Encrypted: env}}})
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(server.Close)
	client, err := NewWithGrant(server.URL, sessionKey, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	client.SetGrantSubject("backend:acme.com", resident.stableID, resident.did, resident.address, "alice")
	client.SetPlainMessageSigner(&failingUnwrapCustody{})
	if _, err := client.Inbox(context.Background(), InboxParams{KeepUndecryptable: true}); err == nil || err.Error() != "grant_revoked" {
		t.Fatalf("custody failure in a listing: err=%v, want grant_revoked", err)
	}
}
