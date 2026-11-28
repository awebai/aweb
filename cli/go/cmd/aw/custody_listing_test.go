//go:build !windows

package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A grant seat's listing reads through the resident's custody socket. A
// message wrapped to an archived key the resident no longer holds stays one
// placeholder row and its readable neighbour survives; a revoked grant still
// fails the listing (docs/e2e-messaging-contract.md "Key Loss And Rotation").
func TestGrantListingThroughCustodySocketKeepsOnlyRowLocalFailures(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "acme.com/bob")
	lostKey, _, err := awid.GenerateX25519Keypair()
	if err != nil {
		t.Fatal(err)
	}
	lostAssertion, err := awid.BuildEncryptionKeyAssertion(alice.signKey, alice.did, alice.stableID, lostKey.PublicKey().Bytes(), "", time.Now().UTC().Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	seal := func(messageID string, key *awid.EncryptionKeyAssertion, body string) *awid.E2EEMessageEnvelope {
		envelope, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{Sender: awid.E2EESenderKey{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion, SigningKey: bob.signKey}, Recipients: []awid.E2EERecipientKey{{Address: alice.address, DID: alice.did, StableID: alice.stableID, EncryptionKey: key}}, Subject: "sealed", Body: body, MessageID: messageID, ConversationID: "99999999-9999-4999-8999-999999999999", CreatedAt: time.Now().UTC()})
		if err != nil {
			t.Fatal(err)
		}
		return envelope
	}
	lost := seal("11111111-1111-4111-8111-111111111111", lostAssertion, "sealed to the lost key")
	readable := seal("22222222-2222-4222-8222-222222222222", alice.assertion, "sealed to the active key")
	stored := map[string]*awid.E2EEMessageEnvelope{lost.MessageID: lost, readable.MessageID: readable}

	_, sessionKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	svc := testCustodyService(t, alice.signKey, sessionKey)
	svc.residentHome = t.TempDir()
	svc.identity.DID, svc.identity.StableID, svc.identity.Address = alice.did, alice.stableID, alice.address
	svc.e2eeAssertion, svc.e2eePrivateKey = alice.assertion, alice.xPriv
	svc.readStoredEnvelope = func(ctx context.Context, kind, messageID, conversationID string) (*awid.E2EEMessageEnvelope, error) {
		if envelope := stored[messageID]; envelope != nil {
			return envelope, nil
		}
		return nil, errors.New("stored_message_unavailable")
	}
	var revoked atomic.Bool
	activeStatus := svc.grantStatus
	svc.grantStatus = func(ctx context.Context, grantID string) (custodyGrantStatus, error) {
		if revoked.Load() {
			return custodyGrantStatus{Active: false, Status: "revoked", EffectiveStatus: "revoked"}, nil
		}
		return activeStatus(ctx, grantID)
	}
	socketDir, err := os.MkdirTemp("/tmp", "awcust")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	if err := os.Chmod(socketDir, 0o700); err != nil {
		t.Fatal(err)
	}
	socketPath := filepath.Join(socketDir, "custody.sock")
	listener, err := listenCustodySocket(socketPath)
	if err != nil {
		t.Fatal(err)
	}
	custodyServer := &http.Server{Handler: svc.routes()}
	go func() { _ = custodyServer.Serve(listener) }()
	t.Cleanup(func() { _ = custodyServer.Close() })

	inbox := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages/inbox" {
			http.NotFound(w, r)
			return
		}
		var rows []awid.InboxMessage
		for _, envelope := range []*awid.E2EEMessageEnvelope{lost, readable} {
			rows = append(rows, awid.InboxMessage{MessageID: envelope.MessageID, ConversationID: envelope.ConversationID, ContentMode: awid.ContentModeEncryptedV2, MessageVersion: awid.E2EEMessageVersion, Encrypted: envelope, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
		}
		_ = json.NewEncoder(w).Encode(awid.InboxResponse{Messages: rows})
	}))
	t.Cleanup(inbox.Close)
	client, err := awid.NewWithGrant(inbox.URL, sessionKey, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	client.SetGrantSubject("backend:acme.com", alice.stableID, alice.did, alice.address, "alice")
	client.SetPlainMessageSigner(&awid.UnixCustodyClient{SocketPath: socketPath})

	listing, err := client.Inbox(context.Background(), awid.InboxParams{KeepUndecryptable: true})
	if err != nil {
		t.Fatalf("grant listing with one lost-key row failed: %v", err)
	}
	if len(listing.Messages) != 2 {
		t.Fatalf("grant listing rows: %+v", listing.Messages)
	}
	if row := listing.Messages[0]; row.MessageID != lost.MessageID || row.DecryptError != "encryption_key_missing" || row.Body != "" || row.Subject != "" || row.VerificationStatus != awid.Failed {
		t.Fatalf("lost-key row: want an encryption_key_missing placeholder, got %+v", row)
	}
	if row := listing.Messages[1]; row.MessageID != readable.MessageID || row.DecryptError != "" || row.Body != "sealed to the active key" {
		t.Fatalf("readable neighbour: got %+v", row)
	}
	if _, err := client.Inbox(context.Background(), awid.InboxParams{MessageID: lost.MessageID}); err == nil || awid.DescribeError(err).Code != "encryption_key_missing" || err.Error() != "archived_key_unavailable" {
		t.Fatalf("exact read of the lost-key row: err=%v code=%s, want the typed archived_key_unavailable refusal", err, awid.DescribeError(err).Code)
	}

	revoked.Store(true)
	if _, err := client.Inbox(context.Background(), awid.InboxParams{KeepUndecryptable: true}); err == nil || err.Error() != "grant_revoked" {
		t.Fatalf("revoked grant listing: err=%v, want grant_revoked", err)
	}
}
