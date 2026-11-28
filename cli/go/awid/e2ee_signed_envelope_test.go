package awid

import (
	"context"
	"crypto/ecdh"
	"fmt"
	"reflect"
	"testing"
)

// A verified envelope is a snapshot of exactly what was verified: changing or
// reusing the caller's envelope afterwards changes neither what Open decrypts
// nor what the snapshot reports.
func TestSignedEnvelopeIsASnapshotOfWhatWasVerified(t *testing.T) {
	recipient := newRotatedRecipient(t)
	identity := E2EEDecryptIdentity{Address: "receiver.example/bob", DID: recipient.did, StableID: recipient.stableID, EncryptionKeyID: recipient.active.EncryptionKeyID, PrivateKey: recipient.activeKey}
	original := sealedMailTo(t, recipient, recipient.active, "what the sender signed")
	signed, err := VerifySignedE2EEEnvelope(original)
	if err != nil {
		t.Fatal(err)
	}

	// The caller reuses its envelope for another message.
	other := sealedMailTo(t, recipient, recipient.active, "a different message")
	senderMessageID, senderFromDID := original.MessageID, original.From.DID
	*original = *other
	original.KeyWraps[0].WrappedCEK = "reused"

	plain, err := signed.Open(identity, nil)
	if err != nil || plain.Body != "what the sender signed" {
		t.Fatalf("open after the caller reused its envelope: body=%v err=%v", plain, err)
	}
	snapshot := signed.Envelope()
	if snapshot.MessageID != senderMessageID || snapshot.From.DID != senderFromDID || snapshot.KeyWraps[0].WrappedCEK == "reused" {
		t.Fatalf("snapshot follows the caller's envelope: %+v", snapshot)
	}

	// Nor can a caller change the snapshot through what Envelope returns.
	snapshot.KeyWraps[0].WrappedCEK = "changed"
	snapshot.Recipients[0].DID = "did:key:changed"
	if snapshot.SenderEncryptionKey != nil {
		snapshot.SenderEncryptionKey.EncryptionKeyID = "changed"
	}
	if plain, err := signed.Open(identity, nil); err != nil || plain.Body != "what the sender signed" {
		t.Fatalf("open after changing a returned envelope: body=%v err=%v", plain, err)
	}
	if again := signed.Envelope(); again.KeyWraps[0].WrappedCEK == "changed" || again.Recipients[0].DID == "did:key:changed" {
		t.Fatalf("Envelope shares storage with the snapshot: %+v", again)
	}
}

// cloneE2EEEnvelope must copy every pointer, slice and map in the envelope,
// including any field added later.
func TestCloneE2EEEnvelopeSharesNoMutableStorage(t *testing.T) {
	stableID, previous := "did:aw:sender", "sha256:previous"
	original := &E2EEMessageEnvelope{
		From:                E2EEIdentityRef{DID: "did:key:sender"},
		SenderEncryptionKey: &EncryptionKeyAssertion{EncryptionKeyID: "sha256:current", IdentityStableID: &stableID, PreviousEncryptionKeyID: &previous},
		Recipients:          []E2EERecipientRef{{DID: "did:key:recipient"}},
		KeyWraps:            []E2EEKeyWrap{{WrapID: "wrap"}},
	}
	requireNoSharedStorage(t, "envelope", reflect.ValueOf(original).Elem(), reflect.ValueOf(cloneE2EEEnvelope(original)).Elem())
}

func requireNoSharedStorage(t *testing.T, path string, original, clone reflect.Value) {
	t.Helper()
	switch original.Kind() {
	case reflect.Pointer:
		if original.IsNil() {
			return
		}
		if original.Pointer() == clone.Pointer() {
			t.Fatalf("%s: clone shares the pointer", path)
		}
		requireNoSharedStorage(t, path, original.Elem(), clone.Elem())
	case reflect.Slice:
		if original.Len() == 0 {
			return
		}
		if original.Pointer() == clone.Pointer() {
			t.Fatalf("%s: clone shares the slice", path)
		}
		for i := 0; i < original.Len(); i++ {
			requireNoSharedStorage(t, fmt.Sprintf("%s[%d]", path, i), original.Index(i), clone.Index(i))
		}
	case reflect.Map:
		if original.Len() > 0 && original.Pointer() == clone.Pointer() {
			t.Fatalf("%s: clone shares the map", path)
		}
	case reflect.Struct:
		for i := 0; i < original.NumField(); i++ {
			requireNoSharedStorage(t, path+"."+original.Type().Field(i).Name, original.Field(i), clone.Field(i))
		}
	}
}

// Open reads its snapshot once: an archive loader that overwrites the verified
// value with another one cannot change what is opened.
func TestSignedEnvelopeOpenIsNotRedirectedByTheArchiveLoader(t *testing.T) {
	recipient := newRotatedRecipient(t)
	identity := E2EEDecryptIdentity{Address: "receiver.example/bob", DID: recipient.did, StableID: recipient.stableID, EncryptionKeyID: recipient.active.EncryptionKeyID, PrivateKey: recipient.activeKey}
	first, err := VerifySignedE2EEEnvelope(sealedMailTo(t, recipient, recipient.archived, "the first message"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := VerifySignedE2EEEnvelope(sealedMailTo(t, recipient, recipient.archived, "the second message"))
	if err != nil {
		t.Fatal(err)
	}
	plain, err := first.Open(identity, func(string) (*ecdh.PrivateKey, error) {
		*first = *second
		return recipient.archivedKey, nil
	})
	if err != nil || plain.Body != "the first message" {
		t.Fatalf("open with a loader that replaced the verified value: body=%v err=%v", plain, err)
	}
}

type mutatingUnwrapCustody struct{ fakeE2EECustody }

func (f *mutatingUnwrapCustody) UnwrapE2EEMessage(ctx context.Context, req *E2EEUnwrapRequest) (*E2EEUnwrapResponse, error) {
	out, err := f.fakeE2EECustody.UnwrapE2EEMessage(ctx, req)
	req.Envelope.MessageID = "changed by custody"
	req.Envelope.KeyWraps[0].WrappedCEK = "changed by custody"
	req.Envelope.Recipients[0].DID = "did:key:changed"
	return out, err
}

// A custody provider receives its own copy of a verified envelope, never the
// snapshot a later decision reads.
func TestCustodyUnwrapGetsADetachedCopyOfTheVerifiedEnvelope(t *testing.T) {
	recipient := newRotatedRecipient(t)
	signed, err := VerifySignedE2EEEnvelope(sealedMailTo(t, recipient, recipient.active, "sealed"))
	if err != nil {
		t.Fatal(err)
	}
	before := signed.Envelope()
	_, sessionKey, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewWithGrant("http://127.0.0.1:1", sessionKey, "11111111-1111-4111-8111-111111111111")
	if err != nil {
		t.Fatal(err)
	}
	client.SetGrantSubject("backend:receiver.example", recipient.stableID, recipient.did, "receiver.example/bob", "bob")
	custody := &mutatingUnwrapCustody{}
	client.SetPlainMessageSigner(custody)
	if _, err := client.decryptE2EEEnvelope(context.Background(), nil, signed); err != nil {
		t.Fatal(err)
	}
	if custody.unwrapReq == nil || custody.unwrapReq.Envelope == signed.envelope {
		t.Fatal("custody received the verified snapshot itself")
	}
	if after := signed.Envelope(); !reflect.DeepEqual(after, before) {
		t.Fatalf("custody changed the verified snapshot: before=%+v after=%+v", before, after)
	}
}
