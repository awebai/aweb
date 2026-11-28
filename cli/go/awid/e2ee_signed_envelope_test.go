package awid

import (
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
