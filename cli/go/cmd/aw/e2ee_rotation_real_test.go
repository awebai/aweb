package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

type rotationMailShow struct {
	Messages []awid.InboxMessage `json:"messages"`
}

// sendE2EEMail sends encrypted mail through the real binary and returns its message id.
func (world *realCommandWorld) sendE2EEMail(t *testing.T, from commandMember, to, subject, body string) string {
	t.Helper()
	var sent struct {
		MessageID string `json:"message_id"`
		Status    string `json:"status"`
	}
	out := world.requireCommand(t, from.Home, "mail", "send", "--e2ee", "--to", to, "--subject", subject, "--body", body)
	if err := json.Unmarshal([]byte(out), &sent); err != nil || sent.MessageID == "" || sent.Status != "delivered" {
		t.Fatalf("e2ee send %q: %v\n%s", subject, err, out)
	}
	return sent.MessageID
}

func (world *realCommandWorld) requireReadableMail(t *testing.T, reader commandMember, messageID, body string) awid.InboxMessage {
	t.Helper()
	var shown rotationMailShow
	out := world.requireCommand(t, reader.Home, "mail", "show", "--message-id", messageID)
	if err := json.Unmarshal([]byte(out), &shown); err != nil || len(shown.Messages) != 1 {
		t.Fatalf("mail show %s: %v\n%s", messageID, err, out)
	}
	if got := shown.Messages[0]; got.Body != body || got.VerificationStatus != awid.Verified {
		t.Fatalf("mail show %s: body=%q status=%q, want %q verified", messageID, got.Body, got.VerificationStatus, body)
	}
	return shown.Messages[0]
}

func rotateEncryptionKey(t *testing.T, world *realCommandWorld, member commandMember) idEncryptionKeyOutput {
	t.Helper()
	var rotated idEncryptionKeyOutput
	out := world.requireCommand(t, member.Home, "id", "encryption-key", "rotate")
	if err := json.Unmarshal([]byte(out), &rotated); err != nil || rotated.Status != "rotated" || rotated.KeyID == "" {
		t.Fatalf("rotate: %v\n%s", err, out)
	}
	return rotated
}

// docs/e2e-messaging-contract.md "Discovery, trust, pinning, and rotation" and
// "Key Loss And Rotation": new sends use the newest key, and the recipient
// reads older mail with the archived key named by the wrap.
func TestRealServerE2EEMailAcrossRecipientKeyRotation(t *testing.T) {
	world := newRealCommandWorld(t)
	alice, bob := world.addLocalMember(t, "alice"), world.addLocalMember(t, "bob")
	before := world.sendE2EEMail(t, alice, "bob", "before-rotation", "wrapped to the first key")
	rotated := rotateEncryptionKey(t, world, bob)
	after := world.sendE2EEMail(t, alice, "bob", "after-rotation", "wrapped to the rotated key")

	afterMessage := world.requireReadableMail(t, bob, after, "wrapped to the rotated key")
	if wraps := deliveryWrapKeyIDs(afterMessage); len(wraps) != 1 || wraps[0] != rotated.KeyID {
		t.Fatalf("post-rotation send wrapped to %v, want the rotated key %s", wraps, rotated.KeyID)
	}
	beforeMessage := world.requireReadableMail(t, bob, before, "wrapped to the first key")
	if wraps := deliveryWrapKeyIDs(beforeMessage); len(wraps) != 1 || wraps[0] == rotated.KeyID {
		t.Fatalf("pre-rotation send wrapped to %v, want the archived key", wraps)
	}
	inbox := world.requireCommand(t, bob.Home, "mail", "inbox")
	for _, body := range []string{"wrapped to the first key", "wrapped to the rotated key"} {
		if !strings.Contains(inbox, body) {
			t.Fatalf("inbox after rotation is missing %q:\n%s", body, inbox)
		}
	}
}

func deliveryWrapKeyIDs(message awid.InboxMessage) []string {
	if message.Encrypted == nil {
		return nil
	}
	var ids []string
	for _, wrap := range message.Encrypted.KeyWraps {
		if wrap.WrapPurpose == "delivery" {
			ids = append(ids, wrap.RecipientEncryptionKeyID)
		}
	}
	return ids
}
