package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
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

// activeEncryptionAssertion reads the member's active signed encryption-key assertion.
func activeEncryptionAssertion(t *testing.T, member commandMember) (*awconfig.EncryptionKeyState, *awid.EncryptionKeyAssertion) {
	t.Helper()
	state, err := awconfig.LoadEncryptionKeyStateFrom(filepath.Join(member.Home, "encryption.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	record := state.ActiveRecord()
	if record == nil {
		t.Fatal("member has no active encryption key")
	}
	assertion, err := loadEncryptionAssertionAt(filepath.Dir(member.Home), member.Home, record.AssertionPath)
	if err != nil {
		t.Fatal(err)
	}
	return state, assertion
}

// useMemberEnvironment gives in-process commands the environment the real binary gets.
func (world *realCommandWorld) useMemberEnvironment(t *testing.T) {
	t.Setenv("HOME", world.UserHome)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	t.Setenv("AW_NO_UPDATE_CHECK", "1")
}

func setEncryptionKeyClock(t *testing.T, clock func() time.Time) {
	t.Helper()
	previous := encryptionKeyClock
	encryptionKeyClock = clock
	t.Cleanup(func() { encryptionKeyClock = previous })
}

func mustParseAssertionTime(t *testing.T, value string) time.Time {
	t.Helper()
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

// A rotation whose clock reads its predecessor's second would tie in every
// newest-key projection (created_at, not_before, then key id). Rotation must
// produce a strictly later assertion so the rotated key is the one discovered.
func TestRealServerRotationInPredecessorSecondIsStrictlyNewer(t *testing.T) {
	world := newRealCommandWorld(t)
	alice, bob := world.addLocalMember(t, "alice"), world.addLocalMember(t, "bob")
	world.useMemberEnvironment(t)
	oldKeyOrderedFirst := false
	for round := 0; round < 24 && !oldKeyOrderedFirst; round++ {
		_, predecessor := activeEncryptionAssertion(t, bob)
		tied := mustParseAssertionTime(t, predecessor.CreatedAt)
		readings := 0
		setEncryptionKeyClock(t, func() time.Time {
			readings++
			if readings == 1 {
				return tied
			}
			return time.Now()
		})
		rotated, err := setupOrRotateIdentityEncryptionKeyForDir(world.Context, filepath.Dir(bob.Home), true, explicitEncryptionKeyIdentityHome(bob.Home))
		if err != nil {
			t.Fatalf("rotate in the predecessor's second: %v", err)
		}
		_, successor := activeEncryptionAssertion(t, bob)
		if successor.EncryptionKeyID != rotated.KeyID || successor.PreviousEncryptionKeyID == nil || *successor.PreviousEncryptionKeyID != predecessor.EncryptionKeyID {
			t.Fatalf("rotation lost its predecessor link: %+v", successor)
		}
		createdAt, notBefore := mustParseAssertionTime(t, successor.CreatedAt), mustParseAssertionTime(t, successor.NotBefore)
		if !createdAt.After(tied) || !notBefore.Equal(createdAt) || createdAt.After(time.Now()) {
			t.Fatalf("rotated assertion created_at=%s not_before=%s, want a real second after %s", successor.CreatedAt, successor.NotBefore, predecessor.CreatedAt)
		}
		// Under the old tie-break the larger key id wins; this round would
		// discover the superseded key if the timestamps tied.
		oldKeyOrderedFirst = predecessor.EncryptionKeyID > rotated.KeyID
		subject := fmt.Sprintf("rotation-round-%d", round)
		message := world.requireReadableMail(t, bob, world.sendE2EEMail(t, alice, "bob", subject, subject), subject)
		if wraps := deliveryWrapKeyIDs(message); len(wraps) != 1 || wraps[0] != rotated.KeyID {
			t.Fatalf("round %d: send after rotation wrapped to %v, want the rotated key %s", round, wraps, rotated.KeyID)
		}
	}
	if !oldKeyOrderedFirst {
		t.Fatal("no round ordered the predecessor's key id first; the tie was never exercised")
	}
}

// When the clock cannot reach a second after the predecessor's, rotate refuses
// before any key is created, activated or published.
func TestRealServerRotationRefusesWhenClockCannotAdvance(t *testing.T) {
	world := newRealCommandWorld(t)
	alice, bob := world.addLocalMember(t, "alice"), world.addLocalMember(t, "bob")
	world.useMemberEnvironment(t)
	stateBefore, predecessor := activeEncryptionAssertion(t, bob)
	keysBefore, err := filepath.Glob(filepath.Join(bob.Home, "encryption-keys", "*"))
	if err != nil {
		t.Fatal(err)
	}
	stuck := mustParseAssertionTime(t, predecessor.CreatedAt)
	setEncryptionKeyClock(t, func() time.Time { return stuck })

	cancelled, cancel := context.WithCancel(world.Context)
	time.AfterFunc(200*time.Millisecond, cancel)
	for name, ctx := range map[string]context.Context{"cancelled": cancelled, "bounded": world.Context} {
		started := time.Now()
		if _, err := setupOrRotateIdentityEncryptionKeyForDir(ctx, filepath.Dir(bob.Home), true, explicitEncryptionKeyIdentityHome(bob.Home)); err == nil {
			t.Fatalf("%s: rotate succeeded on a clock stuck in the predecessor's second", name)
		} else {
			t.Logf("%s refusal after %s: %v", name, time.Since(started).Round(time.Millisecond), err)
		}
		if name == "cancelled" && !errors.Is(cancelled.Err(), context.Canceled) {
			t.Fatal("cancelled context did not cancel")
		}
		stateAfter, current := activeEncryptionAssertion(t, bob)
		keysAfter, err := filepath.Glob(filepath.Join(bob.Home, "encryption-keys", "*"))
		if err != nil {
			t.Fatal(err)
		}
		if current.EncryptionKeyID != predecessor.EncryptionKeyID || len(stateAfter.Keys) != len(stateBefore.Keys) || len(keysAfter) != len(keysBefore) {
			t.Fatalf("%s: refused rotation left a key effect: active=%s keys=%d files=%d", name, current.EncryptionKeyID, len(stateAfter.Keys), len(keysAfter))
		}
	}
	message := world.requireReadableMail(t, bob, world.sendE2EEMail(t, alice, "bob", "after-refused-rotation", "still the original key"), "still the original key")
	if wraps := deliveryWrapKeyIDs(message); len(wraps) != 1 || wraps[0] != predecessor.EncryptionKeyID {
		t.Fatalf("refused rotation changed the discovered key: %v", wraps)
	}
}
