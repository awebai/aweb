package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
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

func (world *realCommandWorld) runTextInIdentityHome(home string, args ...string) (string, error) {
	command := exec.CommandContext(world.Context, world.Binary, append([]string{"--identity-home", home}, args...)...)
	command.Dir = filepath.Dir(home)
	command.Env = append(idCreateCommandEnv(world.UserHome), "AWID_REGISTRY_URL="+world.Stack.RegistryURL, "AW_NO_UPDATE_CHECK=1")
	out, err := command.CombinedOutput()
	return string(out), err
}

func decodeJSONObject(t *testing.T, out string) map[string]any {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal([]byte(out), &value); err != nil {
		t.Fatalf("decode %v\n%s", err, out)
	}
	return value
}

func jsonRows(t *testing.T, out, field string) []map[string]any {
	t.Helper()
	raw, _ := decodeJSONObject(t, out)[field].([]any)
	rows := make([]map[string]any, 0, len(raw))
	for _, item := range raw {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("%s row is not an object: %v", field, item)
		}
		rows = append(rows, row)
	}
	return rows
}

func rowIndex(rows []map[string]any, key, value string) int {
	for i, row := range rows {
		if row[key] == value {
			return i
		}
	}
	return -1
}

// requireLostKeyRefusal requires a command to fail with the typed lost-key code.
func (world *realCommandWorld) requireLostKeyRefusal(t *testing.T, member commandMember, what string, args ...string) {
	t.Helper()
	out, err := world.runInIdentityHome(member.Home, args...)
	var refused cliErrorEnvelope
	if err == nil || json.Unmarshal([]byte(out), &refused) != nil || refused.Error.Code != "encryption_key_missing" {
		t.Fatalf("%s of a lost-key message: want an encryption_key_missing refusal, got err=%v\n%s", what, err, out)
	}
}

func requirePlaceholderRow(t *testing.T, where string, row map[string]any, code string) {
	t.Helper()
	if body, present := row["body"]; present && body != "" {
		t.Fatalf("%s: placeholder kept a body: %v", where, row)
	}
	if row["decrypt_error"] != code || row["verification_status"] != string(awid.Failed) || row["attachments_available"] != false || row["attachments"] != nil {
		t.Fatalf("%s: want an undecryptable placeholder with %s, got %v", where, code, row)
	}
	if subject, present := row["subject"]; present && subject != "" {
		t.Fatalf("%s: placeholder kept a subject: %v", where, row)
	}
}

func requireReadableRow(t *testing.T, where string, row map[string]any, body string) {
	t.Helper()
	if row["body"] != body || row["decrypt_error"] != nil {
		t.Fatalf("%s: want readable %q, got %v", where, body, row)
	}
}

// docs/e2e-messaging-contract.md "Key Loss And Rotation": losing an archived
// key makes only the messages wrapped to it unrecoverable. Listings keep that
// row as an undecryptable placeholder and go on; exact reads still fail.
func TestRealServerListingsKeepUndecryptableRows(t *testing.T) {
	world := newRealCommandWorld(t)
	alice, bob, carol := world.addLocalMember(t, "alice"), world.addLocalMember(t, "bob"), world.addLocalMember(t, "carol")

	plain := decodeJSONObject(t, world.requireCommand(t, alice.Home, "mail", "send", "--to", "bob", "--subject", "plain-neighbour", "--body", "readable plaintext"))["message_id"].(string)
	sealed := world.sendE2EEMail(t, alice, "bob", "sealed-to-first-key", "lost with the first key")
	sealedConversation := world.requireReadableMail(t, alice, sealed, "lost with the first key").ConversationID
	world.requireCommand(t, carol.Home, "chat", "send-and-leave", "bob", "carol chat lost with the first key", "--start-conversation", "--e2ee")
	aliceChat := decodeJSONObject(t, world.requireCommand(t, alice.Home, "chat", "send-and-leave", "bob", "alice chat lost with the first key", "--start-conversation", "--e2ee"))
	aliceSession := aliceChat["session_id"].(string)

	state, first := activeEncryptionAssertion(t, bob)
	firstRecord := state.RecordForKeyID(first.EncryptionKeyID)
	rotated := rotateEncryptionKey(t, world, bob)
	followUp := decodeJSONObject(t, world.requireCommand(t, alice.Home, "mail", "send", "--conversation-id", sealedConversation, "--body", "readable after rotation"))["message_id"].(string)
	if wraps := deliveryWrapKeyIDs(world.requireReadableMail(t, bob, followUp, "readable after rotation")); len(wraps) != 1 || wraps[0] != rotated.KeyID {
		t.Fatalf("follow-up wrapped to %v, want the rotated key %s", wraps, rotated.KeyID)
	}
	world.requireCommand(t, alice.Home, "chat", "send-and-leave", "bob", "alice chat readable after rotation")

	// The archived key is lost: only what was wrapped to it is unrecoverable.
	firstPrivateKey, err := resolveIdentityStoredPath(filepath.Dir(bob.Home), bob.Home, firstRecord.PrivateKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(firstPrivateKey); err != nil {
		t.Fatal(err)
	}

	// Exact content reads stay typed nonzero failures.
	world.requireLostKeyRefusal(t, bob, "exact mail read", "mail", "show", "--message-id", sealed)

	// Chat pending: the preview is blank with its own error; the listing goes on.
	pending := jsonRows(t, world.requireCommand(t, bob.Home, "chat", "pending"), "pending")
	var carolPending, alicePending map[string]any
	for _, row := range pending {
		if row["session_id"] == aliceSession {
			alicePending = row
		} else {
			carolPending = row
		}
	}
	if carolPending == nil || carolPending["last_message"] != "" || carolPending["last_decrypt_error"] != "encryption_key_missing" {
		t.Fatalf("pending preview of a lost-key chat: %v", pending)
	}
	if alicePending == nil || alicePending["last_message"] != "alice chat readable after rotation" || alicePending["last_decrypt_error"] != nil {
		t.Fatalf("pending preview of a readable chat: %v", pending)
	}

	// Chat history: the unreadable row keeps its place before the readable one.
	history := jsonRows(t, world.requireCommand(t, bob.Home, "chat", "history", "alice"), "messages")
	if len(history) != 2 {
		t.Fatalf("chat history rows: %v", history)
	}
	requirePlaceholderRow(t, "chat history", history[0], "encryption_key_missing")
	requireReadableRow(t, "chat history", history[1], "alice chat readable after rotation")
	world.requireLostKeyRefusal(t, bob, "exact chat read", "chat", "history", "--session-id", aliceSession, "--message-id", history[0]["message_id"].(string))

	// Conversation view: oldest first, the unreadable row before its readable neighbour.
	conversation := jsonRows(t, world.requireCommand(t, bob.Home, "mail", "show", "--conversation-id", sealedConversation), "messages")
	if len(conversation) != 2 || conversation[0]["message_id"] != sealed || conversation[1]["message_id"] != followUp {
		t.Fatalf("conversation rows: %v", conversation)
	}
	requirePlaceholderRow(t, "conversation", conversation[0], "encryption_key_missing")
	requireReadableRow(t, "conversation", conversation[1], "readable after rotation")

	// Text inbox marks the row and exits 0 (and acknowledges only readable rows).
	text, err := world.runTextInIdentityHome(bob.Home, "mail", "inbox")
	if err != nil || !strings.Contains(text, "[undecryptable: encryption_key_missing]") || !strings.Contains(text, "readable plaintext") || !strings.Contains(text, "readable after rotation") {
		t.Fatalf("text inbox: err=%v\n%s", err, text)
	}
	unread := jsonRows(t, world.requireCommand(t, bob.Home, "mail", "inbox"), "messages")
	if len(unread) != 1 || unread[0]["message_id"] != sealed {
		t.Fatalf("after presentation only the placeholder stays unread: %v", unread)
	}
	requirePlaceholderRow(t, "unread inbox", unread[0], "encryption_key_missing")

	// The full listing keeps every row; the unreadable one sorts before an older readable one.
	all := jsonRows(t, world.requireCommand(t, bob.Home, "mail", "inbox", "--show-all"), "messages")
	sealedAt, plainAt, followUpAt := rowIndex(all, "message_id", sealed), rowIndex(all, "message_id", plain), rowIndex(all, "message_id", followUp)
	if sealedAt < 0 || plainAt < 0 || followUpAt < 0 || sealedAt > plainAt {
		t.Fatalf("show-all rows: %v", all)
	}
	requirePlaceholderRow(t, "show-all", all[sealedAt], "encryption_key_missing")
	requireReadableRow(t, "show-all", all[plainAt], "readable plaintext")

	// A placeholder supplies no reply target, and a follow-up on its conversation refuses.
	world.requireLostKeyRefusal(t, bob, "reply", "mail", "reply", sealed, "--body", "must not send")
	world.requireLostKeyRefusal(t, bob, "follow-up", "mail", "send", "--conversation-id", sealedConversation, "--body", "must not send")
	if strings.Contains(world.requireCommand(t, alice.Home, "mail", "inbox", "--show-all"), "must not send") {
		t.Fatal("a refused reply was delivered")
	}

	// Explicit acknowledgement stays available for the placeholder.
	world.requireCommand(t, bob.Home, "mail", "ack", sealed)
	if unread := jsonRows(t, world.requireCommand(t, bob.Home, "mail", "inbox"), "messages"); len(unread) != 0 {
		t.Fatalf("explicitly acknowledged placeholder is still unread: %v", unread)
	}
}
