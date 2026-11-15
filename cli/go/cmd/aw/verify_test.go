package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func marshalMessageExport(t *testing.T, export messageExport) []byte {
	t.Helper()
	raw, err := json.Marshal(export)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func localMessageExport(t *testing.T) messageExport {
	t.Helper()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	envelope := &awid.MessageEnvelope{From: "sender", FromDID: awid.ComputeDIDKey(pub), To: "recipient", Type: "mail", Body: "original body", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	signature, err := awid.SignMessage(key, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return messageExport{V: 1, Type: "aweb.message-envelope", SignedPayload: awid.CanonicalJSON(envelope), Signature: signature, SigningKeyID: envelope.FromDID}
}

func TestVerifyExportedMessageAuthenticatesOriginalBytes(t *testing.T) {
	export := localMessageExport(t)
	result := verifyExportedMessage(context.Background(), marshalMessageExport(t, export), whoOptions{})
	if result.ID != export.SigningKeyID || result.Outcome != "unknown" || result.Reason != "legacy_no_chain" || result.IdentityValid != nil {
		t.Fatalf("chainless local author: %+v", result)
	}
	for _, change := range []struct {
		name string
		edit func(*messageExport)
	}{
		{"body", func(e *messageExport) {
			e.SignedPayload = strings.Replace(e.SignedPayload, "original body", "tampered body", 1)
		}},
		{"sender", func(e *messageExport) {
			e.SignedPayload = strings.Replace(e.SignedPayload, e.SigningKeyID, localMessageExport(t).SigningKeyID, 1)
		}},
		{"signature", func(e *messageExport) { e.Signature = "invalid" }},
		{"key selector", func(e *messageExport) { e.SigningKeyID = localMessageExport(t).SigningKeyID }},
		{"missing signature", func(e *messageExport) { e.Signature = "" }},
		{"malformed chain", func(e *messageExport) { e.IDChain = awid.ReceivedIDChain{"certificates": []any{}} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			altered := export
			change.edit(&altered)
			result := verifyExportedMessage(context.Background(), marshalMessageExport(t, altered), whoOptions{})
			if result.IdentityValid == nil || *result.IdentityValid || result.HumanID != nil || result.Kind != nil || len(result.Chain) != 0 {
				t.Fatalf("tamper granted authority: %+v", result)
			}
			if !strings.Contains(formatVerifiedMessage(result), "invalid") {
				t.Fatalf("invalid result not explicit: %s", formatVerifiedMessage(result))
			}
		})
	}
	for _, raw := range [][]byte{[]byte("null"), []byte("{}"), []byte("{"), append(marshalMessageExport(t, export), []byte(" {}")...)} {
		result := verifyExportedMessage(context.Background(), raw, whoOptions{})
		if result.Reason != "malformed_envelope" || result.IdentityValid == nil || *result.IdentityValid {
			t.Fatalf("malformed export: %+v", result)
		}
	}
}

func TestExportMailEnvelopePreservesSignedBytesAndRefusesReconstruction(t *testing.T) {
	export := localMessageExport(t)
	message := awid.InboxMessage{MessageID: "exact", SignedPayload: export.SignedPayload, Signature: export.Signature, SigningKeyID: export.SigningKeyID,
		FromDID: "untrusted server projection", Body: "not the signed body", VerificationStatus: awid.Verified}
	got, err := exportMailEnvelope([]awid.InboxMessage{message}, "exact")
	if err != nil || got.SignedPayload != export.SignedPayload || got.Signature != export.Signature {
		t.Fatalf("got %+v err %v", got, err)
	}
	result := verifyExportedMessage(context.Background(), marshalMessageExport(t, got), whoOptions{})
	if result.ID != export.SigningKeyID || result.Reason != "legacy_no_chain" {
		t.Fatalf("trusted display projection: %+v", result)
	}
	for _, messages := range [][]awid.InboxMessage{nil, {message, message}, {{MessageID: "other"}}, {{MessageID: "exact", Body: "unsigned"}}} {
		if _, err := exportMailEnvelope(messages, "exact"); err == nil {
			t.Fatalf("export reconstructed or substituted: %+v", messages)
		}
	}
}

func TestVerifyEncryptedExportNeedsNoDecryptionKey(t *testing.T) {
	makeKey := func() (ed25519.PrivateKey, string, *awid.EncryptionKeyAssertion) {
		pub, key, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		_, xpub, err := awid.GenerateX25519Keypair()
		if err != nil {
			t.Fatal(err)
		}
		did := awid.ComputeDIDKey(pub)
		assertion, err := awid.BuildEncryptionKeyAssertion(key, did, "", xpub, "", time.Now())
		if err != nil {
			t.Fatal(err)
		}
		return key, did, assertion
	}
	key, sender, assertion := makeKey()
	_, recipient, recipientAssertion := makeKey()
	encrypted, err := awid.EncryptE2EEMail(awid.E2EEEncryptMailParams{
		Sender:     awid.E2EESenderKey{DID: sender, SigningKey: key, EncryptionKey: assertion},
		Recipients: []awid.E2EERecipientKey{{DID: recipient, EncryptionKey: recipientAssertion}},
		MessageID:  "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", Body: "secret", CreatedAt: time.Now(),
	})
	if err != nil {
		t.Fatal(err)
	}
	export, err := exportMailEnvelope([]awid.InboxMessage{{MessageID: encrypted.MessageID, Encrypted: encrypted, Body: "decrypted text"}}, encrypted.MessageID)
	if err != nil {
		t.Fatal(err)
	}
	raw := marshalMessageExport(t, export)
	if strings.Contains(string(raw), "secret") || strings.Contains(string(raw), "decrypted text") {
		t.Fatal("export contains plaintext")
	}
	result := verifyExportedMessage(context.Background(), raw, whoOptions{})
	if result.ID != sender || result.Reason != "legacy_no_chain" {
		t.Fatalf("encrypted author: %+v", result)
	}
	encrypted.From.DID = recipient
	result = verifyExportedMessage(context.Background(), marshalMessageExport(t, export), whoOptions{})
	if result.IdentityValid == nil || *result.IdentityValid || result.Reason != "message_signature_invalid" {
		t.Fatalf("forged encrypted sender: %+v", result)
	}
}

func TestVerifyBinaryIgnoresIdentityStateAndReadsFileOrStdin(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	root := t.TempDir()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	export := localMessageExport(t)
	raw := marshalMessageExport(t, export)
	path := filepath.Join(root, "export.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, input := range []string{path, "-", ""} {
		home := t.TempDir()
		cwd := t.TempDir()
		args := []string{"--identity-home", "/nonexistent/export-verification-principal", "verify", "--json"}
		if input != "" {
			args = append(args, input)
		}
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Dir, cmd.Stdin = cwd, strings.NewReader(string(raw))
		cmd.Env = append(testCommandEnv(home), "AWEB_IDENTITY_HOME=/nonexistent/inherited-principal")
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("binary err=%v: %s", err, output)
		}
		var result whoOutput
		if err := json.Unmarshal(output, &result); err != nil || result.ID != export.SigningKeyID || result.Reason != "legacy_no_chain" {
			t.Fatalf("result %+v err=%v: %s", result, err, output)
		}
		for _, dir := range []string{home, cwd} {
			entries, err := os.ReadDir(dir)
			if err != nil || len(entries) != 0 {
				t.Fatalf("verification wrote state: %s %v %v", dir, entries, err)
			}
		}
	}
}
