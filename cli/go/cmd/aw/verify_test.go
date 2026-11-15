package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
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

func testMessageExport(t *testing.T, global bool) messageExport {
	t.Helper()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	envelope := &awid.MessageEnvelope{From: "sender", FromDID: awid.ComputeDIDKey(pub), To: "recipient", Type: "mail", Body: "original body", Timestamp: time.Now().UTC().Format(time.RFC3339)}
	if global {
		envelope.FromStableID = awid.ComputeStableID(pub)
	}
	signature, err := awid.SignMessage(key, envelope)
	if err != nil {
		t.Fatal(err)
	}
	return messageExport{V: 1, Type: "aweb.message-envelope", SignedPayload: awid.CanonicalJSON(envelope), Signature: signature, SigningKeyID: envelope.FromDID}
}

func TestVerifyExportedMessageAuthenticatesOriginalBytes(t *testing.T) {
	export := testMessageExport(t, false)
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
			e.SignedPayload = strings.Replace(e.SignedPayload, e.SigningKeyID, testMessageExport(t, false).SigningKeyID, 1)
		}},
		{"signature", func(e *messageExport) { e.Signature = "invalid" }},
		{"key selector", func(e *messageExport) { e.SigningKeyID = testMessageExport(t, false).SigningKeyID }},
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

func TestVerifyExportedMessageReservedEvidenceIsNeutral(t *testing.T) {
	export := testMessageExport(t, false)
	raw := marshalMessageExport(t, export)
	want := verifyExportedMessage(context.Background(), raw, whoOptions{})
	tampered := strings.Replace(string(raw), "original body", "tampered body", 1)
	wantTampered := verifyExportedMessage(context.Background(), []byte(tampered), whoOptions{})
	for _, evidence := range []string{
		`{"v":1,"links":[]}`,
		`{"v":999,"future":{"v":1}}`,
		`{"v":1,"identity_valid":true,"human_id":"did:aw:untrusted","grade":"certified_hardware"}`,
		`{"v":1,"v":2,"nested":{"signature":"first","signature":"last"}}`,
		`{"v":"malformed"}`,
		`null`, `[]`, `"opaque"`,
	} {
		t.Run(evidence, func(t *testing.T) {
			withEvidence := []byte(strings.TrimSuffix(string(raw), "}") + `,"evidence":` + evidence + `}`)
			got := verifyExportedMessage(context.Background(), withEvidence, whoOptions{})
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("reserved evidence changed verification: got %+v want %+v", got, want)
			}
			withTamper := []byte(strings.TrimSuffix(tampered, "}") + `,"evidence":` + evidence + `}`)
			if got := verifyExportedMessage(context.Background(), withTamper, whoOptions{}); !reflect.DeepEqual(got, wantTampered) {
				t.Fatalf("evidence changed invalid message result: got %+v want %+v", got, wantTampered)
			}
		})
	}
	for _, name := range []string{`"V"`, `"\u0076"`} {
		alias := strings.Replace(string(raw), `"v"`, name, 1)
		if got := verifyExportedMessage(context.Background(), []byte(alias), whoOptions{}); !reflect.DeepEqual(got, want) {
			t.Fatalf("rejected a unique decoded field: %+v", got)
		}
	}
	// Reserving evidence must not disable strictness for unrelated outer fields.
	unknown := []byte(strings.TrimSuffix(string(raw), "}") + `,"future":{}}`)
	if got := verifyExportedMessage(context.Background(), unknown, whoOptions{}); got.Reason != "malformed_envelope" {
		t.Fatalf("accepted unrelated outer field: %+v", got)
	}
}

func TestVerifyExportedMessageRejectsDuplicateOuterMembers(t *testing.T) {
	raw := marshalMessageExport(t, testMessageExport(t, false))
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	fields["id_chain"], fields["evidence"] = json.RawMessage(`null`), json.RawMessage(`{"v":1}`)
	for field, value := range fields {
		t.Run(field, func(t *testing.T) {
			key, _ := json.Marshal(field)
			// Identical values must also refuse, regardless of which value wins.
			duplicate := []byte(`{` + string(key) + `:` + string(value) + `,` + string(key) + `:` + string(value) + `,` + string(raw[1:]))
			if !json.Valid(duplicate) {
				t.Fatal("control must be syntactically valid JSON")
			}
			got := verifyExportedMessage(context.Background(), duplicate, whoOptions{})
			if got.Reason != "malformed_envelope" || got.IdentityValid == nil || *got.IdentityValid {
				t.Fatalf("accepted duplicate %s: %+v", field, got)
			}
		})
	}
	for _, prefix := range []string{
		`"v":2,`, // The later valid value currently hides this first value.
		`"\u0076":1,`,
		`"V":1,`, // encoding/json also accepts case-insensitive field aliases.
		`"TYPE":"aweb.message-envelope",`,
		`"\u017fignature":"invalid",`, // Unicode folding also aliases signature.
	} {
		t.Run(prefix, func(t *testing.T) {
			got := verifyExportedMessage(context.Background(), []byte(`{`+prefix+string(raw[1:])), whoOptions{})
			if got.Reason != "malformed_envelope" || got.IdentityValid == nil || *got.IdentityValid {
				t.Fatalf("duplicate decoded field accepted: %+v", got)
			}
		})
	}
}

func TestMessageExportPreservesOpaqueVersionedEvidence(t *testing.T) {
	raw := marshalMessageExport(t, testMessageExport(t, false))
	evidence := `{"v":999,"future":{"statement":"unchanged"}}`
	withEvidence := []byte(strings.TrimSuffix(string(raw), "}") + `,"evidence":` + evidence + `}`)
	var export messageExport
	if err := json.Unmarshal(withEvidence, &export); err != nil {
		t.Fatal(err)
	}
	var roundtrip map[string]json.RawMessage
	if err := json.Unmarshal(marshalMessageExport(t, export), &roundtrip); err != nil {
		t.Fatal(err)
	}
	if string(roundtrip["evidence"]) != evidence {
		t.Fatalf("lost reserved evidence: %s", roundtrip["evidence"])
	}
}

func TestExportMailEnvelopePreservesSignedBytesAndRefusesReconstruction(t *testing.T) {
	export := testMessageExport(t, false)
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
	export.Evidence = json.RawMessage(`{"v":999,"future":true}`)
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
	export := testMessageExport(t, false)
	raw := []byte(strings.TrimSuffix(string(marshalMessageExport(t, export)), "}") + `,"evidence":{"v":999}}`)
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
	invalid := export
	invalid.SignedPayload = strings.Replace(invalid.SignedPayload, "original body", "tampered body", 1)
	for _, tc := range []struct {
		name   string
		raw    []byte
		code   int
		reason string
	}{
		{"invalid", marshalMessageExport(t, invalid), 1, "message_signature_invalid"},
		{"malformed", []byte("{"), 1, "malformed_envelope"},
		{"duplicate outer field", []byte(`{"v":2,` + string(raw[1:])), 1, "malformed_envelope"},
		{"unavailable", marshalMessageExport(t, testMessageExport(t, true)), 2, "evidence_unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.CommandContext(ctx, bin, "verify", "--json", "--registry", "https://127.0.0.1:1")
			cmd.Dir, cmd.Stdin = t.TempDir(), strings.NewReader(string(tc.raw))
			cmd.Env = testCommandEnv(t.TempDir())
			// Port 1 is unreachable; no fake registry or DNS response is used.
			var stderr strings.Builder
			cmd.Stderr = &stderr
			output, err := cmd.Output()
			failure, ok := err.(*exec.ExitError)
			if !ok || failure.ExitCode() != tc.code {
				t.Fatalf("exit err=%v want=%d stdout=%s stderr=%s", err, tc.code, output, stderr.String())
			}
			var result whoOutput
			if json.Unmarshal(output, &result) != nil || result.Reason != tc.reason {
				t.Fatalf("one JSON result expected: %s", output)
			}
		})
	}
}
