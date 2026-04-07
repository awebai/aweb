package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"
)

func TestSignVerifyRoundtrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	// Signature should be valid base64 no-padding.
	if _, err := base64.RawStdEncoding.DecodeString(sig); err != nil {
		t.Fatalf("signature is not valid base64 no-padding: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
}

func TestSignVerifyWithStableIDs(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:         "mycompany/researcher",
		FromDID:      did,
		To:           "otherco/monitor",
		ToDID:        "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:         "mail",
		Subject:      "task complete",
		Body:         "results attached",
		Timestamp:    "2026-02-21T15:30:00Z",
		FromStableID: "did:aw:Qm9iJ3x",
		ToStableID:   "did:aw:Qm9iJ3y",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}
}

func TestVerifyTamperedBody(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did
	env.Body = "tampered body"

	status, _ := VerifyMessage(env)
	if status != Failed {
		t.Fatalf("status=%q, want %q", status, Failed)
	}
}

func TestVerifyMissingDID(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		To:        "otherco/monitor",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Unverified {
		t.Fatalf("status=%q, want %q", status, Unverified)
	}
}

func TestVerifyMissingSignature(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK",
		To:        "otherco/monitor",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Unverified {
		t.Fatalf("status=%q, want %q", status, Unverified)
	}
}

func TestVerifyBadDIDFormat(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   "not-a-did",
		To:        "otherco/monitor",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
		Signature: "AAAA",
	}

	status, _ := VerifyMessage(env)
	// SOT §7 step 2: invalid DID format → Unverified (not Failed).
	// A DID that isn't did:key is treated like a missing identity, not a security failure.
	if status != Unverified {
		t.Fatalf("status=%q, want %q", status, Unverified)
	}
}

func TestVerifySigningKeyIDMismatch(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Body:      "hello",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP" // different DID

	status, err := VerifyMessage(env)
	if status != Failed {
		t.Fatalf("status=%q, want %q", status, Failed)
	}
	if err == nil {
		t.Fatal("expected error for signing_key_id mismatch")
	}
}

func TestCanonicalJSONFieldOrder(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   "did:key:z6MkhaXgBZD...",
		To:        "otherco/monitor",
		ToDID:     "did:key:z6MkrT4Jxd...",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
	}

	got := CanonicalJSON(env)
	want := `{"body":"results attached","from":"mycompany/researcher","from_did":"did:key:z6MkhaXgBZD...","subject":"task complete","timestamp":"2026-02-21T15:30:00Z","to":"otherco/monitor","to_did":"did:key:z6MkrT4Jxd...","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONWithStableIDs(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:         "a/b",
		FromDID:      "did:key:z6Mk...",
		To:           "c/d",
		ToDID:        "did:key:z6Mr...",
		Type:         "chat",
		Subject:      "",
		Body:         "hi",
		Timestamp:    "2026-01-01T00:00:00Z",
		FromStableID: "did:aw:abc",
		ToStableID:   "did:aw:def",
	}

	got := CanonicalJSON(env)
	want := `{"body":"hi","from":"a/b","from_did":"did:key:z6Mk...","from_stable_id":"did:aw:abc","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:z6Mr...","to_stable_id":"did:aw:def","type":"chat"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestSignVerifyWithMessageID(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	did := ComputeDIDKey(pub)

	env := &MessageEnvelope{
		From:      "mycompany/researcher",
		FromDID:   did,
		To:        "otherco/monitor",
		ToDID:     "did:key:z6Mkf5rGMoatrSj1f4CyvuHBeXJELe9RPdzo2PKGNCKVtZxP",
		Type:      "mail",
		Subject:   "task complete",
		Body:      "results attached",
		Timestamp: "2026-02-21T15:30:00Z",
		MessageID: "550e8400-e29b-41d4-a716-446655440000",
	}

	sig, err := SignMessage(priv, env)
	if err != nil {
		t.Fatalf("SignMessage: %v", err)
	}

	env.Signature = sig
	env.SigningKeyID = did

	status, err := VerifyMessage(env)
	if err != nil {
		t.Fatalf("VerifyMessage: %v", err)
	}
	if status != Verified {
		t.Fatalf("status=%q, want %q", status, Verified)
	}

	// Tampering with message_id should break verification.
	env.MessageID = "tampered-id"
	status, _ = VerifyMessage(env)
	if status != Failed {
		t.Fatalf("tampered message_id: status=%q, want %q", status, Failed)
	}
}

func TestCanonicalJSONWithMessageID(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "a/b",
		FromDID:   "did:key:z6Mk...",
		To:        "c/d",
		ToDID:     "did:key:z6Mr...",
		Type:      "mail",
		Subject:   "",
		Body:      "hi",
		Timestamp: "2026-01-01T00:00:00Z",
		MessageID: "test-uuid-1234",
	}

	got := CanonicalJSON(env)
	want := `{"body":"hi","from":"a/b","from_did":"did:key:z6Mk...","message_id":"test-uuid-1234","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:z6Mr...","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONWithoutMessageID(t *testing.T) {
	t.Parallel()

	// Existing messages without message_id should produce unchanged canonical JSON.
	env := &MessageEnvelope{
		From:      "a/b",
		FromDID:   "did:key:z6Mk...",
		To:        "c/d",
		ToDID:     "did:key:z6Mr...",
		Type:      "mail",
		Subject:   "",
		Body:      "hi",
		Timestamp: "2026-01-01T00:00:00Z",
	}

	got := CanonicalJSON(env)
	want := `{"body":"hi","from":"a/b","from_did":"did:key:z6Mk...","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:z6Mr...","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONEscaping(t *testing.T) {
	t.Parallel()

	env := &MessageEnvelope{
		From:      "a/b",
		FromDID:   "did:key:z",
		To:        "c/d",
		ToDID:     "did:key:y",
		Type:      "mail",
		Subject:   "",
		Body:      "hello \"world\"\nline2",
		Timestamp: "2026-01-01T00:00:00Z",
	}

	got := CanonicalJSON(env)
	want := `{"body":"hello \"world\"\nline2","from":"a/b","from_did":"did:key:z","subject":"","timestamp":"2026-01-01T00:00:00Z","to":"c/d","to_did":"did:key:y","type":"mail"}`

	if got != want {
		t.Fatalf("canonicalJSON:\ngot:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalReplacementJSONFieldOrder(t *testing.T) {
	t.Parallel()

	got := CanonicalReplacementJSON("acme.com/billing", "did:key:controller", "did:key:old", "did:key:new", "2026-03-22T10:00:00Z")
	want := `{"address":"acme.com/billing","controller_did":"did:key:controller","new_did":"did:key:new","old_did":"did:key:old","timestamp":"2026-03-22T10:00:00Z"}`
	if got != want {
		t.Fatalf("got:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONValueSortsKeys(t *testing.T) {
	t.Parallel()

	got, err := CanonicalJSONValue(map[string]any{
		"z": 1,
		"a": map[string]any{
			"b": true,
			"a": "x",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":{"a":"x","b":true},"z":1}`
	if got != want {
		t.Fatalf("got:  %s\nwant: %s", got, want)
	}
}

func TestCanonicalJSONValuePreservesUnicode(t *testing.T) {
	t.Parallel()

	got, err := CanonicalJSONValue(map[string]any{
		"greeting": "olá",
		"name":     "李雷",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"greeting":"olá","name":"李雷"}`
	if got != want {
		t.Fatalf("got:  %s\nwant: %s", got, want)
	}
}

// aweb-aafx.10: CanonicalJSONValue must NOT HTML-escape <, >, &.
//
// Go's json.Marshal HTML-escapes these three characters by default
// (\u003c, \u003e, \u0026) to be safe in script tags. Python's
// canonical_json_bytes (json.dumps with ensure_ascii=False) does NOT.
// For signatures to verify across the Go CLI and the Python awid/cloud
// verifiers, we must disable HTML escaping in the Go encoder so both
// sides produce byte-identical canonical JSON.
//
// This is the same latent bug that bit the cloud onboarding signing
// family (cli-signup, claim-human, bootstrap-redeem); fixed there in
// the shared cloudDIDKeySignPayload helper. aweb-aafx.10 carries the
// fix into this sibling code path (aw id sign / aw id request).
func TestCanonicalJSONValueDoesNotHTMLEscape(t *testing.T) {
	t.Parallel()

	got, err := CanonicalJSONValue(map[string]any{
		"note": "<foo&bar>",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := `{"note":"<foo&bar>"}`
	if got != want {
		t.Fatalf("HTML escape leaked:\n got: %s\nwant: %s", got, want)
	}
}

// Catches both the HTML-escape divergence AND the ASCII-escape
// divergence in one test vector, per dave's aafx.10 guidance. A payload
// carrying both <, >, & and non-ASCII must round-trip verbatim through
// CanonicalJSONValue. If Go ever picks up SetEscapeHTML(true) by
// accident, the <>& part of this test fails; if someone adds an
// ensure_ascii-style escaper, the café part fails.
func TestCanonicalJSONValueDoesNotEscapeHTMLOrNonASCII(t *testing.T) {
	t.Parallel()

	got, err := CanonicalJSONValue(map[string]any{
		"alias": "café-<dev>",
		"note":  "Tom&Jerry 测试",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Keys sorted: alias < note.
	want := `{"alias":"café-<dev>","note":"Tom&Jerry 测试"}`
	if got != want {
		t.Fatalf("escape leaked:\n got: %s\nwant: %s", got, want)
	}
}

func TestSignArbitraryPayloadRoundtrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	timestamp := "2026-04-05T10:30:00Z"
	didKey, signature, canonical, err := SignArbitraryPayload(priv, map[string]any{
		"domain":    "acme.com",
		"operation": "register",
	}, timestamp)
	if err != nil {
		t.Fatal(err)
	}
	if didKey != ComputeDIDKey(pub) {
		t.Fatalf("didKey=%q", didKey)
	}
	wantCanonical := `{"domain":"acme.com","operation":"register","timestamp":"2026-04-05T10:30:00Z"}`
	if canonical != wantCanonical {
		t.Fatalf("canonical=%s want %s", canonical, wantCanonical)
	}
	sigBytes, err := base64.RawStdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if !ed25519.Verify(pub, []byte(canonical), sigBytes) {
		t.Fatal("signature did not verify")
	}
}

func TestSignArbitraryPayloadRejectsTimestampField(t *testing.T) {
	t.Parallel()

	_, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	_, _, _, err = SignArbitraryPayload(priv, map[string]any{
		"timestamp": "2026-04-05T10:30:00Z",
	}, "2026-04-05T10:30:00Z")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestVerifyReplacementSignatureRoundtrip(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	address := "acme.com/billing"
	controllerDID := ComputeDIDKey(pub)
	oldDID := "did:key:z6MkOLD"
	newDID := "did:key:z6MkNEW"
	timestamp := "2026-03-22T10:00:00Z"

	payload := CanonicalReplacementJSON(address, controllerDID, oldDID, newDID, timestamp)
	sig := ed25519.Sign(priv, []byte(payload))
	sigB64 := base64.RawStdEncoding.EncodeToString(sig)

	ok, err := VerifyReplacementSignature(pub, address, controllerDID, oldDID, newDID, timestamp, sigB64)
	if err != nil {
		t.Fatal(err)
	}
	if !ok {
		t.Fatal("valid signature rejected")
	}
}

func TestVerifyReplacementSignatureTamperedPayload(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	controllerDID := ComputeDIDKey(pub)
	payload := CanonicalReplacementJSON("acme.com/billing", controllerDID, "did:key:old", "did:key:new", "2026-03-22T10:00:00Z")
	sig := ed25519.Sign(priv, []byte(payload))
	sigB64 := base64.RawStdEncoding.EncodeToString(sig)

	// Verify with wrong address
	ok, _ := VerifyReplacementSignature(pub, "evil.com/billing", controllerDID, "did:key:old", "did:key:new", "2026-03-22T10:00:00Z", sigB64)
	if ok {
		t.Fatal("tampered address should fail verification")
	}

	// Verify with wrong newDID
	ok, _ = VerifyReplacementSignature(pub, "acme.com/billing", controllerDID, "did:key:old", "did:key:EVIL", "2026-03-22T10:00:00Z", sigB64)
	if ok {
		t.Fatal("tampered new_did should fail verification")
	}
}

func TestVerifyReplacementSignatureBadBase64(t *testing.T) {
	t.Parallel()

	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}

	_, err = VerifyReplacementSignature(pub, "a", "b", "c", "d", "e", "not-base64!!!")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestIsTimestampFresh(t *testing.T) {
	t.Parallel()

	now := time.Now().UTC().Format(time.RFC3339)
	if !isTimestampFresh(now) {
		t.Fatal("current timestamp should be fresh")
	}

	old := time.Now().Add(-8 * 24 * time.Hour).UTC().Format(time.RFC3339)
	if isTimestampFresh(old) {
		t.Fatal("8-day-old timestamp should not be fresh")
	}

	if isTimestampFresh("not-a-timestamp") {
		t.Fatal("invalid timestamp should not be fresh")
	}

	if isTimestampFresh("") {
		t.Fatal("empty timestamp should not be fresh")
	}
}
