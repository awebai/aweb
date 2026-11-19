package handoff

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// The exact bytes the app's verifier rebuilds (aweb_naapp.console.handoff_wire)
// for this request, as awid.signing.canonical_json_bytes spells them.
const sessionPayload = `{"aud":"https://secrets.example.com","auth":"handoff-session","body_sha256":"44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a","method":"POST","nonce":"00112233445566778899aabbccddeeff","path":"/installations/x/change-sets?a=1","session_id":"s1","timestamp":"2026-11-11T12:00:00Z","v":2}`

func testKey() ed25519.PrivateKey { return ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32)) }

func TestConsoleHeadersSignTheExactRequestBytes(t *testing.T) {
	key := testKey()
	headers, err := consoleHeaders(key, consoleRequest{
		Auth: "handoff-session", Audience: "https://secrets.example.com", Method: "post",
		Path: "/installations/x/change-sets?a=1", SubjectField: "session_id", Subject: "s1",
		Body: []byte("{}"), Timestamp: time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC),
		Nonce: "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := base64.RawURLEncoding.Strict().DecodeString(headers.Get("X-Console-Signed-Payload"))
	if err != nil || string(payload) != sessionPayload {
		t.Fatalf("payload %s err %v", payload, err)
	}
	if headers.Get("X-Console-Key") != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) {
		t.Fatalf("key %q", headers.Get("X-Console-Key"))
	}
	if headers.Get("X-Console-Timestamp") != "2026-11-11T12:00:00Z" {
		t.Fatalf("timestamp %q", headers.Get("X-Console-Timestamp"))
	}
	signature, err := base64.RawStdEncoding.Strict().DecodeString(headers.Get("X-Console-Signature"))
	if err != nil || !ed25519.Verify(key.Public().(ed25519.PublicKey), payload, signature) {
		t.Fatalf("signature %q err %v", headers.Get("X-Console-Signature"), err)
	}
	for name := range headers {
		if name != "X-Console-Key" && name != "X-Console-Signature" && name != "X-Console-Timestamp" && name != "X-Console-Signed-Payload" {
			t.Fatalf("extra header %s", name)
		}
	}
}

func TestAResultSignsTheHandoffIDUnderItsOwnAuth(t *testing.T) {
	headers, err := consoleHeaders(testKey(), consoleRequest{
		Auth: "handoff-result", Audience: "https://secrets.example.com", Method: "POST",
		Path: "/handoffs/h1/result", SubjectField: "handoff_id", Subject: "h1",
		Body: []byte("{}"), Timestamp: time.Now(), Nonce: "00112233445566778899aabbccddeeff",
	})
	if err != nil {
		t.Fatal(err)
	}
	payload, _ := base64.RawURLEncoding.DecodeString(headers.Get("X-Console-Signed-Payload"))
	if !bytes.Contains(payload, []byte(`"auth":"handoff-result"`)) || !bytes.Contains(payload, []byte(`"handoff_id":"h1"`)) || bytes.Contains(payload, []byte("session_id")) {
		t.Fatalf("payload %s", payload)
	}
}

func TestEveryRequestHasAFreshNonce(t *testing.T) {
	a, b := newNonce(), newNonce()
	if len(a) != 32 || a == b || a != string(bytes.ToLower([]byte(a))) {
		t.Fatalf("nonces %q %q", a, b)
	}
}
