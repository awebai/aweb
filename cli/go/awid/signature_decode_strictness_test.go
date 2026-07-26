package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
)

// VerifyMessage and VerifySignedPayload decode the signature with
// RawStdEncoding, which rejects the padded input StdEncoding accepts.
// ed25519.Verify returns false rather than erroring on garbage, so a status of
// Failed on its own cannot distinguish "the decoder rejected the signature"
// from "the signature decoded and did not verify" — both are Failed. These
// tests discriminate the two by the returned error: only the decode path
// returns a base64.CorruptInputError, and a verifier rejection returns Failed
// with a nil error (TestSignatureVerifierRejectionCarriesNoError pins that
// half). Each padded-signature test also asserts the unpadded signature
// verifies, so the fixture is known to be a signature a lenient decoder would
// accept and the decode branch is known to be reached.

func signedTestEnvelope(t *testing.T) (*MessageEnvelope, string, string) {
	t.Helper()

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
	env.SigningKeyID = did
	return env, sig, did
}

func requireCorruptInput(t *testing.T, err error) {
	t.Helper()

	if err == nil {
		t.Fatal("err=nil, want a base64 decode error: the signature reached the verifier instead of being rejected at decode")
	}
	var corrupt base64.CorruptInputError
	if !errors.As(err, &corrupt) {
		t.Fatalf("err=%v, want a base64.CorruptInputError: rejection did not come from the signature decoder", err)
	}
}

func TestVerifyMessageRejectsPaddedSignatureAtDecode(t *testing.T) {
	t.Parallel()

	env, sig, _ := signedTestEnvelope(t)

	env.Signature = sig + "=="
	status, err := VerifyMessage(env)
	if status != Failed {
		t.Fatalf("padded signature: status=%q, want %q", status, Failed)
	}
	requireCorruptInput(t, err)

	env.Signature = sig
	if status, err := VerifyMessage(env); status != Verified || err != nil {
		t.Fatalf("unpadded signature: status=%q err=%v, want %q with no error", status, err, Verified)
	}
}

func TestVerifySignedPayloadRejectsPaddedSignatureAtDecode(t *testing.T) {
	t.Parallel()

	env, sig, did := signedTestEnvelope(t)
	payload := CanonicalJSON(env)

	status, err := VerifySignedPayload(payload, sig+"==", did, did)
	if status != Failed {
		t.Fatalf("padded signature: status=%q, want %q", status, Failed)
	}
	requireCorruptInput(t, err)

	if status, err := VerifySignedPayload(payload, sig, did, did); status != Verified || err != nil {
		t.Fatalf("unpadded signature: status=%q err=%v, want %q with no error", status, err, Verified)
	}
}

// A signature that decodes cleanly but does not verify must return Failed with
// a nil error. Without this, the decode tests above could not treat a non-nil
// error as evidence that the verifier was never reached.
func TestSignatureVerifierRejectionCarriesNoError(t *testing.T) {
	t.Parallel()

	env, sig, did := signedTestEnvelope(t)
	payload := CanonicalJSON(env)
	env.Signature = sig
	env.Body = "tampered body"

	status, err := VerifyMessage(env)
	if status != Failed {
		t.Fatalf("VerifyMessage status=%q, want %q", status, Failed)
	}
	if err != nil {
		t.Fatalf("VerifyMessage err=%v, want nil for a crypto rejection", err)
	}

	status, err = VerifySignedPayload(payload+" ", sig, did, did)
	if status != Failed {
		t.Fatalf("VerifySignedPayload status=%q, want %q", status, Failed)
	}
	if err != nil {
		t.Fatalf("VerifySignedPayload err=%v, want nil for a crypto rejection", err)
	}
}
