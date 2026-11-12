package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// signedReceipt is a protected service's committed result: the owner act it
// signed for intent with key, as the receipt carries it.
func signedReceipt(t *testing.T, key ed25519.PrivateKey, act, teamID, audience string, subject map[string]any, now time.Time) json.RawMessage {
	t.Helper()
	fields, err := newOwnerAct(act, teamID, audience, key, subject, now)
	if err != nil {
		t.Fatal(err)
	}
	signing, signature, err := awid.SignOwnerAct(key, fields)
	if err != nil {
		t.Fatal(err)
	}
	result, _ := json.Marshal(map[string]any{"signing": base64.StdEncoding.EncodeToString(signing), "signature": signature})
	return result
}

func deliveryWorld(t *testing.T) (ed25519.PrivateKey, string, map[string]any) {
	t.Helper()
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	scope := map[string]any{"v": 1, "kind": "protected_key", "service_id": "svc",
		"authority": map[string]any{"kind": "team_controller", "id": "h:example.com", "domain": "example.com"},
		"human":     map[string]any{"id": "did:aw:approver", "domain": "example.com"}, "generation": 1}
	subject := map[string]any{"app_id": "example", "installation_id": "11111111-1111-4111-8111-111111111111", "role": "example.owner", "principal": "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn"}
	intent := protectedRoleIntent("human-role.revoke", scope, "https://app.example.com", subject)
	return key, awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)), intent
}

func TestACommittedActIsTheSignedActAwRequested(t *testing.T) {
	key, authority, intent := deliveryWorld(t)
	now := time.Now()
	result := signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", intent["subject"].(map[string]any), now)
	signed, err := signedActFor(intent, authority, result, now)
	if err != nil {
		t.Fatal(err)
	}
	var sent map[string]string
	_ = json.Unmarshal(result, &sent)
	if signed.Act != "human-role.revoke" || signed.Audience != "https://app.example.com" || signed.Signature != sent["signature"] {
		t.Fatalf("%+v", signed)
	}
	if want, _ := base64.StdEncoding.DecodeString(sent["signing"]); !bytes.Equal(signed.Signing, want) {
		t.Fatal("the signing bytes changed")
	}
}

func TestASignedActThatIsNotWhatAwRequestedIsNeverDelivered(t *testing.T) {
	key, authority, intent := deliveryWorld(t)
	_, other, _ := awid.GenerateKeypair()
	subject := intent["subject"].(map[string]any)
	otherSubject := map[string]any{"app_id": "example", "installation_id": "11111111-1111-4111-8111-111111111111", "role": "example.owner", "principal": "did:aw:2bLT57MhWjqFm6m4r43K3i8wPZb4"}
	designated := map[string]any{"credential_sha256": strings.Repeat("ab", 32)}
	for k, v := range subject {
		designated[k] = v
	}
	now := time.Now()
	for name, result := range map[string]json.RawMessage{
		"other subject":  signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", otherSubject, now),
		"other audience": signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://evil.example.com", subject, now),
		"other act":      signedReceipt(t, key, "human-role.designate", "h:example.com", "https://app.example.com", designated, now),
		"other team":     signedReceipt(t, key, "human-role.revoke", "x:example.com", "https://app.example.com", subject, now),
		"other key":      signedReceipt(t, other, "human-role.revoke", "h:example.com", "https://app.example.com", subject, now),
		"expired":        signedReceipt(t, key, "human-role.revoke", "h:example.com", "https://app.example.com", subject, now.Add(-time.Hour)),
		"extra member":   json.RawMessage(`{"signing":"AA==","signature":"AA","extra":1}`),
		"duplicate":      json.RawMessage(`{"signing":"AA==","signing":"AA==","signature":"AA"}`),
		"not base64":     json.RawMessage(`{"signing":"%%%","signature":"AA"}`),
		"no signature":   json.RawMessage(`{"signing":"AA=="}`),
		"null":           json.RawMessage(`null`),
	} {
		if _, err := signedActFor(intent, authority, result, now); errorCodeOf(err) != "signed_act_invalid" {
			t.Errorf("%s: %v", name, err)
		}
	}
}
