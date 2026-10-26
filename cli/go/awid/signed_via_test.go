package awid

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

// These are the frozen P0 bytes, not a second copy of their grammar or vectors.
func TestSignedViaNativeFrozenBytes(t *testing.T) {
	data, err := os.ReadFile("../../../docs/vectors/human-channels-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Seed  string `json:"public_test_seed_hex"`
		Valid []struct {
			Name      string `json:"name"`
			Canonical string `json:"canonical"`
			Schema    string `json:"schema"`
		} `json:"valid"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(vectors.Seed)
	if err != nil {
		t.Fatal(err)
	}
	key := ed25519.NewKeyFromSeed(seed)
	for _, c := range vectors.Valid {
		if !strings.HasPrefix(c.Name, "NativePlaintext_") {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			var env MessageEnvelope
			if err := json.Unmarshal([]byte(c.Canonical), &env); err != nil {
				t.Fatal(err)
			}
			if got := CanonicalJSON(&env); got != c.Canonical {
				t.Fatalf("signed bytes lost content: got %s; want %s", got, c.Canonical)
			}
			sig, err := SignMessage(key, &env)
			if err != nil {
				t.Fatal(err)
			}
			env.Signature = sig
			if status, err := VerifyMessage(&env); err != nil || status != Verified {
				t.Fatalf("signature did not verify: %s %v", status, err)
			}
			env.Via = "changed_kind"
			if status, _ := VerifyMessage(&env); status != Failed {
				t.Fatalf("changed via verified: %s", status)
			}
		})
	}
}

func TestSignedViaProgrammaticAPIs(t *testing.T) {
	alice, bob := newE2EETestIdentity(t, "example.com/alice"), newE2EETestIdentity(t, "example.com/bob")
	validParams := func(kind, via string) E2EEEncryptMessageParams {
		return E2EEEncryptMessageParams{
			Via: via, Kind: kind,
			Sender:     E2EESenderKey{Address: alice.address, DID: alice.did, StableID: alice.stableID, EncryptionKey: alice.assertion, SigningKey: alice.priv},
			Recipients: []E2EERecipientKey{{Address: bob.address, DID: bob.did, StableID: bob.stableID, EncryptionKey: bob.assertion}},
			Subject:    "subject", Body: "via body", MessageID: "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Date(2026, 5, 26, 12, 1, 0, 0, time.UTC),
		}
	}
	for _, via := range []string{"Telegram", "telegram:user", "telegram\n", strings.Repeat("a", 33)} {
		env := &MessageEnvelope{Via: via}
		if _, err := SignMessage(alice.priv, env); err == nil {
			t.Errorf("SignMessage signed malformed %q", via)
		}
		if _, err := EncryptE2EEMessage(validParams("mail", via)); err == nil {
			t.Errorf("EncryptE2EEMessage accepted malformed %q", via)
		}
	}
	for _, kind := range []string{"mail", "chat"} {
		for _, via := range []string{"", "telegram", "msteams", "future_chat"} {
			t.Run(kind+"/"+via, func(t *testing.T) {
				envelope, err := EncryptE2EEMessage(validParams(kind, via))
				if err != nil {
					t.Fatal(err)
				}
				for _, identity := range []e2eeTestIdentity{bob, alice} {
					plain, err := DecryptE2EEMessage(envelope, E2EEDecryptIdentity{Address: identity.address, DID: identity.did, StableID: identity.stableID, EncryptionKeyID: identity.assertion.EncryptionKeyID, PrivateKey: identity.xPriv})
					if err != nil {
						t.Fatal(err)
					}
					if plain.Via != via || plain.Body != "via body" {
						t.Fatalf("lost content: %#v", plain)
					}
					hash, _ := e2eeInnerHeaderHash(*plain)
					plain.Via = ""
					neighbor, _ := e2eeInnerHeaderHash(*plain)
					if hash != neighbor {
						t.Fatal("via changed inner header")
					}
				}
			})
		}
	}
}

func TestSignedViaExistingNativeReadersAndProducers(t *testing.T) {
	data, err := os.ReadFile("../../../docs/vectors/human-channels-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Seed  string `json:"public_test_seed_hex"`
		Valid []struct {
			Name, Canonical, Signature string
			Value                      map[string]any
		} `json:"valid"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	seed, _ := hex.DecodeString(vectors.Seed)
	key := ed25519.NewKeyFromSeed(seed)
	for _, c := range vectors.Valid {
		if !strings.HasPrefix(c.Name, "native_existing_") {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			did := c.Value["from_did"].(string)
			if status, err := VerifySignedPayload(c.Canonical, c.Signature, did, did); err != nil || status != Verified {
				t.Fatalf("frozen native reader: %s %v", status, err)
			}
			var env MessageEnvelope
			if err := json.Unmarshal([]byte(c.Canonical), &env); err != nil {
				t.Fatal(err)
			}
			sig, err := SignMessage(key, &env)
			if err != nil {
				t.Fatal(err)
			}
			env.Signature = sig
			if status, err := VerifyMessage(&env); err != nil || status != Verified {
				t.Fatalf("native producer: %s %v", status, err)
			}
			// Go's established optional empty-field omission is unchanged even
			// though the frozen Python/local-MCP neighbor retains that field.
			if env.ToStableID == "" && strings.Contains(CanonicalJSON(&env), `"to_stable_id"`) {
				t.Fatal("changed Go optional omission")
			}
		})
	}
}

func TestSignedViaInnerFrozenBytesAndHeader(t *testing.T) {
	data, err := os.ReadFile("../../../docs/vectors/human-channels-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Valid []struct {
			Name      string `json:"name"`
			Canonical string `json:"canonical"`
		} `json:"valid"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Valid {
		if !strings.HasPrefix(c.Name, "NativeV2Content_") {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			var inner E2EEInnerPayload
			if err := json.Unmarshal([]byte(c.Canonical), &inner); err != nil {
				t.Fatal(err)
			}
			got, err := e2eeInnerPayloadCanonical(inner)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.Canonical {
				t.Fatalf("inner content lost: got %s; want %s", got, c.Canonical)
			}
			var withoutVia map[string]any
			if err := json.Unmarshal([]byte(c.Canonical), &withoutVia); err != nil {
				t.Fatal(err)
			}
			delete(withoutVia, "via")
			raw, _ := json.Marshal(withoutVia)
			var neighbor E2EEInnerPayload
			if err := json.Unmarshal(raw, &neighbor); err != nil {
				t.Fatal(err)
			}
			a, _ := e2eeInnerHeaderHash(inner)
			b, _ := e2eeInnerHeaderHash(neighbor)
			if a != b {
				t.Fatal("via changed fixed inner header")
			}
		})
	}
}

func TestSignedViaMalformedWireRefused(t *testing.T) {
	for _, raw := range []string{`{"via":""}`, `{"via":null}`, `{"via":"Telegram"}`, `{"via":"telegram\n"}`, `{"via":{}}`} {
		var env MessageEnvelope
		if err := json.Unmarshal([]byte(raw), &env); err == nil {
			t.Errorf("native accepted %s", raw)
		}
		var inner E2EEInnerPayload
		if err := json.Unmarshal([]byte(raw), &inner); err == nil {
			t.Errorf("inner accepted %s", raw)
		}
	}
}
