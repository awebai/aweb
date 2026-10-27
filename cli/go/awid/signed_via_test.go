package awid

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

type viaCryptoIdentity struct {
	Address       string                  `json:"address"`
	DID           string                  `json:"did"`
	StableID      string                  `json:"stable_id"`
	TeamID        string                  `json:"team_id"`
	SeedHex       string                  `json:"seed_hex"`
	X25519Private string                  `json:"x25519_private"`
	EncryptionKey *EncryptionKeyAssertion `json:"encryption_key"`
}

type viaCryptoCase struct {
	Producer string              `json:"producer"`
	Kind     string              `json:"kind"`
	Via      string              `json:"via"`
	Envelope E2EEMessageEnvelope `json:"envelope"`
}

func TestSignedViaCrossLanguageCrypto(t *testing.T) {
	path := "../../../docs/vectors/human-channels-signed-via-crypto-v1.json"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Description string                       `json:"description"`
		Identities  map[string]viaCryptoIdentity `json:"identities"`
		Cases       []viaCryptoCase              `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	if os.Getenv("AW_GENERATE_SIGNED_VIA_CRYPTO") == "1" {
		for _, c := range fixture.Cases {
			if c.Producer == "go" {
				t.Fatal("refusing to refreeze existing Go vectors")
			}
		}
		alice, bob := fixture.Identities["alice"], fixture.Identities["bob"]
		seed, err := hex.DecodeString(alice.SeedHex)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range []string{"mail", "chat"} {
			for _, via := range []string{"", "telegram", "msteams"} {
				envelope, err := EncryptE2EEMessage(E2EEEncryptMessageParams{Kind: kind, Via: via,
					Sender:     E2EESenderKey{Address: alice.Address, DID: alice.DID, StableID: alice.StableID, TeamID: alice.TeamID, EncryptionKey: alice.EncryptionKey, SigningKey: ed25519.NewKeyFromSeed(seed)},
					Recipients: []E2EERecipientKey{{Address: bob.Address, DID: bob.DID, StableID: bob.StableID, TeamID: bob.TeamID, EncryptionKey: bob.EncryptionKey}},
					Subject:    "P1 subject", Body: "P1 public test body", MessageID: "11111111-1111-4111-8111-111111111111", ConversationID: "22222222-2222-4222-8222-222222222222", CreatedAt: time.Date(2026, 5, 27, 12, 0, 0, 0, time.UTC)})
				if err != nil {
					t.Fatal(err)
				}
				fixture.Cases = append(fixture.Cases, viaCryptoCase{Producer: "go", Kind: kind, Via: via, Envelope: *envelope})
			}
		}
		encoded, err := json.MarshalIndent(fixture, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(encoded, '\n'), 0644); err != nil {
			t.Fatal(err)
		}
	}
	if len(fixture.Cases) != 12 {
		t.Fatalf("want both producers x mail/chat x absent/telegram/msteams, got %d", len(fixture.Cases))
	}
	for _, c := range fixture.Cases {
		t.Run(c.Producer+"/"+c.Kind+"/"+c.Via, func(t *testing.T) {
			for _, alias := range []string{"bob", "alice"} {
				identity := fixture.Identities[alias]
				raw, err := base64.RawStdEncoding.DecodeString(identity.X25519Private)
				if err != nil {
					t.Fatal(err)
				}
				private, err := ecdh.X25519().NewPrivateKey(raw)
				if err != nil {
					t.Fatal(err)
				}
				plain, err := DecryptE2EEMessage(&c.Envelope, E2EEDecryptIdentity{Address: identity.Address, DID: identity.DID, StableID: identity.StableID, EncryptionKeyID: identity.EncryptionKey.EncryptionKeyID, PrivateKey: private})
				if err != nil {
					t.Fatal(err)
				}
				if plain.Via != c.Via || plain.Body != "P1 public test body" {
					t.Fatalf("lost authenticated content: %#v", plain)
				}
			}
		})
	}
}

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

func TestSignedViaPublishedCanonicalAgreement(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/human-channels-signed-via-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Seed  string `json:"public_test_seed_hex"`
		Cases []struct {
			Name        string          `json:"name"`
			Payload     MessageEnvelope `json:"payload"`
			SignedBytes string          `json:"signed_bytes"`
			Signature   string          `json:"signature"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(fixture.Seed)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range fixture.Cases {
		t.Run(c.Name, func(t *testing.T) {
			if CanonicalJSON(&c.Payload) != c.SignedBytes {
				t.Fatalf("canonical bytes differ: %s", CanonicalJSON(&c.Payload))
			}
			signature, err := SignMessage(ed25519.NewKeyFromSeed(seed), &c.Payload)
			if err != nil {
				t.Fatal(err)
			}
			if signature != c.Signature {
				t.Fatal("signature differs from published record")
			}
		})
	}
}
