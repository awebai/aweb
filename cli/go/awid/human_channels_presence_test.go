package awid

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
	"time"
)

func hcP8Map(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var v map[string]any
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}
func hcP8Record(t *testing.T, schema string, v any) HumanChannelsRecord {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	record, err := DecodeHumanChannelsRecord(schema, raw)
	if err != nil {
		t.Fatal(err)
	}
	return record
}
func hcP8Identity(v any) *HumanChannelsPresenceIdentity {
	if v == nil {
		return nil
	}
	m := v.(map[string]any)
	return &HumanChannelsPresenceIdentity{Principal: m["principal"].(string), SigningKeyID: m["signing_key_id"].(string), Active: m["active"].(bool)}
}
func hcP8Time(t *testing.T, v any) time.Time {
	t.Helper()
	if v == nil {
		return time.Time{}
	}
	n, err := time.Parse(time.RFC3339, v.(string))
	if err != nil {
		t.Fatal(err)
	}
	return n
}
func hcP8Strings(v any) []string {
	if v == nil {
		return nil
	}
	a := v.([]any)
	r := make([]string, len(a))
	for i, s := range a {
		r[i] = s.(string)
	}
	return r
}
func hcP8Context(t *testing.T, v map[string]any) HumanChannelsPresenceContext {
	t.Helper()
	raw, _ := json.Marshal(v["subject"])
	var subject HumanChannelsParticipant
	if err := json.Unmarshal(raw, &subject); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal(v["scope"])
	var scope HumanChannelsPresenceScope
	if err := json.Unmarshal(raw, &scope); err != nil {
		t.Fatal(err)
	}
	caller := v["caller"].(map[string]any)
	var grant *HumanChannelsPresenceGrant
	if caller["grant"] != nil {
		g := caller["grant"].(map[string]any)
		grant = &HumanChannelsPresenceGrant{Scopes: hcP8Strings(g["scopes"]), ExpiresAt: hcP8Time(t, g["expires_at"]), NeverExpires: g["never_expires"].(bool)}
	}
	var owner *HumanChannelsPresenceOwnershipPin
	if v["ownership_pin"] != nil {
		p := v["ownership_pin"].(map[string]any)
		raw, _ := json.Marshal(p["subject"])
		var subj HumanChannelsParticipant
		if err := json.Unmarshal(raw, &subj); err != nil {
			t.Fatal(err)
		}
		owner = &HumanChannelsPresenceOwnershipPin{Subject: subj, Audience: p["audience"].(string), Owner: hcP8Identity(p["owner"]), Issuer: hcP8Identity(p["issuer"]), AuthorizationRevision: p["authorization_revision"].(string)}
	}
	c := HumanChannelsPresenceContext{ExpectedIntentHash: v["expected_intent_hash"].(string), Subject: subject, SubjectActive: v["subject_active"].(bool), Platform: v["platform"].(string), Scope: scope, Mode: v["mode"].(string), Audience: v["audience"].(string), AuthorizationRevision: v["authorization_revision"].(string), SubjectIdentity: hcP8Identity(v["subject_identity"]), Caller: HumanChannelsPresenceCaller{Identity: hcP8Identity(caller["identity"]), ActionAuthorized: caller["action_authorized"].(bool), Grant: grant}, ExpectedGeneration: hcNumber(v["expected_generation"]), ConsumedRequestIDs: hcP8Strings(v["consumed_request_ids"]), Now: func() *time.Time { n := hcP8Time(t, v["now"]); return &n }(), MaxTTLSeconds: hcNumber(v["max_ttl_seconds"]), MaxClockSkewSeconds: hcNumber(v["max_clock_skew_seconds"]), OwnershipPin: owner, AllowScopedNative: v["allow_scoped_native"].(bool)}
	if digest, ok := v["binding_digest"].(string); ok {
		c.BindingDigest = digest
	}
	return c
}
func TestHumanChannelsPresenceSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/human-channels-presence-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	vectors := hcP8Map(t, raw)
	seeds := vectors["public_test_seeds"].(map[string]any)
	for _, category := range []string{"valid", "invalid"} {
		for _, entry := range vectors[category].([]any) {
			c := entry.(map[string]any)
			t.Run(c["name"].(string), func(t *testing.T) {
				inputRaw, _ := json.Marshal(c["artifact"])
				artifact, err := DecodeHumanChannelsRecord("SignedArtifact", inputRaw)
				var result HumanChannelsRecord
				if err == nil {
					context := hcP8Context(t, c["context"].(map[string]any))
					if c["family"] == "native" {
						result, err = VerifyHumanChannelsNativePresence(artifact, context)
					} else {
						result, err = VerifyHumanChannelsPresenceBinding(artifact, context)
					}
				}
				if category == "invalid" {
					var refusal *HumanChannelsContractError
					if !errors.As(err, &refusal) || refusal.Code != c["error"] {
						t.Fatalf("got %v want %s", err, c["error"])
					}
					return
				}
				if err != nil {
					t.Fatal(err)
				}
				expected := hcP8Record(t, result.Schema, c["expected"])
				if !reflect.DeepEqual(result.Value, expected.Value) {
					t.Fatalf("result differs: %#v", result.Value)
				}
				schema := "PresenceIntent"
				if c["family"] == "binding" {
					schema = "PresenceBindingIntent"
				}
				a := c["artifact"].(map[string]any)
				intent, err := DecodeHumanChannelsRecord(schema, []byte(a["signed_payload"].(string)))
				if err != nil {
					t.Fatal(err)
				}
				seed, err := hex.DecodeString(seeds[c["key"].(string)].(string))
				if err != nil {
					t.Fatal(err)
				}
				signed, err := SignHumanChannelsPresenceRecord(intent, ed25519.NewKeyFromSeed(seed))
				if err != nil || !reflect.DeepEqual(signed.Value, artifact.Value) {
					t.Fatalf("signing mismatch: %v", err)
				}
			})
		}
	}
}

// The Python host fixture supplies only a disposable signing identity. Go signs
// through the public library and calls the actual authenticated host endpoint.
func TestHumanChannelsPresenceLiveSigner(t *testing.T) {
	path := os.Getenv("AW_TEST_P8_SIGNER_INPUT")
	if path == "" {
		t.Skip("provided by the live host integration")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var input struct {
		URL       string          `json:"url"`
		Seed      string          `json:"seed"`
		DID       string          `json:"did"`
		StableID  string          `json:"stable_id"`
		Intent    json.RawMessage `json:"intent"`
		WrongSeed string          `json:"wrong_seed"`
		WrongDID  string          `json:"wrong_did"`
	}
	if err = json.Unmarshal(raw, &input); err != nil {
		t.Fatal(err)
	}
	seed, err := hex.DecodeString(input.Seed)
	if err != nil {
		t.Fatal(err)
	}
	intent, err := DecodeHumanChannelsRecord("PresenceIntent", input.Intent)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := SignHumanChannelsPresenceRecord(intent, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewWithIdentity(input.URL, ed25519.NewKeyFromSeed(seed), input.DID)
	if err != nil {
		t.Fatal(err)
	}
	client.stableID = input.StableID
	var result map[string]any
	if err = client.Do(context.Background(), "POST", "/__p8/native", artifact.Value, &result); err != nil {
		t.Fatal(err)
	}
	if result["version"] != "aweb-verified-presence-v1" || result["request_id"] != intent.Value["request_id"] {
		t.Fatal("unexpected verified descriptor")
	}
	wrongSeed, err := hex.DecodeString(input.WrongSeed)
	if err != nil {
		t.Fatal(err)
	}
	wrong, err := NewWithIdentity(input.URL, ed25519.NewKeyFromSeed(wrongSeed), input.WrongDID)
	if err != nil {
		t.Fatal(err)
	}
	if err = wrong.Do(context.Background(), "POST", "/__p8/native", artifact.Value, &result); err == nil {
		t.Fatal("unrelated authenticated caller accepted")
	} else if code, ok := HTTPStatusCode(err); !ok || code != 403 {
		t.Fatal(err)
	}
	intent.Value["expected_generation"] = json.Number("6")
	stale, err := SignHumanChannelsPresenceRecord(intent, ed25519.NewKeyFromSeed(seed))
	if err != nil {
		t.Fatal(err)
	}
	if err = client.Do(context.Background(), "POST", "/__p8/native", stale.Value, &result); err == nil {
		t.Fatal("freshly signed stale generation accepted")
	} else if code, ok := HTTPStatusCode(err); !ok || code != 409 {
		t.Fatal(err)
	}
}
