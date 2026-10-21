package awid

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestHumanChannelsSharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/human-channels-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		PublicKey string `json:"public_test_key_hex"`
		Valid     []struct {
			Name, Schema, Canonical, SHA256, Signature string
			Value                                      json.RawMessage
		} `json:"valid"`
		Tampered []struct{ Name, JSON, Signature string }    `json:"tampered"`
		Invalid  []struct{ Name, Schema, JSON, Code string } `json:"invalid"`
	}
	if err = json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	pub, err := hex.DecodeString(vectors.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range vectors.Valid {
		t.Run(c.Name, func(t *testing.T) {
			record, err := DecodeHumanChannelsRecord(c.Schema, c.Value)
			if err != nil {
				t.Fatal(err)
			}
			canonical, err := record.Canonical()
			if err != nil {
				t.Fatal(err)
			}
			if string(canonical) != c.Canonical {
				t.Fatalf("canonical mismatch: %s", canonical)
			}
			digest := sha256.Sum256(canonical)
			if "sha256:"+hex.EncodeToString(digest[:]) != c.SHA256 {
				t.Fatal("hash mismatch")
			}
			sig, err := base64.RawStdEncoding.DecodeString(c.Signature)
			if err != nil {
				t.Fatal(err)
			}
			if !ed25519.Verify(pub, canonical, sig) {
				t.Fatal("signature mismatch")
			}
			if ed25519.Verify(pub, append(canonical, ' '), sig) {
				t.Fatal("tamper accepted")
			}
		})
	}
	for _, c := range vectors.Invalid {
		t.Run(c.Name, func(t *testing.T) {
			_, err := DecodeHumanChannelsRecord(c.Schema, []byte(c.JSON))
			var refusal *HumanChannelsContractError
			if !errors.As(err, &refusal) || refusal.Code != c.Code {
				t.Fatalf("got %v want %s", err, c.Code)
			}
		})
	}
}

func TestHumanChannelsCompiledProfile(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/human-channels-profile-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var want, got any
	if err = json.Unmarshal(raw, &want); err != nil {
		t.Fatal(err)
	}
	if err = json.Unmarshal([]byte(humanChannelsProfileJSON), &got); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(want)
	b, _ := json.Marshal(got)
	if string(a) != string(b) {
		t.Fatal("compiled schema differs from public profile")
	}
}

func TestHumanChannelsTamperAndFutureCapability(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/human-channels-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		PublicKey string `json:"public_test_key_hex"`
		Tampered  []struct{ Name, JSON, Signature string }
		Valid     []struct{ Name, Canonical string }
	}
	if err = json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	pub, _ := hex.DecodeString(v.PublicKey)
	for _, c := range v.Tampered {
		t.Run(c.Name, func(t *testing.T) {
			sig, _ := base64.RawStdEncoding.DecodeString(c.Signature)
			if ed25519.Verify(pub, []byte(c.JSON), sig) {
				t.Fatal("tamper accepted")
			}
		})
	}
	for _, c := range v.Valid {
		if c.Name == "future_advertised_capability" {
			r, err := DecodeHumanChannelsRecord("Capabilities", []byte(c.Canonical))
			if err != nil {
				t.Fatal(err)
			}
			if err = r.RequireCapability("signed-via-v1"); err != nil {
				t.Fatal(err)
			}
			for _, token := range []string{"future-v9", "managed-chat-encrypted-v1", "group-federation-v1"} {
				if err = r.RequireCapability(token); err == nil {
					t.Fatal("unsupported capability selected")
				}
			}
		}
	}
	for _, raw := range []string{`{} {}`, `{"kind":"native","did":"\ud800"}`, `[]`, `{"kind":"native","did":"did:aw:vector","version":{}}`} {
		if _, err := DecodeHumanChannelsRecord("NativeParticipant", []byte(raw)); err == nil {
			t.Fatal("invalid JSON accepted")
		}
	}
	r, _ := DecodeHumanChannelsRecord("NativeParticipant", []byte(`{"kind":"native","did":"did:aw:vector"}`))
	r.Value["external_account_id"] = "not-public"
	if _, err = r.Canonical(); err == nil {
		t.Fatal("mutation bypassed grammar")
	}
}
