package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"testing"
)

func TestCanonicalJSONInterop(t *testing.T) {
	t.Parallel()

	const seedHex = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	const wantDID = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
	const wantCanonical = `{"array":[true,false,null,"","<>&","café",7,1.5,{"emoji":"snowman ☃","html":"<tag>&"}],"boolean":true,"empty":"","integer":42,"nested":{"alpha":"A","html":"<>&","list":[0,{"inner":"βeta"},[]],"unicode":"café ☕","zero_float":0.25},"null":null,"number":3.5,"object":{"a":1,"b":false,"c":["x",""],"z":"终"},"unicode":"Iñtërnâtiônàlizætiøn & <xml>"}`
	const wantSignature = "Y8jC4K4+REcU/xYlO3RQ3FJnKOqusMCGaqGS8BbcQIrrhzZ+M7smKzP4WptEwkThrVAbAo0PN8SakdV9b33ZDw"

	seed, err := hex.DecodeString(seedHex)
	if err != nil {
		t.Fatalf("decode seed hex: %v", err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed length=%d want %d", len(seed), ed25519.SeedSize)
	}

	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)
	if got := ComputeDIDKey(pub); got != wantDID {
		t.Fatalf("did:key=%q want %q", got, wantDID)
	}

	value := map[string]any{
		"array": []any{
			true,
			false,
			nil,
			"",
			"<>&",
			"café",
			7,
			1.5,
			map[string]any{
				"emoji": "snowman ☃",
				"html":  "<tag>&",
			},
		},
		"boolean": true,
		"empty":   "",
		"integer": 42,
		"nested": map[string]any{
			"alpha": "A",
			"html":  "<>&",
			"list": []any{
				0,
				map[string]any{"inner": "βeta"},
				[]any{},
			},
			"unicode":    "café ☕",
			"zero_float": 0.25,
		},
		"null":   nil,
		"number": 3.5,
		"object": map[string]any{
			"a": 1,
			"b": false,
			"c": []any{"x", ""},
			"z": "终",
		},
		"unicode": "Iñtërnâtiônàlizætiøn & <xml>",
	}

	gotCanonical, err := CanonicalJSONValue(value)
	if err != nil {
		t.Fatalf("CanonicalJSONValue: %v", err)
	}
	if gotCanonical != wantCanonical {
		t.Fatalf("canonical JSON mismatch:\ngot:  %s\nwant: %s", gotCanonical, wantCanonical)
	}

	sig := ed25519.Sign(priv, []byte(gotCanonical))
	gotSignature := base64.RawStdEncoding.EncodeToString(sig)
	if gotSignature != wantSignature {
		t.Fatalf("signature mismatch:\ngot:  %s\nwant: %s", gotSignature, wantSignature)
	}
}
