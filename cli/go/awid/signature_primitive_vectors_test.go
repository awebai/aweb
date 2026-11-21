package awid

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/signaturewire"
)

func TestPublicSignaturePrimitiveVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "signature-primitives-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cases []struct {
			Name, Payload, Signature string
			DID                      string `json:"did_key"`
			Expected                 map[string]VerificationStatus
		}
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	for _, c := range vector.Cases {
		t.Run(c.Name, func(t *testing.T) {
			got, _ := VerifySignedPayload(c.Payload, c.Signature, c.DID, "")
			if got != c.Expected["go"] {
				t.Fatalf("got %s, want %s", got, c.Expected["go"])
			}
		})
	}
}

func TestPublicCanonicalURLCodecVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "signature-primitives-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cases []struct {
			Name, Text string
			Hex        *string
		} `json:"base64url_cases"`
	}
	if err = json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	for _, c := range vector.Cases {
		t.Run(c.Name, func(t *testing.T) {
			decoded, err := signaturewire.DecodeCanonicalURL(c.Text)
			if c.Hex == nil {
				if err == nil {
					t.Fatal("invalid encoding accepted")
				}
				return
			}
			if err != nil || hex.EncodeToString(decoded) != *c.Hex {
				t.Fatalf("decoded %x, error %v", decoded, err)
			}
		})
	}
}
