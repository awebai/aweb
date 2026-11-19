package signaturewire_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/signaturewire"
)

func TestSharedPointEncodingComponents(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "signature-point-encoding-v2.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cases []struct {
			Name       string `json:"name"`
			EncodedHex string `json:"encoded_hex"`
			Canonical  *bool  `json:"canonical"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.Cases) == 0 {
		t.Fatal("component corpus is empty")
	}
	for _, c := range vector.Cases {
		t.Run(c.Name, func(t *testing.T) {
			encoded, err := hex.DecodeString(c.EncodedHex)
			if err != nil {
				t.Fatal(err)
			}
			if c.Canonical == nil {
				t.Fatal("component case has no expected canonical value")
			}
			if got := signaturewire.CanonicalPointEncoding(encoded); got != *c.Canonical {
				t.Fatalf("canonical encoding=%t, want %t", got, *c.Canonical)
			}
		})
	}
}
