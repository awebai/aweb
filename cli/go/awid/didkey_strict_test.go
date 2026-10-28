package awid

// aweb-acmz: a did:key whose public key is small-order, non-canonical or
// mixed-order is refused at decode, so no released path can verify a
// signature under it or admit it. The keys are the frozen ID-profile cases.
import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type ed25519KeyCase struct {
	Name      string `json:"name"`
	PublicKey string `json:"public_key_hex"`
	Message   string `json:"message_hex"`
	Signature string `json:"signature_hex"`
}

// Key-level cases: the public key itself is not a canonical, non-identity,
// prime-subgroup point. Signature-side cases (R, S) are outside this rule.
var degenerateKeyCases = []string{
	"small-order-A-0", "small-order-A-1", "small-order-A-2", "small-order-A-3",
	"small-order-A-4", "small-order-A-5", "small-order-A-6", "small-order-A-7",
	"noncanonical-A-identity", "noncanonical-A-x0-sign-bit",
	"mixed-order-A-k-div-8", "mixed-order-A-k-not-div-8",
}

func loadEd25519KeyCases(t *testing.T) map[string]ed25519KeyCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "id-certificates-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		Ed25519 struct {
			Cases []ed25519KeyCase `json:"cases"`
		} `json:"ed25519_verification"`
	}
	if err := json.NewDecoder(bytes.NewReader(data)).Decode(&v); err != nil {
		t.Fatal(err)
	}
	cases := map[string]ed25519KeyCase{}
	for _, c := range v.Ed25519.Cases {
		cases[c.Name] = c
	}
	return cases
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestExtractPublicKeyRefusesDegenerateKeys(t *testing.T) {
	cases := loadEd25519KeyCases(t)
	for _, name := range degenerateKeyCases {
		c, ok := cases[name]
		if !ok {
			t.Fatalf("missing frozen case %s", name)
		}
		t.Run(name, func(t *testing.T) {
			did := ComputeDIDKey(ed25519.PublicKey(mustHex(t, c.PublicKey)))
			if key, err := ExtractPublicKey(did); err == nil {
				t.Fatalf("decoded %x", key)
			}
			payload := string(mustHex(t, c.Message))
			signature := base64.RawStdEncoding.EncodeToString(mustHex(t, c.Signature))
			if status, _ := VerifySignedPayload(payload, signature, did, ""); status == Verified {
				t.Fatal("a signature under a degenerate key verified")
			}
		})
	}
}

func TestExtractPublicKeyAcceptsAnOrdinaryKey(t *testing.T) {
	c := loadEd25519KeyCases(t)["control-root-signs-alice"]
	did := ComputeDIDKey(ed25519.PublicKey(mustHex(t, c.PublicKey)))
	if _, err := ExtractPublicKey(did); err != nil {
		t.Fatal(err)
	}
	payload := string(mustHex(t, c.Message))
	signature := base64.RawStdEncoding.EncodeToString(mustHex(t, c.Signature))
	if status, err := VerifySignedPayload(payload, signature, did, ""); status != Verified {
		t.Fatalf("status=%v err=%v", status, err)
	}
}
