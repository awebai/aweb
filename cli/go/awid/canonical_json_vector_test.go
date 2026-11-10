package awid

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type canonicalJSONVectorCase struct {
	Name         string          `json:"name"`
	Value        json.RawMessage `json:"value"`
	CanonicalHex string          `json:"canonical_hex"`
}

// loadCanonicalJSONVector returns every case of the shared vector: the ones
// every implementation reproduces and the ones that depend on sorting keys by
// code point.
func loadCanonicalJSONVector(t *testing.T) []canonicalJSONVectorCase {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "..", "docs", "vectors", "canonical-json-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cases                  []canonicalJSONVectorCase `json:"cases"`
		CodePointKeyOrderCases []canonicalJSONVectorCase `json:"code_point_key_order_cases"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	cases := append(vector.Cases, vector.CodePointKeyOrderCases...)
	names := map[string]bool{}
	for _, c := range cases {
		names[c.Name] = true
	}
	for _, required := range []string{"line_separator_in_string", "paragraph_separator_in_string", "line_separator_in_key", "paragraph_separator_in_key"} {
		if !names[required] {
			t.Fatalf("shared vector has no case %q", required)
		}
	}
	return cases
}

func decodeCanonicalJSONVectorValue(t *testing.T, raw json.RawMessage) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	return value
}

func TestCanonicalJSONValueReproducesTheSharedVector(t *testing.T) {
	for _, c := range loadCanonicalJSONVector(t) {
		t.Run(c.Name, func(t *testing.T) {
			got, err := CanonicalJSONValue(decodeCanonicalJSONVectorValue(t, c.Value))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString([]byte(got)) != c.CanonicalHex {
				t.Fatalf("canonical bytes\n got %x\nwant %s", got, c.CanonicalHex)
			}
		})
	}
}

func TestStrictCanonicalJSONReproducesTheSharedVector(t *testing.T) {
	for _, c := range loadCanonicalJSONVector(t) {
		t.Run(c.Name, func(t *testing.T) {
			got, err := StrictCanonicalJSON(decodeCanonicalJSONVectorValue(t, c.Value))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != c.CanonicalHex {
				t.Fatalf("canonical bytes\n got %x\nwant %s", got, c.CanonicalHex)
			}
		})
	}
}

func TestIDCertificateCanonicalReproducesTheSharedVector(t *testing.T) {
	for _, c := range loadCanonicalJSONVector(t) {
		t.Run(c.Name, func(t *testing.T) {
			got, err := idCertificateCanonical(decodeCanonicalJSONVectorValue(t, c.Value))
			if err != nil {
				t.Fatal(err)
			}
			if hex.EncodeToString(got) != c.CanonicalHex {
				t.Fatalf("canonical bytes\n got %x\nwant %s", got, c.CanonicalHex)
			}
		})
	}
}

// Every string of the shared vector, written by the string encoder the
// hand-assembled payloads use (message envelopes, team certificates, identity
// log entries, rotation and replacement announcements, registry headers).
func TestMessageEnvelopeStringsReproduceTheSharedVector(t *testing.T) {
	for _, c := range loadCanonicalJSONVector(t) {
		object, ok := decodeCanonicalJSONVectorValue(t, c.Value).(map[string]any)
		if !ok {
			continue
		}
		text, ok := object["text"].(string)
		if !ok || len(object) != 1 {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			want, err := hex.DecodeString(c.CanonicalHex)
			if err != nil {
				t.Fatal(err)
			}
			// The vector's object is {"text":<string>}; the envelope field is "body".
			wantString := strings.TrimSuffix(strings.TrimPrefix(string(want), `{"text":`), `}`)
			got := CanonicalJSON(&MessageEnvelope{Body: text})
			wantEnvelope := `{"body":` + wantString + `,"from":"","from_did":"","subject":"","timestamp":"","to":"","to_did":"","type":""}`
			if got != wantEnvelope {
				t.Fatalf("envelope bytes\n got %x\nwant %x", got, wantEnvelope)
			}
		})
	}
}

// Free text holding the line and paragraph separators, on the signing paths
// that carry caller-supplied strings: each writes the separators as their
// UTF-8 bytes, as the Python reference does.
func TestSignedPayloadsWriteLineSeparatorsAsUTF8(t *testing.T) {
	lineSeparator, paragraphSeparator := string(rune(0x2028)), string(rune(0x2029))
	text := "line" + lineSeparator + "paragraph" + paragraphSeparator + "end <&>"
	// The same string as the reference writes it inside a JSON document.
	wantText := `"` + text + `"`
	emptyBodySHA256 := hex.EncodeToString(sha256.New().Sum(nil))
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))

	t.Run("message envelope", func(t *testing.T) {
		got := CanonicalJSON(&MessageEnvelope{Subject: text, Body: text})
		want := `{"body":` + wantText + `,"from":"","from_did":"","subject":` + wantText + `,"timestamp":"","to":"","to_did":"","type":""}`
		if got != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})

	t.Run("v2 request envelope", func(t *testing.T) {
		target, err := url.Parse("https://app.example/v1/things")
		if err != nil {
			t.Fatal(err)
		}
		_, _, got, err := SignRequestCredential(key, "post", target, "team_id", "backend:example.com", "2026-11-10T00:00:00Z", nil, map[string]any{"note": text})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"aud":"https://app.example","body_sha256":"` + emptyBodySHA256 + `","method":"POST","note":` + wantText +
			`,"path":"/v1/things","team_id":"backend:example.com","timestamp":"2026-11-10T00:00:00Z","v":2}`
		if got != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})

	t.Run("user-data signature", func(t *testing.T) {
		_, _, got, err := SignArbitraryPayload(key, map[string]any{"note": text}, "2026-11-10T00:00:00Z")
		if err != nil {
			t.Fatal(err)
		}
		want := `{"note":` + wantText + `,"timestamp":"2026-11-10T00:00:00Z"}`
		if got != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})

	t.Run("controller request", func(t *testing.T) {
		got, err := ControllerRequestPayload("https://registry.example", "post", "/v1/x", nil, "2026-11-10T00:00:00Z", "example.com", "op", map[string]any{"note": text})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"aud":"https://registry.example","body_sha256":"` + emptyBodySHA256 + `","domain":"example.com","method":"POST","note":` + wantText +
			`,"operation":"op","path":"/v1/x","timestamp":"2026-11-10T00:00:00Z","type":"aweb.awid-controller-request","v":2}`
		if string(got) != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})

	t.Run("onboarding request", func(t *testing.T) {
		got := onboardingDIDKeySignPayloadWithAudience("https://app.example", "post", "/v1/"+text, "2026-11-10T00:00:00Z", nil)
		want := `{"aud":"https://app.example","body_sha256":"` + emptyBodySHA256 + `","method":"POST","path":"/v1/` + text + `","timestamp":"2026-11-10T00:00:00Z"}`
		if string(got) != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})

	t.Run("encrypted message inner payload", func(t *testing.T) {
		got, err := e2eeInnerPayloadCanonical(E2EEInnerPayload{InnerVersion: 2, Kind: "mail", Subject: text, Body: text})
		if err != nil {
			t.Fatal(err)
		}
		want := `{"body":` + wantText + `,"conversation_id":"","created_at":"","from":{},"inner_version":2,"kind":"mail","message_id":"","recipients":[],"subject":` + wantText + `}`
		if string(got) != want {
			t.Fatalf("got %q\nwant %q", got, want)
		}
	})
}
