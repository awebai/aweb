package awid

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

// These are the frozen P0 bytes, not a second copy of their grammar or vectors.
func TestSignedViaNativeFrozenBytes(t *testing.T) {
	data, err := os.ReadFile("../../../docs/vectors/human-channels-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Valid []struct {
			Name      string `json:"name"`
			Canonical string `json:"canonical"`
			Schema    string `json:"schema"`
		} `json:"valid"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
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
