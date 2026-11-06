package conformance_test

import (
	"bytes"
	"encoding/json"
	awid "github.com/awebai/aw/awid"
	"reflect"
	"testing"
)

func TestIDKeyResponseTreeFrozenParse(t *testing.T) {
	data := readRootVector(t, "id-certificates-v1.json")
	var vectors struct {
		Cases []struct {
			Name     string                      `json:"name"`
			Response map[string]any              `json:"key_response"`
			Expected awid.IDTreeEnrollmentResult `json:"expected_parse"`
		} `json:"key_response_id_tree"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, c := range vectors.Cases {
		if seen[c.Name] {
			t.Fatal("duplicate case " + c.Name)
		}
		seen[c.Name] = true
		t.Run(c.Name, func(t *testing.T) {
			if got := awid.KeyResponseIDTree(c.Response); !reflect.DeepEqual(got, c.Expected) {
				t.Fatalf("got %#v, want %#v", got, c.Expected)
			}
		})
	}
	if len(seen) != 19 {
		t.Fatalf("got%d carrier cases, want19", len(seen))
	}
}

func TestIDKeyResponseTreeNilResponseIsMalformed(t *testing.T) {
	for _, c := range []struct {
		name     string
		response map[string]any
		state    string
	}{
		{"nil whole response", nil, "malformed"},
		{"object with absent field", map[string]any{}, "unknown"},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := awid.IDTreeEnrollmentResult{State: c.state}
			if got := awid.KeyResponseIDTree(c.response); !reflect.DeepEqual(got, want) {
				t.Fatalf("got %#v, want %#v", got, want)
			}
		})
	}
}
