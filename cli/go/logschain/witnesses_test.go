package logschain

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// witnessLine is one witness file line holding a receipt or checkpoint.
func witnessLine(kind, signingBytes, signature string) string {
	return `{"` + kind + `":{"signature":"` + signature + `","signing_bytes":"` + signingBytes + `"}}`
}

func TestWitnessesKeepPerKindOrderAcrossReads(t *testing.T) {
	a, b := base64.RawURLEncoding.EncodeToString([]byte("a")), base64.RawURLEncoding.EncodeToString([]byte("b"))
	var witnesses Witnesses
	for _, lines := range [][]string{
		{witnessLine("receipt", a, "sa"), witnessLine("checkpoint", b, "sb")},
		{witnessLine("receipt", b, "sb")},
	} {
		if err := witnesses.Read(bundleReader(lines)); err != nil {
			t.Fatal(err)
		}
	}
	want := Witnesses{
		Receipts:    []Artefact{{[]byte("a"), "sa"}, {[]byte("b"), "sb"}},
		Checkpoints: []Artefact{{[]byte("b"), "sb"}},
	}
	if !reflect.DeepEqual(witnesses, want) {
		t.Fatalf("got %+v; want %+v", witnesses, want)
	}
}

func TestAWitnessLineThatIsNotAnArtefactIsRefusedAtItsLine(t *testing.T) {
	v := loadExportVector(t)
	good := `{"receipt":{"signature":"s","signing_bytes":"YQ"}}`
	for name, bad := range map[string]string{
		"genesis":          v.Cases[0].BundleLines[1],
		"header":           v.Cases[0].BundleLines[0],
		"extra_field":      `{"receipt":{"extra":1,"signature":"s","signing_bytes":"YQ"}}`,
		"not_base64url":    `{"receipt":{"signature":"s","signing_bytes":"Y+Q"}}`,
		"not_canonical":    `{"receipt": {"signature":"s","signing_bytes":"YQ"}}`,
		"two_records":      `{"checkpoint":{"signature":"s","signing_bytes":"YQ"},"receipt":{"signature":"s","signing_bytes":"YQ"}}`,
		"not_json":         `receipt`,
		"oversized_object": `{"receipt":{"signature":"` + strings.Repeat("s", MaxLineBytes) + `","signing_bytes":"YQ"}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var witnesses Witnesses
			err := witnesses.Read(bundleReader([]string{good, bad}))
			var malformed *BundleMalformed
			if !errors.As(err, &malformed) {
				t.Fatalf("got %v; want a malformed witness line", err)
			}
			if malformed.Line != 2 {
				t.Fatalf("refused at line %d; want 2 (%s)", malformed.Line, malformed.Reason)
			}
		})
	}
}

func TestAWitnessFileEndsEveryLineWithANewline(t *testing.T) {
	var witnesses Witnesses
	err := witnesses.Read(strings.NewReader(`{"receipt":{"signature":"s","signing_bytes":"YQ"}}`))
	var malformed *BundleMalformed
	if !errors.As(err, &malformed) || malformed.Line != 1 {
		t.Fatalf("got %v; want line 1 refused", err)
	}
}
