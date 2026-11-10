package logschain

import (
	"encoding/base64"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// witnessLine is one witness in the bundle's own artefact line shape. The
// vector names a byte field signing_bytes_b64url, the cross-vector convention;
// the bundle's wire field signing_bytes already holds base64url text.
func witnessLine(t *testing.T, kind string, a vectorArtefact) string {
	t.Helper()
	return `{"` + kind + `":{"signature":"` + a.Signature + `","signing_bytes":"` + a.SigningBytes + `"}}`
}

func TestWitnessesReadFromBundleArtefactLinesVerifyAsGiven(t *testing.T) {
	for _, c := range loadExportVector(t).Cases {
		if len(c.WitnessReceipts)+len(c.WitnessCheckpoints) == 0 {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			var lines []string
			for _, a := range c.WitnessCheckpoints {
				lines = append(lines, witnessLine(t, "checkpoint", a))
			}
			for _, a := range c.WitnessReceipts {
				lines = append(lines, witnessLine(t, "receipt", a))
			}
			var witnesses Witnesses
			if err := witnesses.Read(bundleReader(lines)); err != nil {
				t.Fatal(err)
			}
			report, err := VerifyBundle(
				bundleReader(c.BundleLines), keySet(c.ReceiptKeys), keySet(c.CheckpointKeys),
				witnesses.Receipts, witnesses.Checkpoints,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got := asJSON(t, report.JSON()); !reflect.DeepEqual(got, asJSON(t, c.Report)) {
				t.Fatalf("report:\n got %v\nwant %v", got, c.Report)
			}
		})
	}
}

func TestWitnessesKeepPerKindOrderAcrossReads(t *testing.T) {
	a := vectorArtefact{SigningBytes: base64.RawURLEncoding.EncodeToString([]byte("a")), Signature: "sa"}
	b := vectorArtefact{SigningBytes: base64.RawURLEncoding.EncodeToString([]byte("b")), Signature: "sb"}
	var witnesses Witnesses
	for _, lines := range [][]string{
		{witnessLine(t, "receipt", a), witnessLine(t, "checkpoint", b)},
		{witnessLine(t, "receipt", b)},
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
