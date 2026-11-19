package logschain

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

const exportVectorPath = "../../../docs/vectors/logs-export-v1.json"

type exportVector struct {
	Cases []struct {
		Name           string         `json:"name"`
		BundleLines    []string       `json:"bundle_lines"`
		ReceiptKeys    []string       `json:"receipt_keys"`
		CheckpointKeys []string       `json:"checkpoint_keys"`
		WitnessLines   []string       `json:"witness_lines"`
		Report         map[string]any `json:"report"`
	} `json:"cases"`
	Malformed []struct {
		Name        string   `json:"name"`
		BundleLines []string `json:"bundle_lines"`
		Line        int      `json:"line"`
	} `json:"malformed"`
}

func loadExportVector(t *testing.T) exportVector {
	t.Helper()
	data, err := os.ReadFile(exportVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var v exportVector
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// bundleReader is lines, each ended by a newline: a file with no lines is empty.
func bundleReader(lines []string) *bytes.Reader {
	var file []byte
	for _, line := range lines {
		file = append(append(file, line...), '\n')
	}
	return bytes.NewReader(file)
}

func TestExportVectorCases(t *testing.T) {
	for _, c := range loadExportVector(t).Cases {
		t.Run(c.Name, func(t *testing.T) {
			var witnesses Witnesses
			if err := witnesses.Read(bundleReader(c.WitnessLines)); err != nil {
				t.Fatalf("witnesses: %v", err)
			}
			report, err := VerifyBundle(
				bundleReader(c.BundleLines), keySet(c.ReceiptKeys), keySet(c.CheckpointKeys),
				witnesses.Receipts, witnesses.Checkpoints,
			)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if got := asJSON(t, report.JSON()); !reflect.DeepEqual(got, asJSON(t, c.Report)) {
				t.Fatalf("report:\n got %v\nwant %v", got, c.Report)
			}
		})
	}
}

func TestExportVectorMalformed(t *testing.T) {
	for _, c := range loadExportVector(t).Malformed {
		t.Run(c.Name, func(t *testing.T) {
			_, err := VerifyBundle(bundleReader(c.BundleLines), nil, nil, nil, nil)
			var malformed *BundleMalformed
			if !errors.As(err, &malformed) {
				t.Fatalf("got %v; want a malformed bundle", err)
			}
			if malformed.Line != c.Line {
				t.Fatalf("refused at line %d; want %d (%s)", malformed.Line, c.Line, malformed.Reason)
			}
		})
	}
}
