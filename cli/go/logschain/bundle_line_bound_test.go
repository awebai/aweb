package logschain

import (
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// The purged case with its purge act lengthened so its event line is length bytes.
func purgedCaseWithLineOf(t *testing.T, length int) (lines []string, line int, act string, receiptKeys, checkpointKeys []string) {
	t.Helper()
	for _, c := range loadExportVector(t).Cases {
		if c.Name != "purged_event_keeps_its_skeleton_and_act" {
			continue
		}
		purged := c.Report["epochs"].([]any)[0].(map[string]any)["purged"].([]any)[0].(map[string]any)
		original := purged["act"].(string)
		field := `"purge_act":"` + original + `"`
		lines = append([]string(nil), c.BundleLines...)
		for i, l := range lines {
			if strings.Contains(l, field) {
				act = original + strings.Repeat("x", length-len(l))
				lines[i] = strings.Replace(l, field, `"purge_act":"`+act+`"`, 1)
				if len(lines[i]) != length {
					t.Fatalf("padded line is %d bytes; want %d", len(lines[i]), length)
				}
				return lines, i + 1, act, c.ReceiptKeys, c.CheckpointKeys
			}
		}
	}
	t.Fatal("the vector has no purged case")
	return
}

func TestALineOfExactlyTheBoundIsVerified(t *testing.T) {
	lines, _, act, receiptKeys, checkpointKeys := purgedCaseWithLineOf(t, MaxLineBytes)
	report, err := VerifyBundle(bundleReader(lines), keySet(receiptKeys), keySet(checkpointKeys), nil, nil)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Intact() {
		t.Fatalf("report not intact: %v", report.JSON())
	}
	purged := report.Epochs[0].Chain.Purged
	if len(purged) != 1 || purged[0].Act != act {
		t.Fatalf("purged %v; want one range with the padded act", purged)
	}
}

func TestALineOneByteOverTheBoundIsRefusedAtItsNumber(t *testing.T) {
	lines, line, _, receiptKeys, checkpointKeys := purgedCaseWithLineOf(t, MaxLineBytes+1)
	_, err := VerifyBundle(bundleReader(lines), keySet(receiptKeys), keySet(checkpointKeys), nil, nil)
	var malformed *BundleMalformed
	if !errors.As(err, &malformed) || malformed.Line != line {
		t.Fatalf("got %v; want a malformed bundle at line %d", err, line)
	}
}

// endless is a header line, then a second line that never ends.
type endless struct{ header []byte }

func (e *endless) Read(p []byte) (int, error) {
	n := copy(p, e.header)
	e.header = e.header[n:]
	for i := n; i < len(p); i++ {
		p[i] = 'x'
	}
	return len(p), nil
}

func TestAnEndlessLineIsRefusedWithoutBeingReadWhole(t *testing.T) {
	header := loadExportVector(t).Cases[0].BundleLines[0] + "\n"
	_, err := VerifyBundle(&endless{[]byte(header)}, nil, nil, nil, nil)
	var malformed *BundleMalformed
	if !errors.As(err, &malformed) || malformed.Line != 2 {
		t.Fatalf("got %v; want a malformed bundle at line 2", err)
	}
}

func TestTheVectorPinsTheBound(t *testing.T) {
	data, err := os.ReadFile(exportVectorPath)
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Scheme struct {
			MaxLineBytes int `json:"max_line_bytes"`
		} `json:"scheme"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if vector.Scheme.MaxLineBytes != MaxLineBytes {
		t.Fatalf("vector max_line_bytes %d; MaxLineBytes %d", vector.Scheme.MaxLineBytes, MaxLineBytes)
	}
}
