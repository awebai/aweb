package logschain

import (
	"encoding/json"
	"reflect"
	"testing"
)

func TestBundleSeparatesStructuralIntegrityFromAcceptedAttestation(t *testing.T) {
	for _, c := range loadExportVector(t).Cases {
		if c.Name != "whole_log_of_two_epochs" {
			continue
		}
		for _, tc := range []struct {
			name  string
			lines []string
			keys  bool
			want  []int64
		}{
			{"header-only", c.BundleLines[:1], true, []int64{}},
			{"no-artefacts", withoutArtefacts(t, c.BundleLines), true, []int64{}},
			{"accepted-artefacts", c.BundleLines, true, []int64{1, 2}},
			{"unaccepted-keys", c.BundleLines, false, []int64{}},
		} {
			t.Run(tc.name, func(t *testing.T) {
				rk, ck := keySet(c.ReceiptKeys), keySet(c.CheckpointKeys)
				if !tc.keys {
					rk = nil
					ck = nil
				}
				report, err := VerifyBundle(bundleReader(tc.lines), rk, ck, nil, nil)
				if err != nil {
					t.Fatal(err)
				}
				got, ok := report.JSON()["attested_epochs"]
				if !ok || !reflect.DeepEqual(asJSON(t, got), asJSON(t, tc.want)) {
					t.Fatalf("accepted-key attestation=%v want %v; report=%v", got, tc.want, report.JSON())
				}
				if tc.name == "header-only" && !report.Intact() {
					t.Fatal("structural intact changed")
				}
			})
		}
		return
	}
	t.Fatal("missing whole_log_of_two_epochs fixture")
}

func withoutArtefacts(t *testing.T, lines []string) []string {
	t.Helper()
	out := []string{}
	for _, line := range lines {
		var row map[string]any
		if err := json.Unmarshal([]byte(line), &row); err != nil {
			t.Fatal(err)
		}
		if row["receipt"] == nil && row["checkpoint"] == nil {
			out = append(out, line)
		}
	}
	return out
}

func TestAcceptedReceiptsAndIndependentWitnessesAttestWithoutCheckpoint(t *testing.T) {
	for _, c := range loadExportVector(t).Cases {
		if c.Name != "events_after_the_last_checkpoint_are_unanchored" {
			continue
		}
		for _, witnessOnly := range []bool{false, true} {
			lines := c.BundleLines
			var receipts []Artefact
			if witnessOnly {
				lines = withoutArtefacts(t, lines)
				for _, line := range c.BundleLines {
					var row map[string]any
					if err := json.Unmarshal([]byte(line), &row); err == nil && row["receipt"] != nil {
						var parsed Witnesses
						if err := parsed.Read(bundleReader([]string{line})); err != nil {
							t.Fatal(err)
						}
						receipts = append(receipts, parsed.Receipts...)
						break
					}
				}
			}
			report, err := VerifyBundle(bundleReader(lines), keySet(c.ReceiptKeys), keySet(c.CheckpointKeys), receipts, nil)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(report.JSON()["attested_epochs"], []int64{1}) {
				t.Fatalf("receipt attestation missing (witness=%v): %v", witnessOnly, report.JSON())
			}
			if report.LastCheckpoint != nil {
				t.Fatal("receipt invented checkpoint coverage")
			}
		}
		return
	}
	t.Fatal("missing receipt-only fixture")
}
