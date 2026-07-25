package conformance_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	awid "github.com/awebai/aw/awid"
)

type pinStoreRawWireVectors struct {
	Schema string `json:"schema"`
	Cases  []struct {
		Name     string `json:"name"`
		YAML     string `json:"yaml"`
		Expected struct {
			Go struct {
				Outcome         string   `json:"outcome"`
				ErrorSubstrings []string `json:"error_substrings"`
				Pins            int      `json:"pins"`
				Addresses       int      `json:"addresses"`
			} `json:"go"`
		} `json:"expected"`
	} `json:"cases"`
}

// TestPinStoreRawWireVectors writes each case's raw bytes to a file and loads it
// through the production LoadPinStore, so the harness never decides what reaches
// validation. Expectations are read from the vector per runtime; nothing in the
// corpus selects which assertion runs.
func TestPinStoreRawWireVectors(t *testing.T) {
	data := readRootVector(t, "pin-store-raw-wire-v1.json")
	var vectors pinStoreRawWireVectors
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if vectors.Schema != "aweb.pin-store.raw-wire.v1" {
		t.Fatalf("schema=%q", vectors.Schema)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("expected pin-store raw-wire cases")
	}

	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "known_agents.yaml")
			if err := os.WriteFile(path, []byte(c.YAML), 0o600); err != nil {
				t.Fatal(err)
			}

			store, err := awid.LoadPinStore(path)

			switch c.Expected.Go.Outcome {
			case "reject":
				if err == nil {
					t.Fatalf("case accepted but the vector requires rejection (pins=%d)", len(store.Pins))
				}
				if len(c.Expected.Go.ErrorSubstrings) == 0 {
					t.Fatal("vector rejects for Go but names no error substring")
				}
				// Assert WHY it was rejected. Two runtimes rejecting the same
				// document for different reasons reads as agreement while hiding
				// a divergence, which is how the non-string-key case was found.
				for _, want := range c.Expected.Go.ErrorSubstrings {
					if !strings.Contains(err.Error(), want) {
						t.Fatalf("error %q does not contain %q", err.Error(), want)
					}
				}
			case "accept":
				if err != nil {
					t.Fatalf("case rejected but the vector requires acceptance: %v", err)
				}
				if len(store.Pins) != c.Expected.Go.Pins {
					t.Fatalf("pins=%d, want %d", len(store.Pins), c.Expected.Go.Pins)
				}
				if len(store.Addresses) != c.Expected.Go.Addresses {
					t.Fatalf("addresses=%d, want %d", len(store.Addresses), c.Expected.Go.Addresses)
				}
			default:
				t.Fatalf("unknown expected outcome %q", c.Expected.Go.Outcome)
			}
		})
	}
}
