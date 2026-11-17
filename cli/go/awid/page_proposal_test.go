package awid

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestPageProposalVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/page-proposal-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var vectors struct {
		Cases []struct {
			Name           string `json:"name"`
			Collection     string `json:"collection"`
			RecordID       string `json:"record_id"`
			Value          any    `json:"value"`
			ProposalSHA256 string `json:"proposal_sha256"`
		} `json:"cases"`
		Refusals []struct {
			Name      string `json:"name"`
			ValueJSON string `json:"value_json"`
		} `json:"refusals"`
	}
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Cases) == 0 {
		t.Fatal("no proposal vectors")
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := ProposalSHA256(tc.Collection, tc.RecordID, tc.Value)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.ProposalSHA256 {
				t.Fatalf("proposal digest = %s, want %s", got, tc.ProposalSHA256)
			}
		})
	}
	if len(vectors.Refusals) == 0 {
		t.Fatal("no proposal refusal vectors")
	}
	for _, tc := range vectors.Refusals {
		t.Run("refuse-"+tc.Name, func(t *testing.T) {
			decoder := json.NewDecoder(bytes.NewReader([]byte(tc.ValueJSON)))
			decoder.UseNumber()
			var value any
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			if got, err := ProposalSHA256("proposals", "r", value); err == nil {
				t.Fatalf("value %s has no canonical form but digested to %s", tc.ValueJSON, got)
			}
		})
	}
}

func TestStrictCanonicalJSONRefusesOtherNumbers(t *testing.T) {
	for _, value := range []any{1.5, float32(2), int64(9007199254740992), uint64(1 << 60), "\xff"[:1] + "\xfe", map[string]any{"a": []any{1.0}}} {
		if _, err := StrictCanonicalJSON(value); err == nil {
			t.Fatalf("%#v has no canonical form but was encoded", value)
		}
	}
}
