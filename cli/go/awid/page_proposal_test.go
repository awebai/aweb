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
}
