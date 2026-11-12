package handoff

import (
	"bytes"
	"encoding/json"
	"os"
	"testing"
)

func TestTheCoveredRequestDigestMatchesTheApprovalVectors(t *testing.T) {
	data, err := os.ReadFile("../../../../docs/vectors/approval-request-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Requests []struct {
			Name             string         `json:"name"`
			PolicyRef        string         `json:"policy_ref"`
			PolicyVersion    json.Number    `json:"policy_version"`
			Request          map[string]any `json:"request"`
			CoveredCanonical string         `json:"covered_canonical"`
			RequestSHA256    string         `json:"request_sha256"`
		} `json:"requests"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors.Requests) == 0 {
		t.Fatal("no requests")
	}
	for _, tc := range vectors.Requests {
		t.Run(tc.Name, func(t *testing.T) {
			covered := map[string]any{
				"policy":  map[string]any{"ref": tc.PolicyRef, "version": tc.PolicyVersion},
				"request": tc.Request,
			}
			digest, err := CoveredRequestDigest(covered)
			if err != nil {
				t.Fatal(err)
			}
			if digest != tc.RequestSHA256 {
				t.Fatalf("digest %s want %s", digest, tc.RequestSHA256)
			}
		})
	}
}
