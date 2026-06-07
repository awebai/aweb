package awid

import (
	"encoding/json"
	"testing"
)

func TestA2APublicationConflictCodesMatchSharedVector(t *testing.T) {
	data := readDocsVector(t, "a2a-awid-publication-v1.json")
	var vector struct {
		ConflictCodes []string `json:"conflict_codes"`
	}
	if err := json.Unmarshal(data, &vector); err != nil {
		t.Fatal(err)
	}
	if len(vector.ConflictCodes) != len(A2APublicationConflictCodes) {
		t.Fatalf("codes len=%d want %d", len(A2APublicationConflictCodes), len(vector.ConflictCodes))
	}
	for i, got := range A2APublicationConflictCodes {
		if want := vector.ConflictCodes[i]; got != want {
			t.Fatalf("code[%d]: got %q want %q", i, got, want)
		}
	}
}
