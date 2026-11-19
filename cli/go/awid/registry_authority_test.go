package awid

import (
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestRegistryAuthoritySharedVectors(t *testing.T) {
	raw, err := os.ReadFile("../../../docs/vectors/registry-authority-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var corpus struct {
		Version int `json:"version"`
		Cases   []struct {
			ID           string                       `json:"id"`
			Input        RegistryAuthorityInput       `json:"input"`
			Expected     RegistryAuthoritySelection   `json:"expected"`
			ErrorCode    RegistryAuthorityRefusalCode `json:"error_code"`
			ErrorMessage string                       `json:"error_message"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &corpus); err != nil {
		t.Fatal(err)
	}
	if corpus.Version != 1 || len(corpus.Cases) == 0 {
		t.Fatal("registry authority vectors missing")
	}
	for _, vector := range corpus.Cases {
		t.Run(vector.ID, func(t *testing.T) {
			selection, err := SelectRegistryAuthority(vector.Input)
			if vector.ErrorCode != "" {
				var refusal *RegistryAuthorityRefusal
				if !errors.As(err, &refusal) || refusal.Code != vector.ErrorCode || err.Error() != vector.ErrorMessage {
					t.Fatalf("refusal = %v, expected %s: %s", err, vector.ErrorCode, vector.ErrorMessage)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(selection, vector.Expected) {
				t.Fatalf("selection = %+v (%v), expected %+v", selection, err, vector.Expected)
			}
		})
	}
}
