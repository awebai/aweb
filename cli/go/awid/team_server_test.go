package awid

import (
	"encoding/json"
	"testing"
	"time"
)

func TestVerifyTeamServerRecordRefusesANonIntegerVersion(t *testing.T) {
	pub, key, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDID := ComputeDIDKey(pub)
	now := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)
	for name, version := range map[string]any{"float": float64(1), "bool": true, "decimal_literal": json.Number("1.0")} {
		t.Run(name, func(t *testing.T) {
			record := NewTeamServerRecord("ops:float.example", teamDID, "https://coord.float.example", now)
			record["v"] = version
			signature, err := SignTeamServerRecord(key, record)
			if err != nil {
				t.Fatal(err)
			}
			_, err = VerifyTeamServerRecord(record, signature, "ops:float.example", teamDID, now)
			if TeamServerRecordErrorCode(err) != "record_invalid" {
				t.Fatalf("version %#v: err=%v, want record_invalid", version, err)
			}
		})
	}
}
