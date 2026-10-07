package appmanifest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"
)

func TestEventDeclarationVectors(t *testing.T) {
	data, err := os.ReadFile("testdata/events-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var vectors struct {
		Cases []struct {
			Name     string          `json:"name"`
			Manifest json.RawMessage `json:"manifest"`
			Accepted bool            `json:"accepted"`
		}
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	for _, tc := range vectors.Cases {
		t.Run(tc.Name, func(t *testing.T) {
			var m Manifest
			err := DecodeSingleJSONStrict(tc.Manifest, &m)
			if err == nil {
				err = Validate(m, nil)
			}
			if (err == nil) != tc.Accepted {
				t.Fatalf("accepted=%v want=%v err=%v", err == nil, tc.Accepted, err)
			}
			if err == nil {
				encoded, e := json.Marshal(m)
				if e != nil {
					t.Fatal(e)
				}
				var again Manifest
				if e := DecodeSingleJSONStrict(encoded, &again); e != nil {
					t.Fatal(e)
				}
				if len(again.Events) != len(m.Events) {
					t.Fatal("events lost on re-encoding")
				}
			}
		})
	}
}

func TestDeployedManifestContracts(t *testing.T) {
	for _, tc := range []struct {
		name, hash string
		events     int
	}{
		{"folio", "480b157753e1ecc9cd257daf70a35b97c5943960d69183971c32498b48c313e3", 1},
		{"library", "0019130d90bbbc61fde49c144b4f883eabac837889b0c69f515d206b35552329", 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + tc.name + "-deployed.json")
			if err != nil {
				t.Fatal(err)
			}
			hash := sha256.Sum256(data)
			if hex.EncodeToString(hash[:]) != tc.hash {
				t.Fatal("deployed bytes drifted")
			}
			var m Manifest
			if err := DecodeSingleJSONStrict(data, &m); err != nil {
				t.Fatal(err)
			}
			if err := Validate(m, nil); err != nil {
				t.Fatal(err)
			}
			if len(m.Events) != tc.events {
				t.Fatal("declaration metadata lost")
			}
		})
	}
}

func TestEventsDoNotRelaxUnknownFields(t *testing.T) {
	for _, raw := range []string{
		`{"manifest_version":1,"app":{"id":"test","origin":"https://example.test"},"tools":[],"events":[],"unknown":true}`,
		`{"manifest_version":1,"app":{"id":"test","origin":"https://example.test","unknown":true},"tools":[],"events":[]}`,
		`{"manifest_version":1,"app":{"id":"test","origin":"https://example.test"},"tools":[{"name":"x","auht":"none"}],"events":[]}`,
		`{"manifest_version":1,"app":{"id":"test","origin":"https://example.test"},"tools":[],"events":[{"type":"x","unknown":true}]}`,
	} {
		var m Manifest
		if err := DecodeSingleJSONStrict([]byte(raw), &m); err == nil {
			t.Fatal("unknown field accepted")
		}
	}
}
