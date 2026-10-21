package main

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/awebai/aw/internal/appmanifest"
)

func TestInstallRegistrationBodyPinsTheOriginWithoutUploadingAuthority(t *testing.T) {
	for _, version := range []int{1, 2} {
		manifest := appmanifest.Manifest{ManifestVersion: version}
		manifest.App.ID = "notes"
		manifest.App.Origin = "https://notes.example"
		body := installRegistrationBody(&appmanifest.Resolved{Manifest: manifest}, "sha256:abc", nil)
		for _, field := range []string{"manifest", "manifest_version", "app_version", "events", "event_emitters", "app_keys"} {
			if _, supplied := body[field]; supplied {
				t.Fatalf("%s supplied as install authority: %#v", field, body)
			}
		}
		if body["digest"] != "sha256:abc" || body["origin"] != "https://notes.example" {
			t.Fatalf("confirmation = %#v", body)
		}
	}
}

func TestInstallRegistrationBodyCarriesTheObservedGeneration(t *testing.T) {
	manifest := appmanifest.Manifest{ManifestVersion: 2}
	manifest.App.ID = "notes"
	generation := int64(7)
	body := installRegistrationBody(&appmanifest.Resolved{Manifest: manifest}, "sha256:abc", &generation)
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), `"expected_generation":7`) {
		t.Fatalf("missing conditional generation: %s", encoded)
	}
}
