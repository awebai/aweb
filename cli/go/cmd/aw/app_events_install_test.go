package main

import (
	"encoding/base64"
	"testing"

	"github.com/awebai/aw/internal/appmanifest"
)

func TestInstallRegistrationBodyCarriesTheExactFetchedBytes(t *testing.T) {
	fetched := []byte(`{"manifest_version":1,"app":{"id":"notes","version":"1.0","origin":"https://notes.example"}}`)
	manifest := appmanifest.Manifest{ManifestVersion: 1}
	manifest.App.ID = "notes"
	manifest.App.Version = "1.0"
	manifest.App.Origin = "https://notes.example"

	body := installRegistrationBody(&appmanifest.Resolved{Manifest: manifest}, "sha256:abc", fetched)

	if body["manifest"] != base64.StdEncoding.EncodeToString(fetched) {
		t.Fatalf("manifest = %v", body["manifest"])
	}
	if body["digest"] != "sha256:abc" || body["origin"] != "https://notes.example" {
		t.Fatalf("body = %v", body)
	}
}

func TestInstallRegistrationBodyOmitsBytesWhenThereAreNone(t *testing.T) {
	manifest := appmanifest.Manifest{ManifestVersion: 1}
	manifest.App.ID = "notes"

	body := installRegistrationBody(&appmanifest.Resolved{Manifest: manifest}, "sha256:abc", nil)

	if _, ok := body["manifest"]; ok {
		t.Fatalf("manifest sent without bytes: %v", body["manifest"])
	}
}

func TestRegistrationBytesAreSentOnlyWhenTheyNameTheRegisteredOrigin(t *testing.T) {
	fetched := []byte(`{}`)
	cases := []struct {
		name, declared, registered string
		want                       bool
	}{
		{"same origin", "https://notes.example", "https://notes.example", true},
		{"dev origin equal after canonicalization", "https://Notes.example:443", "https://notes.example", true},
		{"dev origin rewrites the app", "https://notes.example", "http://localhost:8080", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := registrationManifestBytesFor(fetched, 1, tc.declared, tc.registered)
			if (got != nil) != tc.want {
				t.Fatalf("bytes sent = %v, want %v", got != nil, tc.want)
			}
		})
	}
}

func TestRegistrationBytesAreSentOnlyForManifestVersionsTheServerReads(t *testing.T) {
	fetched := []byte(`{}`)
	if registrationManifestBytesFor(fetched, 1, "https://notes.example", "https://notes.example") == nil {
		t.Fatal("v1 bytes not sent")
	}
	if got := registrationManifestBytesFor(fetched, 2, "https://notes.example", "https://notes.example"); got != nil {
		t.Fatal("v2 bytes sent before the server reads v2 manifests")
	}
}
