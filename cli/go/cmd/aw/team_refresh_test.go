package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

// writeLibraryShelfManifestPluginForTest installs a library plugin whose manifest
// declares get-shelf-profile (the Layer 2 tool), so `aw library get-shelf-profile
// --profile_ref X --include files` dispatches to the test server.
func writeLibraryShelfManifestPluginForTest(t *testing.T, home, origin string) {
	t.Helper()
	pluginDir := filepath.Join(home, ".aw", "plugins", "library")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + origin + `"},"tools":[` +
		`{"name":"get-shelf-profile","method":"GET","path":"/v1/profiles/{profile_ref}",` +
		`"input_schema":{"type":"object","properties":{"profile_ref":{"type":"string"},"include":{"type":"string"}}},` +
		`"params":[{"name":"profile_ref","in":"path"},{"name":"include","in":"query"}],"mutation":false}]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestRefreshLibraryProfileReMaterializesFromLatestShelf(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)

	// The latest shelf version (e.g. the one an approved proposal minted): bump
	// the profile.yaml version - the materialize derives the recorded version from
	// it, and the changed content yields a new canonical digest.
	files := testLibraryProfilePayloadFiles()
	for i := range files {
		if files[i].Path == "profile.yaml" {
			files[i].ContentUTF8 = strings.Replace(files[i].ContentUTF8, "version: 0.1.0", "version: 0.2.0", 1)
		}
	}
	newDigest := testLibraryProfilePayloadDigest(t, files)

	sawInclude := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profiles/coordinator" {
			t.Fatalf("unexpected library request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-AWID-Team-Certificate") == "" {
			t.Fatalf("get-shelf-profile must be team-signed (private shelf): %#v", r.Header)
		}
		sawInclude = r.URL.Query().Get("include")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_ref":              "coordinator",
			"version":                  "0.2.0",
			"digest":                   newDigest,
			"source_blueprint_ref":     "aweb.engineering",
			"source_blueprint_version": "0.1.0",
			"source_blueprint_digest":  "sha256:blueprint",
			"files":                    files,
		})
	}))
	defer server.Close()
	writeLibraryShelfManifestPluginForTest(t, home, server.URL)

	// The home as recorded after an earlier materialize at the OLD version.
	old := recordedProfileRef{
		ProfileRef:             "coordinator",
		ProfileVersion:         "0.1.0",
		ProfileDigest:          "sha256:old",
		SourceBlueprintRef:     "aweb.engineering",
		SourceBlueprintVersion: "0.1.0",
		SourceBlueprintDigest:  "sha256:blueprint",
	}

	result, err := refreshLibraryProfileInHome(home, "coordinator", old, "claude-code")
	if err != nil {
		t.Fatalf("refreshLibraryProfileInHome: %v", err)
	}
	if sawInclude != "files" {
		t.Fatalf("refresh must request the content form (?include=files), got %q", sawInclude)
	}
	if result.ProfileVersion != "0.2.0" || result.ProfileDigest != newDigest {
		t.Fatalf("refresh did not pick up the latest shelf version: %+v", result)
	}

	// ref.json is rewritten to the new shelf version.
	data, err := os.ReadFile(filepath.Join(home, ".aw", "profile", "ref.json"))
	if err != nil {
		t.Fatalf("ref.json missing after refresh: %v", err)
	}
	var got recordedProfileRef
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ProfileVersion != "0.2.0" || got.ProfileDigest != newDigest {
		t.Fatalf("ref.json not updated to the new shelf version: %+v", got)
	}
	// The profile files were re-materialized.
	if _, err := os.Stat(filepath.Join(home, ".aw", "profile", "profile.yaml")); err != nil {
		t.Fatalf("re-materialized .aw/profile/profile.yaml missing: %v", err)
	}
}

// A response whose profile_ref differs from the locally recorded one must be
// refused - the refresh is pinned to the recorded ref and must never rewrite
// ref.json to a different profile the remote named.
func TestRefreshLibraryProfileRefusesMismatchedProfileRef(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)

	files := testLibraryProfilePayloadFiles()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// respond with a DIFFERENT profile_ref than the recorded one.
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_ref":              "reviewer",
			"version":                  "0.2.0",
			"digest":                   "sha256:deadbeef",
			"source_blueprint_ref":     "aweb.engineering",
			"source_blueprint_version": "0.1.0",
			"source_blueprint_digest":  "sha256:blueprint",
			"files":                    files,
		})
	}))
	defer server.Close()
	writeLibraryShelfManifestPluginForTest(t, home, server.URL)

	old := recordedProfileRef{
		ProfileRef:             "coordinator",
		ProfileVersion:         "0.1.0",
		ProfileDigest:          "sha256:old",
		SourceBlueprintRef:     "aweb.engineering",
		SourceBlueprintVersion: "0.1.0",
		SourceBlueprintDigest:  "sha256:blueprint",
	}
	// pre-write ref.json so we can assert the refused refresh leaves it untouched.
	refPath := filepath.Join(home, ".aw", "profile", "ref.json")
	if err := os.MkdirAll(filepath.Dir(refPath), 0o755); err != nil {
		t.Fatal(err)
	}
	origRef, _ := json.Marshal(old)
	if err := os.WriteFile(refPath, origRef, 0o644); err != nil {
		t.Fatal(err)
	}

	if _, err := refreshLibraryProfileInHome(home, "coordinator", old, "claude-code"); err == nil || !strings.Contains(err.Error(), "refusing to rewrite") {
		t.Fatalf("expected refusal on mismatched profile_ref, got %v", err)
	}
	// ref.json is unchanged (still the recorded coordinator@0.1.0).
	data, err := os.ReadFile(refPath)
	if err != nil {
		t.Fatal(err)
	}
	var after recordedProfileRef
	if err := json.Unmarshal(data, &after); err != nil {
		t.Fatal(err)
	}
	if after.ProfileRef != "coordinator" || after.ProfileVersion != "0.1.0" {
		t.Fatalf("ref.json was rewritten despite the refusal: %+v", after)
	}
}
