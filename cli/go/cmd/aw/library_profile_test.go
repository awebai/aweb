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
	"github.com/awebai/aw/internal/profilepack"
)

func TestApplyLibraryProfileToHomeUsesInstalledManifestAndMaterializesLocally(t *testing.T) {
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
	profileDigest := testLibraryProfilePayloadDigest(t, files)

	var importBody, bindBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/profile-packs/aweb.engineering-pack/profiles/coordinator":
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-AWID-Team-Certificate") != "" {
				t.Fatalf("auth:none get-profile should be unsigned: %#v", r.Header)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pack_ref":            "aweb.engineering-pack",
				"pack_version":        "0.1.0",
				"profile_ref":         "coordinator",
				"version":             "0.1.0",
				"digest":              profileDigest,
				"runtime_assumptions": []string{"local shell"},
				"files":               files,
			})
		case "/v1/shelf/import":
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("missing signed headers for %s: %#v", r.URL.Path, r.Header)
			}
			if err := json.NewDecoder(r.Body).Decode(&importBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_ref":                 "coordinator",
				"version":                     "0.1.0",
				"digest":                      profileDigest,
				"source_profile_pack_ref":     "aweb.engineering-pack",
				"source_profile_pack_version": "0.1.0",
				"source_profile_pack_digest":  "sha256:pack",
				"created":                     true,
			})
		case "/v1/agents/coordinator/profile-binding":
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("missing signed headers for %s: %#v", r.URL.Path, r.Header)
			}
			if err := json.NewDecoder(r.Body).Decode(&bindBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "coordinator", "profile_ref": "coordinator", "profile_version": "0.1.0", "profile_digest": profileDigest})
		case "/v1/materialize":
			t.Fatalf("server materialize must not be called in local-compose flow")
		default:
			t.Fatalf("unexpected library request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	writeLibraryManifestPluginForTest(t, home, server.URL)

	selector, err := parseLibraryProfileSelector("aweb.engineering-pack/coordinator@0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	_, written, err := applyLibraryProfileToHome(home, "coordinator", selector, false)
	if err != nil {
		t.Fatalf("applyLibraryProfileToHome: %v", err)
	}
	if len(written) != 4 {
		t.Fatalf("written=%v", written)
	}
	if _, err := os.Lstat(filepath.Join(home, "CLAUDE.md")); !os.IsNotExist(err) {
		t.Fatalf("local-shell profile unexpectedly wrote CLAUDE.md: %v", err)
	}
	if importBody["source_profile_pack_ref"] != "aweb.engineering-pack" || importBody["source_profile_pack_version"] != "0.1.0" || importBody["profile_ref"] != "coordinator" {
		t.Fatalf("import body=%#v", importBody)
	}
	if bindBody["profile_ref"] != "coordinator" || bindBody["profile_version"] != "0.1.0" || bindBody["profile_digest"] != profileDigest {
		t.Fatalf("bind body=%#v", bindBody)
	}
	if _, err := os.Stat(filepath.Join(home, ".aw", "profile", "profile.yaml")); err != nil {
		t.Fatalf("materialized .aw/profile/profile.yaml missing: %v", err)
	}
}

func TestApplyLibraryProfileToHomeRejectsFetchedImportMismatchBeforeBindOrWrite(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)

	var bindCalled bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/profile-packs/aweb.engineering-pack/profiles/coordinator":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"pack_ref":            "aweb.engineering-pack",
				"pack_version":        "0.2.0",
				"profile_ref":         "coordinator",
				"version":             "0.2.0",
				"digest":              "sha256:latest",
				"runtime_assumptions": []string{"local shell"},
				"files":               testLibraryProfilePayloadFiles(),
			})
		case "/v1/shelf/import":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_ref":                 "coordinator",
				"version":                     "0.1.0",
				"digest":                      "sha256:pinned",
				"source_profile_pack_ref":     "aweb.engineering-pack",
				"source_profile_pack_version": "0.1.0",
				"source_profile_pack_digest":  "sha256:pack",
				"created":                     false,
			})
		case "/v1/agents/coordinator/profile-binding":
			bindCalled = true
			_ = json.NewEncoder(w).Encode(map[string]any{})
		default:
			t.Fatalf("unexpected library request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	writeLibraryManifestPluginForTest(t, home, server.URL)

	selector, err := parseLibraryProfileSelector("aweb.engineering-pack/coordinator@0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = applyLibraryProfileToHome(home, "coordinator", selector, false)
	if err == nil || !strings.Contains(err.Error(), "get-profile/import mismatch") {
		t.Fatalf("error=%v", err)
	}
	if bindCalled {
		t.Fatalf("bind called despite fetched/import mismatch")
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".aw", "profile", "profile.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("profile written despite fetched/import mismatch: %v", statErr)
	}
}

func testLibraryProfilePayloadFiles() []profilepack.LibraryProfilePayloadFile {
	return []profilepack.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate the team.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Coordinate.\n"},
	}
}

func testLibraryProfilePayloadDigest(t *testing.T, files []profilepack.LibraryProfilePayloadFile) string {
	t.Helper()
	result, err := profilepack.MaterializeLibraryProfilePayload(profilepack.MaterializeLibraryProfilePayloadOptions{
		TargetDir:      t.TempDir(),
		PackRef:        "aweb.engineering-pack",
		PackVersion:    "0.1.0",
		ProfileRef:     "coordinator",
		ProfileVersion: "0.1.0",
		RuntimeKind:    "local-shell",
		Files:          files,
	})
	if err != nil {
		t.Fatal(err)
	}
	return result.ProfileDigest
}

func writeLibraryManifestPluginForTest(t *testing.T, home, origin string) {
	t.Helper()
	pluginDir := filepath.Join(home, ".aw", "plugins", "library")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + origin + `"},"tools":[{"name":"get-profile","auth":"none","method":"GET","path":"/v1/profile-packs/{pack_ref}/profiles/{profile_ref}","input_schema":{"type":"object","properties":{"pack_ref":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"pack_ref","in":"path"},{"name":"profile_ref","in":"path"}],"mutation":false},{"name":"import-to-shelf","method":"POST","path":"/v1/shelf/import","input_schema":{"type":"object","properties":{"source_profile_pack_ref":{"type":"string"},"source_profile_pack_version":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"source_profile_pack_ref","in":"body"},{"name":"source_profile_pack_version","in":"body"},{"name":"profile_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},{"name":"bind","method":"POST","path":"/v1/agents/{agent_id}/profile-binding","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"profile_ref":{"type":"string"},"profile_version":{"type":"string"},"profile_digest":{"type":"string"},"source_profile_pack_ref":{"type":"string"}}},"params":[{"name":"agent_id","in":"path"},{"name":"profile_ref","in":"body"},{"name":"profile_version","in":"body"},{"name":"profile_digest","in":"body"},{"name":"source_profile_pack_ref","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}
