package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
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
				"digest":              "sha256:profile",
				"runtime_assumptions": []string{"local shell"},
				"files": []map[string]any{
					{"path": "profile.yaml", "content_utf8": "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate the team.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
					{"path": "instructions.md", "content_utf8": "Coordinate.\n"},
				},
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
				"digest":                      "sha256:profile",
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
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "coordinator", "profile_ref": "coordinator", "profile_version": "0.1.0", "profile_digest": "sha256:profile"})
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
	if bindBody["profile_ref"] != "coordinator" || bindBody["profile_version"] != "0.1.0" || bindBody["profile_digest"] != "sha256:profile" {
		t.Fatalf("bind body=%#v", bindBody)
	}
	if _, err := os.Stat(filepath.Join(home, ".aw", "profile", "profile.yaml")); err != nil {
		t.Fatalf("materialized .aw/profile/profile.yaml missing: %v", err)
	}
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
