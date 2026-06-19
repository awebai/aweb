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

func TestApplyLibraryProfileToHomeUsesInstalledManifestAndWritesHomeFiles(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)

	var importBody, bindBody, materializeBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
			t.Fatalf("missing signed headers for %s: %#v", r.URL.Path, r.Header)
		}
		switch r.URL.Path {
		case "/v1/shelf/import":
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
			if err := json.NewDecoder(r.Body).Decode(&bindBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "coordinator", "profile_ref": "coordinator", "profile_version": "0.1.0", "profile_digest": "sha256:profile"})
		case "/v1/materialize":
			if err := json.NewDecoder(r.Body).Decode(&materializeBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_ref":         "coordinator",
				"profile_version":     "0.1.0",
				"profile_digest":      "sha256:profile",
				"runtime_assumptions": []string{"claude-code"},
				"home_files": []map[string]any{
					{"path": "AGENTS.md", "kind": "file", "content_utf8": "# Coordinator\n"},
					{"path": "CLAUDE.md", "kind": "symlink", "target": "AGENTS.md"},
					{"path": ".aw/profile/ref.json", "kind": "file", "content_utf8": "{}\n"},
					{"path": ".aw/profile/profile.yaml", "kind": "file", "content_utf8": "id: coordinator\n"},
					{"path": ".aw/profile/instructions.md", "kind": "file", "content_utf8": "Coordinate.\n"},
				},
			})
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
	_, written, err := applyLibraryProfileToHome(home, "coordinator", selector)
	if err != nil {
		t.Fatalf("applyLibraryProfileToHome: %v", err)
	}
	if len(written) != 5 {
		t.Fatalf("written=%v", written)
	}
	if importBody["source_profile_pack_ref"] != "aweb.engineering-pack" || importBody["source_profile_pack_version"] != "0.1.0" || importBody["profile_ref"] != "coordinator" {
		t.Fatalf("import body=%#v", importBody)
	}
	if bindBody["profile_ref"] != "coordinator" || bindBody["profile_version"] != "0.1.0" || bindBody["profile_digest"] != "sha256:profile" {
		t.Fatalf("bind body=%#v", bindBody)
	}
	if materializeBody["agent_id"] != "coordinator" || materializeBody["runtime_kind"] != "claude-code" || materializeBody["target"] != "local" {
		t.Fatalf("materialize body=%#v", materializeBody)
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
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + origin + `"},"tools":[{"name":"import-to-shelf","method":"POST","path":"/v1/shelf/import","input_schema":{"type":"object","properties":{"source_profile_pack_ref":{"type":"string"},"source_profile_pack_version":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"source_profile_pack_ref","in":"body"},{"name":"source_profile_pack_version","in":"body"},{"name":"profile_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},{"name":"bind","method":"POST","path":"/v1/agents/{agent_id}/profile-binding","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"profile_ref":{"type":"string"},"profile_version":{"type":"string"},"profile_digest":{"type":"string"},"source_profile_pack_ref":{"type":"string"}}},"params":[{"name":"agent_id","in":"path"},{"name":"profile_ref","in":"body"},{"name":"profile_version","in":"body"},{"name":"profile_digest","in":"body"},{"name":"source_profile_pack_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},{"name":"materialize","method":"POST","path":"/v1/materialize","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"runtime_kind":{"type":"string"},"target":{"type":"string"}}},"params":[{"name":"agent_id","in":"body"},{"name":"runtime_kind","in":"body"},{"name":"target","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}
