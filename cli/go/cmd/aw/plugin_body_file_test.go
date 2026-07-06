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

func TestLibraryProposeBodyFileAndInlineContentReachApprove(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)
	t.Chdir(home)

	proposals := map[string]map[string]any{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
			t.Fatalf("library proposal flow must be team-signed: %#v", r.Header)
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/proposals":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			id := "p-inline"
			if body["summary"] == "from body file" {
				id = "p-file"
			}
			proposals[id] = body
			_ = json.NewEncoder(w).Encode(map[string]any{"proposal_id": id, "status": "created"})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/proposals/") && strings.HasSuffix(r.URL.Path, "/approve"):
			id := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/proposals/"), "/approve")
			body := proposals[id]
			content, _ := body["content"].(map[string]any)
			assets, _ := content["assets"].([]any)
			if content["schema"] != "aweb.library.profile-asset-changeset.v1" || len(assets) != 1 {
				http.Error(w, "invalid changeset", http.StatusUnprocessableEntity)
				return
			}
			asset, _ := assets[0].(map[string]any)
			if asset["path"] == "" || asset["content_utf8"] == "" || asset["base_asset_digest"] == "" {
				http.Error(w, "invalid asset", http.StatusUnprocessableEntity)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"proposal_id": id, "status": "approved"})
		default:
			t.Fatalf("unexpected library request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	writeLibraryProposeManifestPluginForTest(t, home, server.URL)

	changeset := `{"schema":"aweb.library.profile-asset-changeset.v1","assets":[{"path":"instructions.md","content_utf8":"inline","base_asset_digest":"sha256:inline"}]}`
	result, exists, err := executeInstalledManifestTool(libraryPluginName, []string{"propose", "--target", "profile", "--profile_ref", "developer", "--content", changeset, "--summary", "from inline"})
	if err != nil || !exists || result.Status >= 400 {
		t.Fatalf("inline propose result=%+v exists=%v err=%v body=%s", result, exists, err, resultBody(result))
	}
	result, exists, err = executeInstalledManifestTool(libraryPluginName, []string{"approve", "--proposal_id", "p-inline"})
	if err != nil || !exists || result.Status >= 400 {
		t.Fatalf("inline approve result=%+v exists=%v err=%v body=%s", result, exists, err, resultBody(result))
	}

	bodyPath := filepath.Join(t.TempDir(), "proposal.json")
	fileBody := `{"summary":"from body file","content":{"schema":"aweb.library.profile-asset-changeset.v1","assets":[{"path":"instructions.md","content_utf8":"file","base_asset_digest":"sha256:file"}]}}`
	if err := os.WriteFile(bodyPath, []byte(fileBody), 0o644); err != nil {
		t.Fatal(err)
	}
	result, exists, err = executeInstalledManifestTool(libraryPluginName, []string{"propose", "--target", "profile", "--profile_ref", "developer", "--body-file", bodyPath})
	if err != nil || !exists || result.Status >= 400 {
		t.Fatalf("body-file propose result=%+v exists=%v err=%v body=%s", result, exists, err, resultBody(result))
	}
	result, exists, err = executeInstalledManifestTool(libraryPluginName, []string{"approve", "--proposal_id", "p-file"})
	if err != nil || !exists || result.Status >= 400 {
		t.Fatalf("body-file approve result=%+v exists=%v err=%v body=%s", result, exists, err, resultBody(result))
	}

	for id, wantContent := range map[string]string{"p-inline": "inline", "p-file": "file"} {
		body := proposals[id]
		if body["target"] != "profile" || body["profile_ref"] != "developer" {
			t.Fatalf("%s did not carry explicit flags: %#v", id, body)
		}
		content := body["content"].(map[string]any)
		asset := content["assets"].([]any)[0].(map[string]any)
		if asset["content_utf8"] != wantContent {
			t.Fatalf("%s content dropped/mangled: %#v", id, body)
		}
	}
}

func resultBody(result *installedManifestToolResult) string {
	if result == nil {
		return ""
	}
	return string(result.Body)
}

func writeLibraryProposeManifestPluginForTest(t *testing.T, home, origin string) {
	t.Helper()
	pluginDir := filepath.Join(home, ".aw", "plugins", "library")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + origin + `"},"tools":[` +
		`{"name":"propose","method":"POST","path":"/v1/proposals","input_schema":{"type":"object","required":["target"],"properties":{"target":{"type":"string"},"profile_ref":{"type":"string"},"content":{"type":"object"},"summary":{"type":"string"}}},"params":[{"name":"target","in":"body"},{"name":"profile_ref","in":"body"},{"name":"content","in":"body"},{"name":"summary","in":"body"}],"body":{"mode":"json"},"mutation":true},` +
		`{"name":"approve","method":"POST","path":"/v1/proposals/{proposal_id}/approve","input_schema":{"type":"object","required":["proposal_id"],"properties":{"proposal_id":{"type":"string"}}},"params":[{"name":"proposal_id","in":"path"}],"mutation":true}` +
		`]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}
