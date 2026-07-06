package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/blueprint"
	"github.com/spf13/cobra"
)

func TestTeamAdoptRepointsPublicPinToShelfAndRefreshUsesShelfMint(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))

	publicFiles := testLibraryProfilePayloadFiles()
	publicDigest := testLibraryProfilePayloadDigest(t, publicFiles)
	latestFiles := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.2.0\nmission: Coordinate the team with an approved shelf improvement.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Coordinate from the shelf mint.\n"},
	})
	latestDigest := testLibraryProfilePayloadDigest(t, latestFiles)

	var importBody, bindBody map[string]any
	var shelfSigned bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/blueprints/aweb.team/profiles/coordinator":
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-AWID-Team-Certificate") != "" {
				t.Fatalf("public get-profile should be unsigned: %#v", r.Header)
			}
			_ = json.NewEncoder(w).Encode(libraryProfileDetailResponse{BlueprintRef: "aweb.team", BlueprintVersion: "0.1.0", ProfileRef: "coordinator", Version: "0.1.0", Digest: publicDigest, Files: publicFiles})
		case "/v1/shelf/import":
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("import-to-shelf must be team-signed: %#v", r.Header)
			}
			if err := json.NewDecoder(r.Body).Decode(&importBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(libraryImportToShelfResponse{ProfileRef: "coordinator", Version: "0.1.0", Digest: publicDigest, SourceBlueprintRef: "aweb.team", SourceBlueprintVersion: "0.1.0", SourceBlueprintDigest: "sha256:shelf-source", Created: true})
		case "/v1/agents/coordinator/profile-binding":
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("bind must be team-signed: %#v", r.Header)
			}
			if err := json.NewDecoder(r.Body).Decode(&bindBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(libraryBindResponse{AgentID: "coordinator", ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: publicDigest})
		case "/v1/profiles/coordinator":
			if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
				t.Fatalf("get-shelf-profile must be team-signed: %#v", r.Header)
			}
			shelfSigned = true
			_ = json.NewEncoder(w).Encode(libraryShelfProfileResponse{ProfileRef: "coordinator", Version: "0.2.0", Digest: latestDigest, SourceBlueprintRef: "aweb.team", SourceBlueprintVersion: "0.1.0", SourceBlueprintDigest: "sha256:shelf-source", Files: latestFiles})
		default:
			t.Fatalf("unexpected library request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()

	writeLocalTeamSignedRequestWorkspaceForTest(t, home, server.URL, "default:acme.com", "coordinator", did, priv)
	writeLibraryAdoptManifestPluginForTest(t, home, server.URL)

	_, _, err = applyPublicLibraryProfileToHome(home, libraryProfileSelector{LibraryURL: server.URL, SourceBlueprintRef: "aweb.team", ProfileRef: "coordinator", RuntimeKind: "pi"}, true)
	if err != nil {
		t.Fatalf("public materialize: %v", err)
	}
	publicRef, err := readRecordedProfileRef(home)
	if err != nil {
		t.Fatal(err)
	}
	if publicRef.LibraryURL == "" {
		t.Fatalf("test setup expected a public pin with library_url: %+v", publicRef)
	}

	oldHomeFlag := agentHomeFlag
	agentHomeFlag = home
	t.Cleanup(func() { agentHomeFlag = oldHomeFlag })
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runTeamAdopt(cmd, []string{"coordinator"}); err != nil {
		t.Fatalf("team adopt: %v", err)
	}
	if importBody["source_blueprint_ref"] != "aweb.team" || importBody["source_blueprint_version"] != "0.1.0" || importBody["profile_ref"] != "coordinator" {
		t.Fatalf("import body=%#v", importBody)
	}
	if bindBody["profile_ref"] != "coordinator" || bindBody["profile_version"] != "0.1.0" || bindBody["profile_digest"] != publicDigest {
		t.Fatalf("bind body=%#v", bindBody)
	}
	if !strings.Contains(out.String(), "Adopted coordinator onto the team Library shelf") {
		t.Fatalf("adopt output=%q", out.String())
	}

	adoptedRef, err := readRecordedProfileRef(home)
	if err != nil {
		t.Fatal(err)
	}
	if adoptedRef.LibraryURL != "" || adoptedRef.ProfileVersion != "0.1.0" || adoptedRef.ProfileDigest != publicDigest || adoptedRef.SourceBlueprintDigest != "sha256:shelf-source" || adoptedRef.RuntimeKind != "pi" {
		t.Fatalf("adopted ref did not re-point to shelf: %+v", adoptedRef)
	}

	result, err := refreshLibraryProfileInHome(home, "coordinator", adoptedRef, "pi")
	if err != nil {
		t.Fatalf("refresh shelf mint: %v", err)
	}
	if !shelfSigned {
		t.Fatal("refresh did not call get-shelf-profile")
	}
	if result.ProfileVersion != "0.2.0" || result.ProfileDigest != latestDigest {
		t.Fatalf("refresh result=%+v", result)
	}
	data, err := os.ReadFile(filepath.Join(home, ".aw", "profile", "profile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "version: 0.2.0") || !strings.Contains(string(data), "approved shelf improvement") {
		t.Fatalf("profile.yaml was not refreshed from shelf mint:\n%s", data)
	}
	refreshedRef, err := readRecordedProfileRef(home)
	if err != nil {
		t.Fatal(err)
	}
	if refreshedRef.LibraryURL != "" || refreshedRef.ProfileVersion != "0.2.0" || refreshedRef.ProfileDigest != latestDigest {
		t.Fatalf("ref after refresh=%+v", refreshedRef)
	}
}

func TestTeamAdoptRequiresLibraryPluginForShelfImport(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	if err := os.MkdirAll(filepath.Join(home, ".aw", "profile"), 0o755); err != nil {
		t.Fatal(err)
	}
	ref := recordedProfileRef{LibraryURL: "https://library.example", ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: "sha256:profile", SourceBlueprintRef: "aweb.team", SourceBlueprintVersion: "0.1.0", RuntimeKind: "pi"}
	data, err := json.MarshalIndent(ref, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aw", "profile", "ref.json"), append(data, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	oldHomeFlag := agentHomeFlag
	agentHomeFlag = home
	t.Cleanup(func() { agentHomeFlag = oldHomeFlag })

	err = runTeamAdopt(&cobra.Command{}, []string{"coordinator"})
	if err == nil || !strings.Contains(err.Error(), "Library plugin is not installed") || !strings.Contains(err.Error(), libraryPluginInstallCommand) {
		t.Fatalf("error=%v", err)
	}
}

func writeLibraryAdoptManifestPluginForTest(t *testing.T, home, origin string) {
	t.Helper()
	pluginDir := filepath.Join(home, ".aw", "plugins", "library")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + origin + `"},"tools":[` +
		`{"name":"get-profile","auth":"none","method":"GET","path":"/v1/blueprints/{blueprint_ref}/profiles/{profile_ref}","input_schema":{"type":"object","properties":{"blueprint_ref":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"blueprint_ref","in":"path"},{"name":"profile_ref","in":"path"}],"mutation":false},` +
		`{"name":"import-to-shelf","method":"POST","path":"/v1/shelf/import","input_schema":{"type":"object","properties":{"source_blueprint_ref":{"type":"string"},"source_blueprint_version":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"source_blueprint_ref","in":"body"},{"name":"source_blueprint_version","in":"body"},{"name":"profile_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},` +
		`{"name":"bind","method":"POST","path":"/v1/agents/{agent_id}/profile-binding","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"profile_ref":{"type":"string"},"profile_version":{"type":"string"},"profile_digest":{"type":"string"},"source_blueprint_ref":{"type":"string"}}},"params":[{"name":"agent_id","in":"path"},{"name":"profile_ref","in":"body"},{"name":"profile_version","in":"body"},{"name":"profile_digest","in":"body"},{"name":"source_blueprint_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},` +
		`{"name":"get-shelf-profile","method":"GET","path":"/v1/profiles/{profile_ref}","input_schema":{"type":"object","properties":{"profile_ref":{"type":"string"},"include":{"type":"string"}}},"params":[{"name":"profile_ref","in":"path"},{"name":"include","in":"query"}],"mutation":false}` +
		`]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}
