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
	"github.com/awebai/aw/internal/blueprint"
)

func TestChooseLibraryRuntimeKindUsesFirstSupportedRuntimeHint(t *testing.T) {
	tests := []struct {
		name  string
		hints []string
		want  string
	}{
		{name: "first supported pi beats later claude", hints: []string{"pi", "claude-code"}, want: "pi"},
		{name: "skips unknown to later supported", hints: []string{"unknown", "codex"}, want: "codex"},
		{name: "local shell alias", hints: []string{"local shell"}, want: "local-shell"},
		{name: "absent defaults claude", hints: nil, want: "claude-code"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := chooseLibraryRuntimeKind(tc.hints); got != tc.want {
				t.Fatalf("chooseLibraryRuntimeKind(%v)=%q want %q", tc.hints, got, tc.want)
			}
		})
	}
}

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
		case "/v1/blueprints/aweb.engineering/profiles/coordinator":
			if r.Header.Get("Authorization") != "" || r.Header.Get("X-AWID-Team-Certificate") != "" {
				t.Fatalf("auth:none get-profile should be unsigned: %#v", r.Header)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blueprint_ref":       "aweb.engineering",
				"blueprint_version":   "0.1.0",
				"profile_ref":         "coordinator",
				"version":             "0.1.0",
				"digest":              profileDigest,
				"runtime_assumptions": []string{"local shell"},
				"runtime_hints":       []string{"local-shell"},
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
				"profile_ref":              "coordinator",
				"version":                  "0.1.0",
				"digest":                   profileDigest,
				"source_blueprint_ref":     "aweb.engineering",
				"source_blueprint_version": "0.1.0",
				"source_blueprint_digest":  "sha256:blueprint",
				"created":                  true,
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

	selector, err := parseLibraryProfileSelector("aweb.engineering/coordinator")
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
	if importBody["source_blueprint_ref"] != "aweb.engineering" || importBody["source_blueprint_version"] != nil || importBody["profile_ref"] != "coordinator" {
		t.Fatalf("import body=%#v", importBody)
	}
	if bindBody["profile_ref"] != "coordinator" || bindBody["profile_version"] != "0.1.0" || bindBody["profile_digest"] != profileDigest {
		t.Fatalf("bind body=%#v", bindBody)
	}
	if _, err := os.Stat(filepath.Join(home, ".aw", "profile", "profile.yaml")); err != nil {
		t.Fatalf("materialized .aw/profile/profile.yaml missing: %v", err)
	}
}

func TestApplyLibraryProfileToHomeRejectsVersionedSelectorUntilVersionedSourceFetch(t *testing.T) {
	home := t.TempDir()
	selector, err := parseLibraryProfileSelector("aweb.engineering/coordinator@0.1.0")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = applyLibraryProfileToHome(home, "coordinator", selector, false)
	if err == nil || !strings.Contains(err.Error(), "versioned Library profile selectors are not supported") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".aw", "profile", "profile.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("profile written despite unsupported versioned selector: %v", statErr)
	}
}

func TestApplyLibraryProfileToHomeRejectsMissingBlueprintSourceIdentityBeforeBindOrWrite(t *testing.T) {
	for _, tc := range []struct {
		name          string
		getProfile    map[string]any
		importResult  map[string]any
		wantErrSubstr string
	}{
		{
			name: "get-profile missing blueprint_ref",
			getProfile: map[string]any{
				"blueprint_version":   "0.1.0",
				"profile_ref":         "coordinator",
				"version":             "0.1.0",
				"digest":              "DIGEST",
				"runtime_assumptions": []string{"local shell"},
				"files":               testLibraryProfilePayloadFiles(),
			},
			importResult: map[string]any{
				"profile_ref":              "coordinator",
				"version":                  "0.1.0",
				"digest":                   "DIGEST",
				"source_blueprint_ref":     "aweb.engineering",
				"source_blueprint_version": "0.1.0",
				"source_blueprint_digest":  "sha256:blueprint",
			},
			wantErrSubstr: "get-profile response missing blueprint_ref",
		},
		{
			name: "import missing source_blueprint_ref",
			getProfile: map[string]any{
				"blueprint_ref":       "aweb.engineering",
				"blueprint_version":   "0.1.0",
				"profile_ref":         "coordinator",
				"version":             "0.1.0",
				"digest":              "DIGEST",
				"runtime_assumptions": []string{"local shell"},
				"files":               testLibraryProfilePayloadFiles(),
			},
			importResult: map[string]any{
				"profile_ref":              "coordinator",
				"version":                  "0.1.0",
				"digest":                   "DIGEST",
				"source_blueprint_version": "0.1.0",
				"source_blueprint_digest":  "sha256:blueprint",
			},
			wantErrSubstr: "import-to-shelf response missing source_blueprint_ref",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
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
			for _, response := range []map[string]any{tc.getProfile, tc.importResult} {
				if response["digest"] == "DIGEST" {
					response["digest"] = profileDigest
				}
			}

			var bindCalled bool
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/v1/blueprints/aweb.engineering/profiles/coordinator":
					_ = json.NewEncoder(w).Encode(tc.getProfile)
				case "/v1/shelf/import":
					_ = json.NewEncoder(w).Encode(tc.importResult)
				case "/v1/agents/coordinator/profile-binding":
					bindCalled = true
					_ = json.NewEncoder(w).Encode(map[string]any{})
				default:
					t.Fatalf("unexpected library request %s %s", r.Method, r.URL.Path)
				}
			}))
			defer server.Close()
			writeLibraryManifestPluginForTest(t, home, server.URL)

			selector, err := parseLibraryProfileSelector("aweb.engineering/coordinator")
			if err != nil {
				t.Fatal(err)
			}
			_, _, err = applyLibraryProfileToHome(home, "coordinator", selector, false)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrSubstr) {
				t.Fatalf("error=%v, want substring %q", err, tc.wantErrSubstr)
			}
			if bindCalled {
				t.Fatalf("bind called despite missing source identity")
			}
			if _, statErr := os.Lstat(filepath.Join(home, ".aw", "profile", "profile.yaml")); !os.IsNotExist(statErr) {
				t.Fatalf("profile written despite missing source identity: %v", statErr)
			}
		})
	}
}

func TestApplyLibraryProfileToHomeRejectsBindImportMismatchBeforeWrite(t *testing.T) {
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

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/blueprints/aweb.engineering/profiles/coordinator":
			_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "coordinator", "version": "0.1.0", "digest": profileDigest, "runtime_assumptions": []string{"local shell"}, "runtime_hints": []string{"local-shell"}, "files": files})
		case "/v1/shelf/import":
			_ = json.NewEncoder(w).Encode(map[string]any{"profile_ref": "coordinator", "version": "0.1.0", "digest": profileDigest, "source_blueprint_ref": "aweb.engineering", "source_blueprint_version": "0.1.0", "source_blueprint_digest": "sha256:blueprint", "created": false})
		case "/v1/agents/coordinator/profile-binding":
			_ = json.NewEncoder(w).Encode(map[string]any{"agent_id": "coordinator", "profile_ref": "coordinator", "profile_version": "0.1.0", "profile_digest": "sha256:other"})
		default:
			t.Fatalf("unexpected library request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	writeLibraryManifestPluginForTest(t, home, server.URL)

	selector, err := parseLibraryProfileSelector("aweb.engineering/coordinator")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = applyLibraryProfileToHome(home, "coordinator", selector, false)
	if err == nil || !strings.Contains(err.Error(), "bind/import mismatch") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".aw", "profile", "profile.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("profile written despite bind/import mismatch: %v", statErr)
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
		case "/v1/blueprints/aweb.engineering/profiles/coordinator":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"blueprint_ref":       "aweb.engineering",
				"blueprint_version":   "0.2.0",
				"profile_ref":         "coordinator",
				"version":             "0.2.0",
				"digest":              "sha256:latest",
				"runtime_assumptions": []string{"local shell"},
				"files":               testLibraryProfilePayloadFiles(),
			})
		case "/v1/shelf/import":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_ref":              "coordinator",
				"version":                  "0.1.0",
				"digest":                   "sha256:pinned",
				"source_blueprint_ref":     "aweb.engineering",
				"source_blueprint_version": "0.1.0",
				"source_blueprint_digest":  "sha256:blueprint",
				"created":                  false,
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

	selector, err := parseLibraryProfileSelector("aweb.engineering/coordinator")
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

func testLibraryProfilePayloadFiles() []blueprint.LibraryProfilePayloadFile {
	return []blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate the team.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Coordinate.\n"},
	}
}

func testLibraryProfilePayloadDigest(t *testing.T, files []blueprint.LibraryProfilePayloadFile) string {
	t.Helper()
	result, err := blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir:        t.TempDir(),
		BlueprintRef:     "aweb.engineering",
		BlueprintVersion: "0.1.0",
		ProfileRef:       "coordinator",
		ProfileVersion:   "0.1.0",
		RuntimeKind:      "local-shell",
		Files:            files,
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
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + origin + `"},"tools":[{"name":"get-profile","auth":"none","method":"GET","path":"/v1/blueprints/{blueprint_ref}/profiles/{profile_ref}","input_schema":{"type":"object","properties":{"blueprint_ref":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"blueprint_ref","in":"path"},{"name":"profile_ref","in":"path"}],"mutation":false},{"name":"import-to-shelf","method":"POST","path":"/v1/shelf/import","input_schema":{"type":"object","properties":{"source_blueprint_ref":{"type":"string"},"source_blueprint_version":{"type":"string"},"profile_ref":{"type":"string"}}},"params":[{"name":"source_blueprint_ref","in":"body"},{"name":"source_blueprint_version","in":"body"},{"name":"profile_ref","in":"body"}],"body":{"mode":"json"},"mutation":true},{"name":"bind","method":"POST","path":"/v1/agents/{agent_id}/profile-binding","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"profile_ref":{"type":"string"},"profile_version":{"type":"string"},"profile_digest":{"type":"string"},"source_blueprint_ref":{"type":"string"}}},"params":[{"name":"agent_id","in":"path"},{"name":"profile_ref","in":"body"},{"name":"profile_version","in":"body"},{"name":"profile_digest","in":"body"},{"name":"source_blueprint_ref","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
}
