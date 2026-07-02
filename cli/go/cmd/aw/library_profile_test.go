package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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

func TestMissingLibraryPluginErrorsAreActionable(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, exists, err := executeInstalledManifestTool(libraryPluginName, []string{"get-profile", "--blueprint_ref", "aweb.development", "--profile_ref", "developer"})
	if err != nil || exists {
		t.Fatalf("executeInstalledManifestTool err=%v exists=%v, want missing without error for direct lookup", err, exists)
	}

	_, err = resolveTrustedPluginCommand(libraryPluginName)
	if err == nil {
		t.Fatal("expected aw library command resolution to fail actionably")
	}
	for _, want := range []string{"The aw Library plugin is not installed", "Install it with:", libraryPluginInstallCommand} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("missing plugin error should contain %q, got %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "Adding an agent") {
		t.Fatalf("direct aw library error should not use team-add wording: %v", err)
	}

	_, _, err = applyLibraryProfileToHome(t.TempDir(), "developer", libraryProfileSelector{SourceBlueprintRef: "aweb.development", ProfileRef: "developer"}, true)
	if err == nil {
		t.Fatal("expected team/profile materialize path to fail without library plugin")
	}
	for _, want := range []string{"Adding an agent from a Library profile (aweb.development/developer) requires the aw Library plugin", "Install it, then re-run:", libraryPluginInstallCommand} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("profile path missing plugin error should contain %q, got %v", want, err)
		}
	}
	if strings.Contains(err.Error(), "The aw Library plugin is not installed. Install it with:") {
		t.Fatalf("profile path should use team-add wording, got %v", err)
	}
}

func TestResolveLibraryProfileSelectorSourcePrecedence(t *testing.T) {
	t.Setenv(libraryURLEnvVar, "https://env-library.example/")
	t.Setenv(libraryBlueprintEnvVar, "env.blueprint")
	selector, err := parseLibraryProfileSelector("developer")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := resolveLibraryProfileSelectorSource(selector, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.LibraryURL != "https://env-library.example" || resolved.SourceBlueprintRef != "env.blueprint" || resolved.ProfileRef != "developer" {
		t.Fatalf("env resolved=%+v", resolved)
	}
	resolved, err = resolveLibraryProfileSelectorSource(selector, "http://flag-library.example/base/", "flag.blueprint")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.LibraryURL != "http://flag-library.example/base" || resolved.SourceBlueprintRef != "flag.blueprint" {
		t.Fatalf("flag resolved=%+v", resolved)
	}
	explicit, err := parseLibraryProfileSelector("selector.blueprint/reviewer")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = resolveLibraryProfileSelectorSource(explicit, "", "flag.blueprint")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.SourceBlueprintRef != "selector.blueprint" {
		t.Fatalf("selector blueprint should win, got %+v", resolved)
	}
	t.Setenv(libraryURLEnvVar, "")
	t.Setenv(libraryBlueprintEnvVar, "")
	resolved, err = resolveLibraryProfileSelectorSource(selector, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if resolved.LibraryURL != defaultLibraryBaseURL || resolved.SourceBlueprintRef != defaultLibraryBlueprintRef {
		t.Fatalf("default resolved=%+v", resolved)
	}
}

func TestParseLibraryProfileSelectorRuntimeSuffix(t *testing.T) {
	profileOnly, err := parseLibraryProfileSelector("reviewer:local=pi")
	if err != nil {
		t.Fatalf("parse profile-only selector: %v", err)
	}
	if profileOnly.SourceBlueprintRef != "" || profileOnly.ProfileRef != "reviewer" || profileOnly.IdentityScope != awid.IdentityModeLocal || profileOnly.RuntimeKind != "pi" {
		t.Fatalf("profile-only selector=%+v", profileOnly)
	}
	selector, err := parseLibraryProfileSelector("aweb.engineering/reviewer=pi")
	if err != nil {
		t.Fatalf("parse selector: %v", err)
	}
	if selector.SourceBlueprintRef != "aweb.engineering" || selector.ProfileRef != "reviewer" || selector.RuntimeKind != "pi" {
		t.Fatalf("selector=%+v", selector)
	}
	scoped, err := parseLibraryProfileSelector("aweb.engineering/reviewer:global=codex")
	if err != nil {
		t.Fatalf("parse scoped selector: %v", err)
	}
	if scoped.IdentityScope != awid.IdentityModeGlobal || scoped.RuntimeKind != "codex" {
		t.Fatalf("scoped selector=%+v", scoped)
	}
	if _, err := parseLibraryProfileSelector("aweb.engineering/reviewer@0.2.0=local-shell"); err == nil || !strings.Contains(err.Error(), "@ now separates NAME") {
		t.Fatalf("versioned selector error=%v", err)
	}
	if _, err := parseLibraryProfileSelector("aweb.engineering/reviewer=python"); err == nil || !strings.Contains(err.Error(), "supported runtimes") {
		t.Fatalf("bad runtime error=%v", err)
	}
}

func TestApplyLocalBlueprintProfileToHomeUsesLocalSourceAndRuntime(t *testing.T) {
	fixture := filepath.Join(engineeringBlueprintFixtureRoot(t), "source")
	home := t.TempDir()
	selector := libraryProfileSelector{SourceBlueprintRef: "aweb.engineering", ProfileRef: "developer", RuntimeKind: "pi"}

	result, written, err := applyLocalBlueprintProfileToHome(home, selector, fixture, true)
	if err != nil {
		t.Fatal(err)
	}
	if result.SourceBlueprintRef != "aweb.engineering" || result.ProfileRef != "developer" {
		t.Fatalf("result=%+v", result)
	}
	if len(written) == 0 {
		t.Fatalf("no files written")
	}
	if _, err := os.Lstat(filepath.Join(home, "CLAUDE.md")); !os.IsNotExist(err) {
		t.Fatalf("pi runtime should not create CLAUDE.md symlink, err=%v", err)
	}
	profileYAML, err := os.ReadFile(filepath.Join(home, ".aw", "profile", "profile.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(profileYAML), "id: developer") {
		t.Fatalf("profile.yaml did not come from local developer profile:\n%s", string(profileYAML))
	}
}

func TestApplyMaterializeRuntimePolicyDefaultsAndHonorsFlag(t *testing.T) {
	selector := libraryProfileSelector{SourceBlueprintRef: "aweb.engineering", ProfileRef: "coordinator"}
	got, err := applyMaterializeRuntimePolicy(selector, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.RuntimeKind != defaultMaterializeRuntimeKind {
		t.Fatalf("default runtime=%q", got.RuntimeKind)
	}
	got, err = applyMaterializeRuntimePolicy(selector, "pi")
	if err != nil {
		t.Fatal(err)
	}
	if got.RuntimeKind != "pi" {
		t.Fatalf("flag runtime=%q", got.RuntimeKind)
	}
	suffix := libraryProfileSelector{SourceBlueprintRef: "aweb.engineering", ProfileRef: "coordinator", RuntimeKind: "codex"}
	got, err = applyMaterializeRuntimePolicy(suffix, "pi")
	if err != nil {
		t.Fatal(err)
	}
	if got.RuntimeKind != "codex" {
		t.Fatalf("suffix runtime should win, got %q", got.RuntimeKind)
	}
}

func TestApplyPublicLibraryProfileToHomeFetchesUnsignedWritesPinAndRejectsBadDigest(t *testing.T) {
	files := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: developer\nname: Developer\nversion: 0.1.0\nmission: Build.\naccepted_work: [development]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Build.\n"},
	})
	digest := testLibraryProfilePayloadDigestForProfile(t, "developer", files)
	badDigest := "sha256:0000000000000000000000000000000000000000000000000000000000000000"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/developer" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-AWID-Team-Certificate") != "" {
			t.Fatalf("public get-profile should be unsigned: %#v", r.Header)
		}
		responseDigest := digest
		if r.URL.Query().Get("bad") == "1" {
			responseDigest = badDigest
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "developer", "version": "0.1.0", "digest": responseDigest, "files": files})
	}))
	defer server.Close()

	home := t.TempDir()
	selector := libraryProfileSelector{LibraryURL: server.URL, SourceBlueprintRef: "aweb.engineering", ProfileRef: "developer", RuntimeKind: "local-shell"}
	if _, _, err := applyPublicLibraryProfileToHome(home, selector, true); err != nil {
		t.Fatalf("applyPublicLibraryProfileToHome: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(home, ".aw", "profile", "ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pin struct {
		LibraryURL            string   `json:"library_url"`
		ManagedSet            []string `json:"managed_set"`
		SourceBlueprintDigest string   `json:"source_blueprint_digest"`
	}
	if err := json.Unmarshal(data, &pin); err != nil {
		t.Fatal(err)
	}
	if pin.LibraryURL != server.URL || len(pin.ManagedSet) == 0 || pin.SourceBlueprintDigest != "" {
		t.Fatalf("pin=%+v", pin)
	}

	badHome := t.TempDir()
	badSelector := selector
	// Route a deliberately corrupt response through a second real HTTP fixture.
	badServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "developer", "version": "0.1.0", "digest": badDigest, "files": files})
	}))
	defer badServer.Close()
	badSelector.LibraryURL = badServer.URL
	_, _, err = applyPublicLibraryProfileToHome(badHome, badSelector, true)
	if err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("bad digest error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(badHome, ".aw", "profile", "profile.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("bad digest wrote target state, stat err=%v", statErr)
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
				"runtime_hints":       []string{"pi", "claude-code"},
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

	selector, err := parseLibraryProfileSelector("aweb.engineering/coordinator=local-shell")
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

func TestParseLibraryProfileSelectorRejectsVersionedSelector(t *testing.T) {
	home := t.TempDir()
	_, err := parseLibraryProfileSelector("aweb.engineering/coordinator@0.1.0")
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
	return withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate the team.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Coordinate.\n"},
	})
}

func withLibraryPayloadFileSHA(files []blueprint.LibraryProfilePayloadFile) []blueprint.LibraryProfilePayloadFile {
	out := make([]blueprint.LibraryProfilePayloadFile, len(files))
	for i, file := range files {
		sum := sha256.Sum256([]byte(file.ContentUTF8))
		file.SHA256 = "sha256:" + hex.EncodeToString(sum[:])
		out[i] = file
	}
	return out
}

func testLibraryProfilePayloadDigest(t *testing.T, files []blueprint.LibraryProfilePayloadFile) string {
	t.Helper()
	version := "0.1.0"
	for _, file := range files {
		if file.Path == "profile.yaml" && strings.Contains(file.ContentUTF8, "version: 0.2.0") {
			version = "0.2.0"
		}
	}
	result, err := blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir:        t.TempDir(),
		BlueprintRef:     "aweb.engineering",
		BlueprintVersion: "0.1.0",
		ProfileRef:       "coordinator",
		ProfileVersion:   version,
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
