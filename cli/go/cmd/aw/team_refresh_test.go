package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
	"github.com/awebai/aw/internal/blueprint"
	"github.com/spf13/cobra"
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

func TestRefreshPublicLibraryProfileNoOpsWhenDigestUnchanged(t *testing.T) {
	home := t.TempDir()
	files := testLibraryProfilePayloadFiles()
	digest := testLibraryProfilePayloadDigest(t, files)
	gets := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gets++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/coordinator" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "coordinator", "version": "0.1.0", "digest": digest, "files": files})
	}))
	defer server.Close()
	old := recordedProfileRef{LibraryURL: server.URL, ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: digest, SourceBlueprintRef: "aweb.engineering", SourceBlueprintVersion: "0.1.0", ManagedSet: []string{"AGENTS.md", ".aw/profile/ref.json"}}
	if err := writeRecordedProfileRef(home, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "AGENTS.md"), []byte("local existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	oldHomeFlag, oldJSONFlag, oldRuntime := agentHomeFlag, jsonFlag, teamRefreshRuntime
	agentHomeFlag, jsonFlag, teamRefreshRuntime = home, false, "claude-code"
	t.Cleanup(func() {
		agentHomeFlag, jsonFlag, teamRefreshRuntime = oldHomeFlag, oldJSONFlag, oldRuntime
	})
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)

	if err := runTeamRefresh(cmd, []string{"coordinator"}); err != nil {
		t.Fatalf("runTeamRefresh: %v", err)
	}
	if gets != 1 {
		t.Fatalf("public profile gets=%d, want 1", gets)
	}
	if !strings.Contains(out.String(), "latest public profile version") || !strings.Contains(out.String(), "source: public catalog "+server.URL) || strings.Contains(out.String(), "shelf version") {
		t.Fatalf("public no-op refresh described the wrong source: %q", out.String())
	}
	data, err := os.ReadFile(filepath.Join(home, "AGENTS.md"))
	if err != nil || string(data) != "local existing\n" {
		t.Fatalf("no-op refresh wrote AGENTS.md: %q err=%v", data, err)
	}
}

func TestRefreshPublicLibraryProfileMaterializesMissingManagedPathDespiteUnchangedDigest(t *testing.T) {
	home := t.TempDir()
	files := testLibraryProfilePayloadFiles()
	files = append(files, blueprint.LibraryProfilePayloadFile{Path: "patterns/unconsumed.md", ContentUTF8: "unconsumed\n"})
	files = withLibraryPayloadFileSHA(files)
	digest := testLibraryProfilePayloadDigest(t, files)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/coordinator" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "coordinator", "version": "0.1.0", "digest": digest, "files": files})
	}))
	defer server.Close()
	old := recordedProfileRef{LibraryURL: server.URL, ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: digest, SourceBlueprintRef: "aweb.engineering", SourceBlueprintVersion: "0.1.0", ManagedSet: []string{"AGENTS.md", ".aw/profile/ref.json"}}
	refPath := filepath.Join(home, ".aw", "profile", "ref.json")
	if err := os.MkdirAll(filepath.Dir(refPath), 0o755); err != nil {
		t.Fatal(err)
	}
	refData, err := json.Marshal(old)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(refPath, refData, 0o644); err != nil {
		t.Fatal(err)
	}
	oldHomeFlag, oldJSONFlag, oldRuntime := agentHomeFlag, jsonFlag, teamRefreshRuntime
	agentHomeFlag, jsonFlag, teamRefreshRuntime = home, false, "claude-code"
	t.Cleanup(func() {
		agentHomeFlag, jsonFlag, teamRefreshRuntime = oldHomeFlag, oldJSONFlag, oldRuntime
	})
	cmd := &cobra.Command{}
	var out bytes.Buffer
	cmd.SetOut(&out)

	if err := runTeamRefresh(cmd, []string{"coordinator"}); err != nil {
		t.Fatalf("runTeamRefresh: %v", err)
	}
	if !strings.Contains(out.String(), "re-materialized") {
		t.Fatalf("repair did not report written files: %q", out.String())
	}
	if !strings.Contains(out.String(), "WARNING: library profile asset patterns/unconsumed.md is not declared by profile.yaml and was not materialized (warning only)") {
		t.Fatalf("refresh output omitted unmaterialized-asset warning: %q", out.String())
	}
	if data, err := os.ReadFile(filepath.Join(home, "AGENTS.md")); err != nil || !strings.Contains(string(data), "Coordinate.") {
		t.Fatalf("missing body was not materialized: %q err=%v", data, err)
	}
}

func TestRefreshPublicLibraryProfileRejectsDishonestUnchangedDigest(t *testing.T) {
	home := t.TempDir()
	files := testLibraryProfilePayloadFiles()
	digest := testLibraryProfilePayloadDigest(t, files)
	corrupt := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Coordinate.\n"},
	})
	corrupt[1].ContentUTF8 = "tampered without updating sha\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/coordinator" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "coordinator", "version": "0.1.0", "digest": digest, "files": corrupt})
	}))
	defer server.Close()
	old := recordedProfileRef{LibraryURL: server.URL, ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: digest, SourceBlueprintRef: "aweb.engineering", SourceBlueprintVersion: "0.1.0", ManagedSet: []string{"AGENTS.md"}}
	if err := os.WriteFile(filepath.Join(home, "AGENTS.md"), []byte("local existing\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := refreshLibraryProfileInHome(home, "coordinator", old, "claude-code")
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("dishonest unchanged digest error=%v", err)
	}
	data, readErr := os.ReadFile(filepath.Join(home, "AGENTS.md"))
	if readErr != nil || string(data) != "local existing\n" {
		t.Fatalf("failed-closed refresh mutated AGENTS.md: %q err=%v", data, readErr)
	}
}

func TestRefreshPublicLibraryProfilePrunesRemovedManagedFilesOnly(t *testing.T) {
	home := t.TempDir()
	oldFiles := refreshTestProfileFiles(true, "0.1.0")
	newFiles := refreshTestProfileFiles(false, "0.2.0")
	oldDigest := testLibraryProfilePayloadDigest(t, oldFiles)
	newDigest := testLibraryProfilePayloadDigest(t, newFiles)
	currentFiles := oldFiles
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/coordinator" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		digest := oldDigest
		version := "0.1.0"
		if currentFiles[0].ContentUTF8 == newFiles[0].ContentUTF8 {
			digest = newDigest
			version = "0.2.0"
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "coordinator", "version": version, "digest": digest, "files": currentFiles})
	}))
	defer server.Close()
	selector := libraryProfileSelector{LibraryURL: server.URL, SourceBlueprintRef: "aweb.engineering", ProfileRef: "coordinator", RuntimeKind: "claude-code"}
	if _, _, err := applyPublicLibraryProfileToHome(home, selector, true); err != nil {
		t.Fatalf("initial materialize: %v", err)
	}
	old, err := readRecordedProfileRef(home)
	if err != nil {
		t.Fatal(err)
	}
	localPath := filepath.Join(home, ".aw", "runtime", "state.json")
	if err := os.MkdirAll(filepath.Dir(localPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(localPath, []byte("local\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	currentFiles = newFiles

	result, err := refreshLibraryProfileInHome(home, "coordinator", old, "claude-code")
	if err != nil {
		t.Fatalf("refreshLibraryProfileInHome: %v", err)
	}
	if result.ProfileDigest != newDigest || len(result.FilesWritten) == 0 {
		t.Fatalf("refresh result=%+v want digest %s", result, newDigest)
	}
	for _, rel := range []string{"skills/old/SKILL.md", ".aw/profile/skills/old/SKILL.md", ".claude/skills/old/SKILL.md"} {
		if _, err := os.Lstat(filepath.Join(home, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Fatalf("removed upstream managed file still exists %s: %v", rel, err)
		}
	}
	if data, err := os.ReadFile(localPath); err != nil || string(data) != "local\n" {
		t.Fatalf("local runtime state not preserved: %q err=%v", data, err)
	}
}

func TestTeamRefreshUpdatesExistingCoordinationBlockFromActiveInstructions(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	oldFiles := refreshTestProfileFiles(false, "0.1.0")
	newFiles := refreshTestProfileFiles(false, "0.2.0")
	oldDigest := testLibraryProfilePayloadDigest(t, oldFiles)
	newDigest := testLibraryProfilePayloadDigest(t, newFiles)
	currentInstructions := "## Current instructions\n\nRead mail before claiming work."
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/profiles/coordinator":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"profile_ref": "coordinator", "version": "0.2.0", "digest": newDigest,
				"source_blueprint_ref": "aweb.engineering", "source_blueprint_version": "0.1.0",
				"source_blueprint_digest": "sha256:blueprint", "files": newFiles,
			})
		case "/v1/instructions/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_instructions_id": "instructions-v3", "active_team_instructions_id": "instructions-v3",
				"team_id": "default:acme.com", "version": 3,
				"document": map[string]any{"body_md": currentInstructions, "format": "markdown"},
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, server.URL, "default:acme.com", "coordinator", did, priv)
	writeLibraryShelfManifestPluginForTest(t, home, server.URL)

	if _, err := blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir: home, BlueprintRef: "aweb.engineering", BlueprintVersion: "0.1.0", BlueprintDigest: "sha256:blueprint",
		ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: oldDigest,
		RuntimeKind: "claude-code", Files: oldFiles, Force: true,
	}); err != nil {
		t.Fatalf("initial materialize: %v", err)
	}
	staleInstructions := "## Superseded instructions\n\nClaim work before reading mail."
	if result := InjectProvidedAgentDocs(home, staleInstructions); len(result.Errors) > 0 {
		t.Fatalf("inject stale coordination block: %v", result.Errors)
	}

	oldHomeFlag, oldJSONFlag, oldRuntime := agentHomeFlag, jsonFlag, teamRefreshRuntime
	agentHomeFlag, jsonFlag, teamRefreshRuntime = home, false, "claude-code"
	t.Cleanup(func() {
		agentHomeFlag, jsonFlag, teamRefreshRuntime = oldHomeFlag, oldJSONFlag, oldRuntime
	})
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	if err := runTeamRefresh(cmd, []string{"coordinator"}); err != nil {
		t.Fatalf("runTeamRefresh: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Coordinate 0.2.0.") || strings.Contains(text, "Coordinate 0.1.0.") {
		t.Fatalf("refresh did not advance profile-managed content:\n%s", text)
	}
	if !strings.Contains(text, currentInstructions) || strings.Contains(text, staleInstructions) {
		t.Fatalf("refresh did not replace stale coordination instructions:\n%s", text)
	}
	if strings.Count(text, awDocsMarkerStart) != 1 || strings.Count(text, awDocsMarkerEnd) != 1 {
		t.Fatalf("refresh did not leave exactly one complete marker pair:\n%s", text)
	}

	newerInstructions := "## Newer instructions\n\nRead all waiting messages first."
	currentInstructions = newerInstructions
	if err := runTeamRefresh(cmd, []string{"coordinator"}); err != nil {
		t.Fatalf("runTeamRefresh with unchanged profile: %v", err)
	}
	data, err = os.ReadFile(filepath.Join(home, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text = string(data)
	if !strings.Contains(text, newerInstructions) || strings.Contains(text, "## Current instructions") {
		t.Fatalf("unchanged-profile refresh did not advance team instructions:\n%s", text)
	}
	if strings.Count(text, awDocsMarkerStart) != 1 || strings.Count(text, awDocsMarkerEnd) != 1 {
		t.Fatalf("unchanged-profile refresh did not leave exactly one complete marker pair:\n%s", text)
	}
}

func TestTeamRefreshRejectsCoordinationDocsSymlinkOutsideHome(t *testing.T) {
	skipIfNoSymlinkSupport(t)

	home := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.md")
	original := []byte(renderInjectedDocs("## Outside instructions\n\nDo not change."))
	if err := os.WriteFile(outside, original, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(home, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	if err := writeRecordedProfileRef(home, recordedProfileRef{ProfileRef: "coordinator"}); err != nil {
		t.Fatal(err)
	}

	oldHomeFlag, oldJSONFlag, oldRuntime := agentHomeFlag, jsonFlag, teamRefreshRuntime
	agentHomeFlag, jsonFlag, teamRefreshRuntime = home, false, "claude-code"
	t.Cleanup(func() {
		agentHomeFlag, jsonFlag, teamRefreshRuntime = oldHomeFlag, oldJSONFlag, oldRuntime
	})
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	err := runTeamRefresh(cmd, []string{"coordinator"})
	if err == nil {
		t.Fatal("expected refresh to reject coordination-doc symlink outside home")
	}
	for _, want := range []string{home, outside} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refresh escape error %q does not name %q", err, want)
		}
	}
	data, readErr := os.ReadFile(outside)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(data) != string(original) {
		t.Fatalf("refresh modified outside file:\n%s", data)
	}
}

func TestTeamRefreshLeavesUnmarkedHomeUnmarked(t *testing.T) {
	home := t.TempDir()
	oldFiles := refreshTestProfileFiles(false, "0.1.0")
	newFiles := refreshTestProfileFiles(false, "0.2.0")
	oldDigest := testLibraryProfilePayloadDigest(t, oldFiles)
	newDigest := testLibraryProfilePayloadDigest(t, newFiles)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/coordinator" {
			t.Fatalf("unmarked refresh made unexpected request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0",
			"profile_ref": "coordinator", "version": "0.2.0", "digest": newDigest, "files": newFiles,
		})
	}))
	defer server.Close()
	if _, err := blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir: home, LibraryURL: server.URL, BlueprintRef: "aweb.engineering", BlueprintVersion: "0.1.0",
		ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: oldDigest,
		RuntimeKind: "claude-code", Files: oldFiles, Force: true,
	}); err != nil {
		t.Fatalf("initial materialize: %v", err)
	}

	oldHomeFlag, oldJSONFlag, oldRuntime := agentHomeFlag, jsonFlag, teamRefreshRuntime
	agentHomeFlag, jsonFlag, teamRefreshRuntime = home, false, "claude-code"
	t.Cleanup(func() {
		agentHomeFlag, jsonFlag, teamRefreshRuntime = oldHomeFlag, oldJSONFlag, oldRuntime
	})
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	if err := runTeamRefresh(cmd, []string{"coordinator"}); err != nil {
		t.Fatalf("runTeamRefresh: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(home, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "Coordinate 0.2.0.") || strings.Contains(text, "Coordinate 0.1.0.") {
		t.Fatalf("refresh did not advance profile-managed content:\n%s", text)
	}
	if strings.Contains(text, awDocsMarkerStart) || strings.Contains(text, awDocsMarkerEnd) {
		t.Fatalf("refresh invented a coordination block in an unmarked home:\n%s", text)
	}
}

func TestRefreshShelfProfilePreservesInjectedCoordinationBlockWithoutInventingOne(t *testing.T) {
	for _, tc := range []struct {
		name       string
		injectDocs bool
	}{
		{name: "preserves marker-delimited block", injectDocs: true},
		{name: "does not inject an absent block", injectDocs: false},
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

			oldFiles := refreshTestProfileFiles(false, "0.1.0")
			newFiles := refreshTestProfileFiles(false, "0.2.0")
			oldDigest := testLibraryProfilePayloadDigest(t, oldFiles)
			newDigest := testLibraryProfilePayloadDigest(t, newFiles)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != "/v1/profiles/coordinator" {
					t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("X-AWID-Team-Certificate") == "" {
					t.Fatal("shelf refresh must be team-signed")
				}
				_ = json.NewEncoder(w).Encode(map[string]any{
					"profile_ref": "coordinator", "version": "0.2.0", "digest": newDigest,
					"source_blueprint_ref": "aweb.engineering", "source_blueprint_version": "0.1.0",
					"source_blueprint_digest": "sha256:blueprint", "files": newFiles,
				})
			}))
			defer server.Close()
			writeLibraryShelfManifestPluginForTest(t, home, server.URL)

			_, err = blueprint.MaterializeLibraryProfilePayload(blueprint.MaterializeLibraryProfilePayloadOptions{
				TargetDir:    home,
				BlueprintRef: "aweb.engineering", BlueprintVersion: "0.1.0", BlueprintDigest: "sha256:blueprint",
				ProfileRef: "coordinator", ProfileVersion: "0.1.0", ProfileDigest: oldDigest,
				RuntimeKind: "claude-code", Files: oldFiles, Force: true,
			})
			if err != nil {
				t.Fatalf("initial materialize: %v", err)
			}
			old, err := readRecordedProfileRef(home)
			if err != nil {
				t.Fatal(err)
			}
			coordination := "## Coordination sentinel\n\nUse `aw`."
			if tc.injectDocs {
				result := InjectProvidedAgentDocs(home, coordination)
				if len(result.Errors) > 0 {
					t.Fatalf("inject coordination block: %v", result.Errors)
				}
			}

			if _, err := refreshLibraryProfileInHome(home, "coordinator", old, "claude-code"); err != nil {
				t.Fatalf("refreshLibraryProfileInHome: %v", err)
			}
			data, err := os.ReadFile(filepath.Join(home, "AGENTS.md"))
			if err != nil {
				t.Fatal(err)
			}
			text := string(data)
			if !strings.Contains(text, "Coordinate 0.2.0.") || strings.Contains(text, "Coordinate 0.1.0.") {
				t.Fatalf("refresh did not update profile-managed content:\n%s", text)
			}
			if tc.injectDocs {
				if !strings.Contains(text, awDocsMarkerEnd) {
					t.Fatalf("refresh stripped complete coordination block (missing AWEB:END):\n%s", text)
				}
				if strings.Count(text, awDocsMarkerStart) != 1 || strings.Count(text, awDocsMarkerEnd) != 1 || !strings.Contains(text, renderInjectedDocs(coordination)) {
					t.Fatalf("refresh did not preserve exactly one complete coordination block:\n%s", text)
				}
			} else if strings.Contains(text, awDocsMarkerStart) || strings.Contains(text, awDocsMarkerEnd) {
				t.Fatalf("refresh invented a coordination block in an unmarked home:\n%s", text)
			}
		})
	}
}

func TestMaterializeAndPruneMigratesLegacyClaudeSkillLinkAndIsIdempotent(t *testing.T) {
	home := t.TempDir()
	legacyDir := filepath.Join(home, ".claude", "skills", "implement")
	if err := os.MkdirAll(legacyDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../skills/implement/SKILL.md", filepath.Join(legacyDir, "SKILL.md")); err != nil {
		t.Fatal(err)
	}
	files := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: developer\nname: Developer\nversion: 0.1.0\nmission: Implement.\naccepted_work: [implementation]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\nskills:\n  - path: skills/implement/SKILL.md\n"},
		{Path: "instructions.md", ContentUTF8: "Implement.\n"},
		{Path: "skills/implement/SKILL.md", ContentUTF8: "# Implement\n"},
		{Path: "skills/implement/assets/checklist.md", ContentUTF8: "# Checklist\n"},
	})
	digest := testLibraryProfilePayloadDigestForProfile(t, "developer", files)
	opts := blueprint.MaterializeLibraryProfilePayloadOptions{
		TargetDir: home, ProfileRef: "developer", ProfileVersion: "0.1.0", ProfileDigest: digest,
		RuntimeKind: "claude-code", Files: files, Force: true,
	}
	old := recordedProfileRef{ManagedSet: []string{".claude/skills/implement/SKILL.md"}}

	result, err := materializeAndPruneLibraryProfileInHome(home, old, opts)
	if err != nil {
		t.Fatalf("legacy refresh transition: %v", err)
	}
	if got, readErr := os.Readlink(filepath.Join(home, ".claude", "skills", "implement")); readErr != nil || got != "../../skills/implement" {
		t.Fatalf("Claude skill directory link=%q err=%v", got, readErr)
	}
	for _, rel := range []string{
		"skills/implement/SKILL.md",
		"skills/implement/assets/checklist.md",
		".aw/profile/skills/implement/SKILL.md",
		".aw/profile/skills/implement/assets/checklist.md",
	} {
		if _, statErr := os.Stat(filepath.Join(home, filepath.FromSlash(rel))); statErr != nil {
			t.Fatalf("projected file %s: %v", rel, statErr)
		}
	}
	var refreshed recordedProfileRef
	refData, err := os.ReadFile(filepath.Join(home, ".aw", "profile", "ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(refData, &refreshed); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(refreshed.ManagedSet, ".claude/skills/implement") || slices.Contains(refreshed.ManagedSet, ".claude/skills/implement/SKILL.md") {
		t.Fatalf("new managed_set did not record only the directory link: %v", refreshed.ManagedSet)
	}

	if _, err := materializeAndPruneLibraryProfileInHome(home, refreshed, opts); err != nil {
		t.Fatalf("new-layout refresh must be idempotent: %v", err)
	}
	if len(result.FilesWritten) == 0 {
		t.Fatal("transition did not report materialized files")
	}
}

func refreshTestProfileFiles(withSkill bool, version string) []blueprint.LibraryProfilePayloadFile {
	profile := "id: coordinator\nname: Coordinator\nversion: " + version + "\nmission: Coordinate.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"
	files := []blueprint.LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: profile}, {Path: "instructions.md", ContentUTF8: "Coordinate " + version + ".\n"}}
	if withSkill {
		files[0].ContentUTF8 += "skills:\n  - path: skills/old/SKILL.md\n"
		files = append(files, blueprint.LibraryProfilePayloadFile{Path: "skills/old/SKILL.md", ContentUTF8: "---\nname: old\n---\n# Old\n"})
	}
	return withLibraryPayloadFileSHA(files)
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
	files = append(files, blueprint.LibraryProfilePayloadFile{Path: "patterns/common-failure-patterns.md", ContentUTF8: "# Shelf-only lesson\n"})
	files = withLibraryPayloadFileSHA(files)
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
	if len(result.Warnings) != 1 || !strings.Contains(result.Warnings[0], "patterns/common-failure-patterns.md") {
		t.Fatalf("refresh did not report shelf-only asset: %+v", result.Warnings)
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
