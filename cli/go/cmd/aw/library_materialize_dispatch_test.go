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

func TestLibraryManifestLocalMaterializeRejectsUnsignedReadOnlyToolBeforeRequest(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_HOME", "")
	managed := []string{"AGENTS.md", ".aw/profile/ref.json"}
	pin := recordedProfileRef{ProfileRef: "developer", ProfileVersion: "0.1.0", ProfileDigest: "sha256:profile", RuntimeKind: "claude-code", ManagedSet: managed}
	refData, err := json.Marshal(pin)
	if err != nil {
		t.Fatal(err)
	}
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_ref":     "developer",
			"profile_version": "0.1.0",
			"profile_digest":  "sha256:profile",
			"home_files": []blueprint.LibraryHomeFile{
				{Path: "AGENTS.md", Kind: "file", ContentUTF8: "unsigned\n"},
				{Path: ".aw/profile/ref.json", Kind: "file", ContentUTF8: string(refData)},
			},
		})
	}))
	defer server.Close()
	pluginDir := filepath.Join(home, ".aw", "plugins", "library")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + server.URL + `"},"tools":[` +
		`{"name":"materialize","method":"GET","path":"/v1/materialize","auth":"none","input_schema":{"type":"object","properties":{"runtime_kind":{"type":"string"},"target":{"type":"string"}}},"params":[{"name":"runtime_kind","in":"query"},{"name":"target","in":"query"}],"mutation":false}]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}

	err = withWorkingDir(home, func() error {
		_, _, err := executeInstalledManifestTool("library", []string{"materialize", "--runtime_kind", "claude-code", "--target", "local"})
		return err
	})
	if err == nil || !strings.Contains(err.Error(), "signed mutation") {
		t.Fatalf("unsigned local materialize error=%v", err)
	}
	if called {
		t.Fatal("unsigned read-only materialize reached the remote endpoint")
	}
	if _, err := os.Lstat(filepath.Join(home, "AGENTS.md")); !os.IsNotExist(err) {
		t.Fatalf("unsigned response mutated AGENTS.md: %v", err)
	}
}

func TestLibraryManifestMaterializeTargetLocalWritesCurrentHomeAndPrunes(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_HOME", "")
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))

	managed := []string{
		"AGENTS.md",
		"CLAUDE.md",
		".aw/profile/profile.yaml",
		".aw/profile/instructions.md",
		".aw/profile/ref.json",
	}
	newRef := recordedProfileRef{
		ProfileRef:     "developer",
		ProfileVersion: "0.2.0",
		ProfileDigest:  "sha256:new",
		RuntimeKind:    "claude-code",
		ManagedSet:     managed,
	}
	refData, err := json.MarshalIndent(newRef, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	homeFiles := []blueprint.LibraryHomeFile{
		{Path: "AGENTS.md", Kind: "file", ContentUTF8: "# Developer\n"},
		{Path: "CLAUDE.md", Kind: "symlink", Target: "AGENTS.md"},
		{Path: ".aw/profile/profile.yaml", Kind: "file", ContentUTF8: "id: developer\nversion: 0.2.0\n"},
		{Path: ".aw/profile/instructions.md", Kind: "file", ContentUTF8: "Build.\n"},
		{Path: ".aw/profile/ref.json", Kind: "file", ContentUTF8: string(append(refData, '\n'))},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/materialize" {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") == "" || r.Header.Get("X-AWID-Team-Certificate") == "" {
			t.Fatalf("materialize request was not team-authenticated: %#v", r.Header)
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["target"] != "local" || body["runtime_kind"] != "claude-code" || body["agent_id"] != "developer" {
			t.Fatalf("unexpected materialize body: %#v", body)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"profile_ref":     "developer",
			"profile_version": "0.2.0",
			"profile_digest":  "sha256:new",
			"home_files":      homeFiles,
		})
	}))
	defer server.Close()

	writeLocalTeamSignedRequestWorkspaceForTest(t, home, server.URL, "default:acme.com", "developer", did, priv)
	pluginDir := filepath.Join(home, ".aw", "plugins", "library")
	if err := os.MkdirAll(pluginDir, 0o755); err != nil {
		t.Fatal(err)
	}
	manifest := `{"manifest_version":1,"app":{"id":"library","version":"test","origin":"` + server.URL + `"},"tools":[` +
		`{"name":"materialize","method":"POST","path":"/v1/materialize","input_schema":{"type":"object","properties":{"agent_id":{"type":"string"},"runtime_kind":{"type":"string"},"target":{"type":"string"}}},"params":[{"name":"agent_id","in":"body"},{"name":"runtime_kind","in":"body"},{"name":"target","in":"body"}],"body":{"mode":"json"},"mutation":true}]}`
	if err := os.WriteFile(filepath.Join(pluginDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	oldRef := recordedProfileRef{ProfileRef: "developer", ProfileVersion: "0.1.0", ProfileDigest: "sha256:old", RuntimeKind: "claude-code", ManagedSet: []string{"obsolete.md", ".aw/profile/ref.json"}}
	oldRefData, err := json.Marshal(oldRef)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".aw", "profile"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".aw", "profile", "ref.json"), oldRefData, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "obsolete.md"), []byte("old\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "local-state.txt"), []byte("keep\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	requestPath := filepath.Join(home, ".aw", "materialize-request.json")
	if err := os.WriteFile(requestPath, []byte(`{"agent_id":"developer","runtime_kind":"claude-code","target":"local"}`), 0o600); err != nil {
		t.Fatal(err)
	}

	if err := withWorkingDir(home, func() error {
		result, exists, err := executeInstalledManifestTool("library", []string{"materialize", "--body-file", requestPath})
		if err != nil {
			return err
		}
		if !exists || result.Status != http.StatusOK {
			t.Fatalf("materialize dispatch exists=%v result=%+v", exists, result)
		}
		return nil
	}); err != nil {
		t.Fatalf("library materialize dispatch: %v", err)
	}

	if data, err := os.ReadFile(filepath.Join(home, "AGENTS.md")); err != nil || string(data) != "# Developer\n" {
		t.Fatalf("AGENTS.md=%q err=%v", data, err)
	}
	if target, err := os.Readlink(filepath.Join(home, "CLAUDE.md")); err != nil || target != "AGENTS.md" {
		t.Fatalf("CLAUDE.md target=%q err=%v", target, err)
	}
	if _, err := os.Lstat(filepath.Join(home, "obsolete.md")); !os.IsNotExist(err) {
		t.Fatalf("obsolete managed file survived: %v", err)
	}
	if data, err := os.ReadFile(filepath.Join(home, "local-state.txt")); err != nil || string(data) != "keep\n" {
		t.Fatalf("unmanaged local state=%q err=%v", data, err)
	}
	var got recordedProfileRef
	data, err := os.ReadFile(filepath.Join(home, ".aw", "profile", "ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.ProfileVersion != "0.2.0" || len(got.ManagedSet) != len(managed) {
		t.Fatalf("recorded ref=%+v", got)
	}
}
