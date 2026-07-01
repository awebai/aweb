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
)

func writeTestBlueprintSource(t *testing.T, root string) {
	t.Helper()
	write := func(rel, content string) {
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("blueprint.yaml", `id: aweb.ops
name: Ops Blueprint
version: 0.1.0
summary: Ops profile.
description: Ops starter.
profiles:
  - id: coordinator
    default_count: 1
    min: 1
    max: 1
    runtime_hints: [claude-code]
runtime_hints: [claude-code]
expected_apps: [library, tasks]
first_mission_examples:
  - Run ops.
`)
	write("README.md", "# Ops\n")
	write("profiles/coordinator/profile.yaml", `id: coordinator
name: Coordinator
version: 0.1.0
mission: Coordinate the agent team.
accepted_work: [planning, coordination]
instructions: instructions.md
runtime_assumptions: [local shell]
memory_policy:
  mode: reviewed-learning
  proposal_target: library
expected_apps: [library, tasks]
`)
	write("profiles/coordinator/instructions.md", "Coordinate work.\n")
}

func TestBlueprintPublishProfilePacksAndSignsPost(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")

	_, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(priv.Public().(ed25519.PublicKey))
	writeLocalTeamSignedRequestWorkspaceForTest(t, home, "https://library.invalid", "default:acme.com", "coordinator", did, priv)

	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/profiles" || r.Method != http.MethodPost {
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("X-AWID-Team-Certificate") == "" {
			t.Fatalf("publish must be team-signed: %#v", r.Header)
		}
		if err := json.NewDecoder(r.Body).Decode(&gotBody); err != nil {
			t.Fatal(err)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"profile_ref": "coordinator", "version": "0.1.0", "digest": "sha256:abc"})
	}))
	defer server.Close()
	writeLibraryManifestPluginForTest(t, home, server.URL)

	source := filepath.Join(t.TempDir(), "src")
	writeTestBlueprintSource(t, source)

	var out bytes.Buffer
	if err := withWorkingDir(home, func() error {
		return runBlueprintPublishProfile(&out, source, "coordinator", []string{"ops"}, false)
	}); err != nil {
		t.Fatalf("runBlueprintPublishProfile: %v", err)
	}

	// the signed POST carried the locally-packed files + the tag.
	files, ok := gotBody["files"].([]any)
	if !ok || len(files) == 0 {
		t.Fatalf("no files in POST body: %#v", gotBody)
	}
	f0 := files[0].(map[string]any)
	if f0["path"] == nil || f0["sha256"] == nil || f0["content_utf8"] == nil {
		t.Fatalf("packed file missing fields: %#v", f0)
	}
	tags, _ := gotBody["tags"].([]any)
	if len(tags) != 1 || tags[0] != "ops" {
		t.Fatalf("tags not carried: %#v", gotBody["tags"])
	}
	if !strings.Contains(out.String(), "coordinator@0.1.0") {
		t.Fatalf("unexpected output: %s", out.String())
	}
}
