//go:build e2e

package e2e

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The manifest dispatch must apply the real service's files and prune only its
// previous managed set (docs/blueprint-materialization-contract.md:257-275).
func TestRealStackLibraryMaterializeLocalWritesAndPrunesManagedFiles(t *testing.T) {
	requireE2E(t)
	tm := newThrowawayTeam(t)
	installLibrary(t, libraryInstall{dir: tm.workspace, env: tm.env, namespace: tm.namespace, team: "default"})
	workspacePath := filepath.Join(tm.workspace, ".aw", "workspace.yaml")
	unmanaged := filepath.Join(tm.workspace, "local-state.txt")
	writeFile(t, unmanaged, "operator-owned state\n")

	firstBody := writeMaterializeDispatchProfile(t, []materializeDispatchFile{
		{Path: "profile.yaml", ContentUTF8: materializeDispatchProfileYAML + "artifacts:\n  - path: artifacts/obsolete.md\n    kind: status_template\n"},
		{Path: "instructions.md", ContentUTF8: "Build from the first shelf version.\n"},
		{Path: "artifacts/obsolete.md", ContentUTF8: "first-version artifact\n"},
	})
	first := decodeMaterializeDispatchVersion(t, tm.library(t, "create-shelf-profile", "--body-file", firstBody))
	if first.Version != "0.1.0" {
		t.Fatalf("created shelf version=%q, want 0.1.0", first.Version)
	}
	first.bind(t, tm)
	requestBody := writeMaterializeDispatchJSON(t, map[string]string{
		"agent_id": tm.alias, "runtime_kind": "claude-code", "target": "local",
	})
	tm.library(t, "materialize", "--body-file", requestBody)
	for _, rel := range []string{"artifacts/obsolete.md", ".aw/profile/artifacts/obsolete.md"} {
		data, err := os.ReadFile(filepath.Join(tm.workspace, filepath.FromSlash(rel)))
		if err != nil || string(data) != "first-version artifact\n" {
			t.Fatalf("initial materialize did not write %s: %v", rel, err)
		}
	}
	oldPin := readMaterializeDispatchPin(t, tm.workspace)
	if oldPin.ProfileVersion != first.Version || oldPin.ProfileDigest != first.Digest || !slices.Contains(oldPin.ManagedSet, "artifacts/obsolete.md") {
		t.Fatalf("first pin does not match its real shelf version: %+v", oldPin)
	}

	secondBody := writeMaterializeDispatchProfile(t, []materializeDispatchFile{
		{Path: "profile.yaml", ContentUTF8: strings.Replace(materializeDispatchProfileYAML, "version: 0.1.0", "version: 0.2.0", 1)},
		{Path: "instructions.md", ContentUTF8: "Build from the second shelf version.\n"},
	})
	second := decodeMaterializeDispatchVersion(t, tm.library(t, "shelf-version", "--profile_ref", "developer", "--body-file", secondBody))
	if second.Version != "0.2.0" || second.Digest == first.Digest {
		t.Fatalf("shelf update did not create the requested new content version: %+v", second)
	}
	second.bind(t, tm)
	workspaceBefore, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatal(err)
	}
	tm.library(t, "materialize", "--body-file", requestBody)
	for _, rel := range []string{"artifacts/obsolete.md", ".aw/profile/artifacts/obsolete.md"} {
		if _, err := os.Lstat(filepath.Join(tm.workspace, filepath.FromSlash(rel))); !os.IsNotExist(err) {
			t.Fatalf("removed managed path %s survived: %v", rel, err)
		}
	}
	agents, err := os.ReadFile(filepath.Join(tm.workspace, "AGENTS.md"))
	if err != nil || !strings.Contains(string(agents), "Build from the second shelf version.") {
		t.Fatalf("second materialize did not replace the home body: %v", err)
	}
	if target, err := os.Readlink(filepath.Join(tm.workspace, "CLAUDE.md")); err != nil || target != "AGENTS.md" {
		t.Fatalf("runtime link=%q err=%v", target, err)
	}
	if data, err := os.ReadFile(unmanaged); err != nil || string(data) != "operator-owned state\n" {
		t.Fatalf("materialize changed unmanaged state: %v", err)
	}
	if data, err := os.ReadFile(workspacePath); err != nil || !bytes.Equal(data, workspaceBefore) {
		t.Fatalf("materialize changed the connected workspace: %v", err)
	}
	pin := readMaterializeDispatchPin(t, tm.workspace)
	if pin.ProfileRef != second.ProfileRef || pin.ProfileVersion != second.Version || pin.ProfileDigest != second.Digest || pin.RuntimeKind != "claude-code" {
		t.Fatalf("second pin does not match its bound shelf version: %+v", pin)
	}
	expectedManaged := []string{"AGENTS.md", "CLAUDE.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md", ".aw/profile/ref.json"}
	if !slices.Equal(pin.ManagedSet, expectedManaged) {
		t.Fatalf("second pin managed set=%v, want %v", pin.ManagedSet, expectedManaged)
	}
}

const materializeDispatchProfileYAML = `id: developer
name: Developer
version: 0.1.0
mission: Build locally.
accepted_work: [development]
instructions: instructions.md
runtime_assumptions: [local shell]
memory_policy:
  mode: reviewed-learning
  proposal_target: library
`

type materializeDispatchFile struct {
	Path        string `json:"path"`
	ContentUTF8 string `json:"content_utf8"`
	SHA256      string `json:"sha256"`
}

func writeMaterializeDispatchProfile(t *testing.T, files []materializeDispatchFile) string {
	t.Helper()
	for i := range files {
		files[i].SHA256 = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(files[i].ContentUTF8)))
	}
	return writeMaterializeDispatchJSON(t, struct {
		Files []materializeDispatchFile `json:"files"`
	}{Files: files})
}

func writeMaterializeDispatchJSON(t *testing.T, body any) string {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "request.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

type materializeDispatchVersion struct {
	ProfileRef string `json:"profile_ref"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
}

func decodeMaterializeDispatchVersion(t *testing.T, body string) materializeDispatchVersion {
	t.Helper()
	var version materializeDispatchVersion
	if err := json.Unmarshal([]byte(body), &version); err != nil {
		t.Fatal(err)
	}
	if version.ProfileRef != "developer" || version.Version == "" || version.Digest == "" {
		t.Fatalf("shelf version lacks its content identity: %+v", version)
	}
	return version
}

func (version materializeDispatchVersion) bind(t *testing.T, tm *e2eTeam) {
	t.Helper()
	tm.library(t, "bind", "--agent_id", tm.alias, "--profile_ref", version.ProfileRef,
		"--profile_version", version.Version, "--profile_digest", version.Digest)
}

type materializeDispatchPin struct {
	ProfileRef     string   `json:"profile_ref"`
	ProfileVersion string   `json:"profile_version"`
	ProfileDigest  string   `json:"profile_digest"`
	RuntimeKind    string   `json:"runtime_kind"`
	ManagedSet     []string `json:"managed_set"`
}

func readMaterializeDispatchPin(t *testing.T, home string) materializeDispatchPin {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(home, ".aw", "profile", "ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	var pin materializeDispatchPin
	if err := json.Unmarshal(data, &pin); err != nil {
		t.Fatal(err)
	}
	return pin
}
