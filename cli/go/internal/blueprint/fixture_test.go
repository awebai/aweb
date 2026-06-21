package blueprint

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEngineeringBlueprintFixtureInspectAndImportPayload(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	source := filepath.Join(fixture, "source")
	bp, err := LoadLocalDir(source)
	if err != nil {
		t.Fatalf("LoadLocalDir: %v", err)
	}
	plan := InspectPlan(bp)
	plan.Source.Ref = "FIXTURE/source"
	actual, err := json.MarshalIndent(plan, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	actual = append(actual, '\n')
	expected := readFixtureFile(t, filepath.Join(fixture, "expected/inspect.json"))
	if !bytes.Equal(actual, expected) {
		t.Fatalf("inspect JSON mismatch\nactual:\n%s\nexpected:\n%s", actual, expected)
	}

	payload, err := CanonicalImportPayload(source)
	if err != nil {
		t.Fatalf("CanonicalImportPayload: %v", err)
	}
	expectedPayload := bytes.TrimSpace(readFixtureFile(t, filepath.Join(fixture, "expected/import-payload.canonical.json")))
	if !bytes.Equal(payload, expectedPayload) {
		t.Fatalf("canonical import payload mismatch")
	}
	digest := strings.TrimSpace(string(readFixtureFile(t, filepath.Join(fixture, "expected/import-payload.digest"))))
	if digest != bp.Source.Digest {
		t.Fatalf("digest mismatch: got %s want %s", bp.Source.Digest, digest)
	}
}

func TestEngineeringBlueprintDigestVectorPinsPathBases(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	var vector map[string]any
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(fixture, "expected/digest-inputs.json")), &vector); err != nil {
		t.Fatal(err)
	}
	if vector["blueprint_payload_schema"] != "aweb.blueprint.import-payload.v1" || vector["blueprint_payload_path_base"] != "blueprint-relative" {
		t.Fatalf("blueprint path base not pinned: %+v", vector)
	}
	if vector["profile_payload_schema"] != "aweb.blueprint.profile-payload.v1" || vector["profile_payload_path_base"] != "profile-relative" {
		t.Fatalf("profile path base not pinned: %+v", vector)
	}
	blueprintFields := vector["blueprint_payload_fields"].(map[string]any)
	profileFields := vector["profile_payload_fields"].(map[string]any)
	if blueprintFields["path_base"] != "blueprint-relative" || profileFields["path_base"] != "profile-relative" {
		t.Fatalf("payload field path bases not pinned: blueprint=%v profile=%v", blueprintFields["path_base"], profileFields["path_base"])
	}
}

func TestMaterializeCreatedProfilePayloadMatchesEngineeringFixture(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	profileRoot := filepath.Join(fixture, "source", "profiles", "developer")
	var files []LibraryProfilePayloadFile
	if err := filepath.WalkDir(profileRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(profileRoot, path)
		if err != nil {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		files = append(files, LibraryProfilePayloadFile{Path: filepath.ToSlash(rel), ContentUTF8: string(data)})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	result, err := MaterializeLibraryProfilePayload(MaterializeLibraryProfilePayloadOptions{
		TargetDir:      target,
		ProfileRef:     "developer",
		ProfileVersion: "0.1.0",
		RuntimeKind:    "claude-code",
		Files:          files,
	})
	if err != nil {
		t.Fatalf("MaterializeLibraryProfilePayload: %v", err)
	}
	if result.SourceBlueprintRef != "" || result.SourceBlueprintVersion != "" || result.SourceBlueprintDigest != "" {
		t.Fatalf("created result included source blueprint provenance: %+v", result)
	}
	expected := filepath.Join(fixture, "expected", "materialized-home-created", "developer")
	if err := compareMaterializedTrees(expected, target); err != nil {
		t.Fatalf("created materialized tree mismatch: %v", err)
	}
}

func TestEngineeringBlueprintAgentHomeCompositionFixtures(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	for _, id := range []string{"coordinator", "developer", "reviewer"} {
		t.Run(id, func(t *testing.T) {
			home := filepath.Join(fixture, "expected", "materialized-home", id)
			agents := string(readFixtureFile(t, filepath.Join(home, "AGENTS.md")))
			if !strings.Contains(agents, "> Profile "+id+" v0.1.0 · blueprint aweb.engineering v0.1.0") {
				t.Fatalf("AGENTS.md missing source-blueprint provenance:\n%s", agents)
			}
			if strings.Contains(agents, "## Runtime assumptions") || strings.Contains(agents, "## Event subscriptions") {
				t.Fatalf("AGENTS.md rendered system config sections:\n%s", agents)
			}
			if link, err := os.Readlink(filepath.Join(home, "CLAUDE.md")); err != nil || link != "AGENTS.md" {
				t.Fatalf("CLAUDE.md symlink=%q err=%v", link, err)
			}
			if _, err := os.Stat(filepath.Join(home, ".aw", "profile", "profile.yaml")); err != nil {
				t.Fatalf("missing full profile source: %v", err)
			}
		})
	}
	assertInOrder(t, string(readFixtureFile(t, filepath.Join(fixture, "expected", "materialized-home", "coordinator", "AGENTS.md"))), []string{"- library", "- tasks", "- audit", "- secrets.read", "- github.merge_pr"})
	assertInOrder(t, string(readFixtureFile(t, filepath.Join(fixture, "expected", "materialized-home", "developer", "AGENTS.md"))), []string{"- tasks", "- github", "- audit"})
	assertInOrder(t, string(readFixtureFile(t, filepath.Join(fixture, "expected", "materialized-home", "reviewer", "AGENTS.md"))), []string{"- tasks", "- github", "- audit"})

	created := filepath.Join(fixture, "expected", "materialized-home-created", "developer")
	createdAgents := string(readFixtureFile(t, filepath.Join(created, "AGENTS.md")))
	if !strings.Contains(createdAgents, "> Profile developer v0.1.0 · created") {
		t.Fatalf("created fixture missing no-source-blueprint provenance:\n%s", createdAgents)
	}
	createdRef := string(readFixtureFile(t, filepath.Join(created, ".aw", "profile", "ref.json")))
	if strings.Contains(createdRef, "source_blueprint") {
		t.Fatalf("created fixture ref should not include source blueprint provenance:\n%s", createdRef)
	}
}

func assertInOrder(t *testing.T, text string, needles []string) {
	t.Helper()
	pos := -1
	for _, needle := range needles {
		next := strings.Index(text[pos+1:], needle)
		if next < 0 {
			t.Fatalf("%q not found after byte %d in:\n%s", needle, pos, text)
		}
		pos += next + 1
	}
}

func TestEngineeringBlueprintNegativeFixtures(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	cases := map[string]string{
		"aw-state":           ".aw runtime state",
		"private-key":        "identity material",
		"certificate":        "identity material",
		"token":              "identity material",
		"secret":             "unexpected identity material",
		"generated-worktree": "generated worktrees",
		"host-path":          "host or scheme paths",
		"symlink":            "symlinks are not allowed",
	}
	for name, want := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := LoadLocalDir(filepath.Join(fixture, "negatives", name))
			if err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("error=%v, want %q", err, want)
			}
		})
	}
}

func engineeringFixtureRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../test-vectors/blueprints/engineering"))
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root: %v", err)
	}
	return root
}

func readFixtureFile(t *testing.T, path string) []byte {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
