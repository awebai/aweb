package profilepack

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEngineeringProfilePackFixtureInspectAndImportPayload(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	source := filepath.Join(fixture, "source")
	pack, err := LoadLocalDir(source)
	if err != nil {
		t.Fatalf("LoadLocalDir: %v", err)
	}
	plan := InspectPlan(pack)
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
	if digest != pack.Source.Digest {
		t.Fatalf("digest mismatch: got %s want %s", pack.Source.Digest, digest)
	}
}

func TestEngineeringProfilePackDigestVectorPinsPathBases(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	var vector map[string]any
	if err := json.Unmarshal(readFixtureFile(t, filepath.Join(fixture, "expected/digest-inputs.json")), &vector); err != nil {
		t.Fatal(err)
	}
	if vector["pack_payload_schema"] != "aweb.profile-pack.import-payload.v1" || vector["pack_payload_path_base"] != "pack-relative" {
		t.Fatalf("pack path base not pinned: %+v", vector)
	}
	if vector["profile_payload_schema"] != "aweb.profile-pack.profile-payload.v1" || vector["profile_payload_path_base"] != "profile-relative" {
		t.Fatalf("profile path base not pinned: %+v", vector)
	}
	packFields := vector["pack_payload_fields"].(map[string]any)
	profileFields := vector["profile_payload_fields"].(map[string]any)
	if packFields["path_base"] != "pack-relative" || profileFields["path_base"] != "profile-relative" {
		t.Fatalf("payload field path bases not pinned: pack=%v profile=%v", packFields["path_base"], profileFields["path_base"])
	}
}

func TestEngineeringProfilePackNegativeFixtures(t *testing.T) {
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
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../test-vectors/profile-packs/engineering"))
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
