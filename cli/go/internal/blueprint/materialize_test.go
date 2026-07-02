package blueprint

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestMaterializeLocalProfileMatchesEngineeringFixture(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	target := t.TempDir()
	result, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "developer", TargetDir: target})
	if err != nil {
		t.Fatalf("MaterializeLocalProfile: %v", err)
	}
	if result.ProfileRef != "developer" || result.ProfileVersion != "0.1.0" || !strings.HasPrefix(result.ProfileDigest, "sha256:") {
		t.Fatalf("unexpected result: %+v", result)
	}
	assertDirsEqual(t, filepath.Join(fixture, "expected/materialized-home/developer"), target)
}

func TestMaterializeLocalProfileRecordsRuntimeKind(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	target := t.TempDir()
	_, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "developer", TargetDir: target, RuntimeKind: "pi"})
	if err != nil {
		t.Fatalf("MaterializeLocalProfile: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(target, ".aw", "profile", "ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref struct {
		RuntimeKind string `json:"runtime_kind"`
	}
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	if ref.RuntimeKind != "pi" {
		t.Fatalf("runtime_kind=%q", ref.RuntimeKind)
	}
}

func TestMaterializeLibraryProfilePayloadAllowsFoldedBlockMission(t *testing.T) {
	target := t.TempDir()
	_, err := MaterializeLibraryProfilePayload(MaterializeLibraryProfilePayloadOptions{
		TargetDir:      target,
		ProfileRef:     "reviewer",
		ProfileVersion: "0.2.0",
		RuntimeKind:    "claude-code",
		Files: withPayloadFileSHA([]LibraryProfilePayloadFile{
			{Path: "profile.yaml", ContentUTF8: "id: reviewer\nname: Reviewer\nversion: 0.2.0\nmission: >\n  Give independent, fresh-eyes review before merge,\n  with blocking and non-blocking findings.\naccepted_work:\n  - >\n    reviewing a developer diff\n    against acceptance criteria\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
			{Path: "instructions.md", ContentUTF8: "Review changes carefully.\n"},
		}),
	})
	if err != nil {
		t.Fatalf("MaterializeLibraryProfilePayload: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "AGENTS.md")); err != nil {
		t.Fatalf("profile was not materialized: %v", err)
	}
}

func TestMaterializeLocalProfileRejectsTargetSymlinkEscape(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	target := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(target, "skills")); err != nil {
		t.Fatal(err)
	}
	_, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "developer", TargetDir: target})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "implement", "SKILL.md")); !os.IsNotExist(err) {
		t.Fatalf("materialize wrote through symlink, stat err=%v", err)
	}
	if _, err := os.Stat(filepath.Join(target, ".aw", "profile", "ref.json")); !os.IsNotExist(err) {
		t.Fatalf("preflight should prevent partial writes before symlink failure, stat err=%v", err)
	}
}

func TestMaterializeLocalProfileRejectsSymlinkedTargetParent(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	base := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(base, "link")); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "link", "agent")
	_, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "developer", TargetDir: target})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "agent")); !os.IsNotExist(err) {
		t.Fatalf("materialize created target through symlinked parent, stat err=%v", err)
	}
}

func TestMaterializeLocalProfileRejectsExistingDirectoryDestinationEvenWithForce(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	target := t.TempDir()
	if err := os.Mkdir(filepath.Join(target, "AGENTS.md"), 0o755); err != nil {
		t.Fatal(err)
	}
	_, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "developer", TargetDir: target, Force: true})
	if err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("error=%v", err)
	}
	if _, err := os.Stat(filepath.Join(target, ".aw", "profile", "ref.json")); !os.IsNotExist(err) {
		t.Fatalf("preflight should prevent partial writes before directory destination failure, stat err=%v", err)
	}
}

func TestMaterializeLocalProfileRequiresBoundProfileAndRefusesOverwrite(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	target := t.TempDir()
	_, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "missing", TargetDir: target})
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("missing profile error=%v", err)
	}
	if _, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "coordinator", TargetDir: target}); err != nil {
		t.Fatalf("initial materialize: %v", err)
	}
	_, err = MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "coordinator", TargetDir: target})
	if err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("overwrite error=%v", err)
	}
	if _, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "coordinator", TargetDir: target, Force: true}); err != nil {
		t.Fatalf("force materialize: %v", err)
	}
}

func assertDirsEqual(t *testing.T, wantDir, gotDir string) {
	t.Helper()
	wantFiles := listFiles(t, wantDir)
	gotFiles := listFiles(t, gotDir)
	if strings.Join(wantFiles, "\n") != strings.Join(gotFiles, "\n") {
		t.Fatalf("files mismatch\nwant=%v\ngot=%v", wantFiles, gotFiles)
	}
	for _, rel := range wantFiles {
		wantPath := filepath.Join(wantDir, filepath.FromSlash(rel))
		gotPath := filepath.Join(gotDir, filepath.FromSlash(rel))
		wantInfo, err := os.Lstat(wantPath)
		if err != nil {
			t.Fatal(err)
		}
		gotInfo, err := os.Lstat(gotPath)
		if err != nil {
			t.Fatal(err)
		}
		if wantInfo.Mode()&os.ModeSymlink != 0 {
			if gotInfo.Mode()&os.ModeSymlink == 0 {
				t.Fatalf("%s: got non-symlink", rel)
			}
			wantLink, _ := os.Readlink(wantPath)
			gotLink, _ := os.Readlink(gotPath)
			if wantLink != gotLink {
				t.Fatalf("%s: symlink target %q, want %q", rel, gotLink, wantLink)
			}
			continue
		}
		if gotInfo.Mode()&os.ModeSymlink != 0 {
			t.Fatalf("%s: got symlink, want regular file", rel)
		}
		want, err := os.ReadFile(wantPath)
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(gotPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("file %s mismatch\nwant=%s\ngot=%s", rel, want, got)
		}
	}
}

func listFiles(t *testing.T, root string) []string {
	t.Helper()
	files := []string{}
	if err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		files = append(files, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}
