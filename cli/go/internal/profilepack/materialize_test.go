package profilepack

import (
	"bytes"
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
		want, err := os.ReadFile(filepath.Join(wantDir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		got, err := os.ReadFile(filepath.Join(gotDir, filepath.FromSlash(rel)))
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
