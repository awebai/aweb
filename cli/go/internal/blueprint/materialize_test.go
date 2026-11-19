package blueprint

import (
	"bytes"
	"encoding/json"
	"errors"
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
	assertMaterializedTreesEqual(t, materializedTreeRoots{Expected: filepath.Join(fixture, "expected/materialized-home/developer"), Actual: target})
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
	for _, rel := range []string{
		"skills/implement/assets/checklist.md",
		".aw/profile/skills/implement/assets/checklist.md",
	} {
		if _, err := os.Stat(filepath.Join(target, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("runtime-independent skill asset %s: %v", rel, err)
		}
	}
	if _, err := os.Lstat(filepath.Join(target, ".claude", "skills", "implement")); !os.IsNotExist(err) {
		t.Fatalf("pi runtime should not have a Claude skill link: %v", err)
	}
}

func TestMaterializeManagedSetUsesDeclarationAndPerSkillPathOrder(t *testing.T) {
	target := t.TempDir()
	files := withPayloadFileSHA([]LibraryProfilePayloadFile{
		{Path: "skills/zeta/assets/z.txt", ContentUTF8: "z\n"},
		{Path: "artifacts/a.txt", ContentUTF8: "a\n"},
		{Path: "skills/alpha/SKILL.md", ContentUTF8: "# Alpha\n"},
		{Path: "instructions.md", ContentUTF8: "Build.\n"},
		{Path: "skills/zeta/SKILL.md", ContentUTF8: "# Zeta\n"},
		{Path: "artifacts/z.txt", ContentUTF8: "z\n"},
		{Path: "skills/zeta/assets/a.txt", ContentUTF8: "a\n"},
		{Path: "profile.yaml", ContentUTF8: "id: builder\nname: Builder\nversion: 0.1.0\nmission: Build.\naccepted_work: [implementation]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\nskills:\n  - path: skills/zeta/SKILL.md\n  - path: skills/alpha/SKILL.md\nartifacts:\n  - path: artifacts/z.txt\n  - path: artifacts/a.txt\n"},
	})

	_, err := MaterializeLibraryProfilePayload(MaterializeLibraryProfilePayloadOptions{
		TargetDir: target, ProfileRef: "builder", ProfileVersion: "0.1.0",
		RuntimeKind: "claude-code", Files: files, ProfileDigest: mustPayloadDigest(t, files),
	})
	if err != nil {
		t.Fatalf("MaterializeLibraryProfilePayload: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(target, ".aw", "profile", "ref.json"))
	if err != nil {
		t.Fatal(err)
	}
	var ref materializedProfileRef
	if err := json.Unmarshal(data, &ref); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"AGENTS.md", "CLAUDE.md", ".aw/profile/profile.yaml", ".aw/profile/instructions.md",
		"skills/zeta/SKILL.md", ".aw/profile/skills/zeta/SKILL.md",
		"skills/zeta/assets/a.txt", ".aw/profile/skills/zeta/assets/a.txt",
		"skills/zeta/assets/z.txt", ".aw/profile/skills/zeta/assets/z.txt",
		".claude/skills/zeta",
		"skills/alpha/SKILL.md", ".aw/profile/skills/alpha/SKILL.md",
		".claude/skills/alpha",
		"artifacts/z.txt", ".aw/profile/artifacts/z.txt",
		"artifacts/a.txt", ".aw/profile/artifacts/a.txt",
		".aw/profile/ref.json",
	}
	if strings.Join(ref.ManagedSet, "\n") != strings.Join(want, "\n") {
		t.Fatalf("managed_set ordering\ngot:  %v\nwant: %v", ref.ManagedSet, want)
	}
}

func TestMaterializeLibraryProfilePayloadWarnsForShelfAssetsOutsideDeclaration(t *testing.T) {
	target := t.TempDir()
	files := withPayloadFileSHA([]LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: reviewer\nname: Reviewer\nversion: 0.1.5\nmission: Review.\naccepted_work: [review]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\nartifacts:\n  - path: artifacts/review-template.md\n"},
		{Path: "instructions.md", ContentUTF8: "Review carefully.\n"},
		{Path: "artifacts/review-template.md", ContentUTF8: "# Delivered review template\n"},
		{Path: "patterns/common-failure-patterns.md", ContentUTF8: "# Undeliverable lesson\n"},
	})

	result, err := MaterializeLibraryProfilePayload(MaterializeLibraryProfilePayloadOptions{
		TargetDir: target, ProfileRef: "reviewer", ProfileVersion: "0.1.5", RuntimeKind: "pi", Files: files, ProfileDigest: mustPayloadDigest(t, files),
	})
	if err != nil {
		t.Fatalf("MaterializeLibraryProfilePayload: %v", err)
	}
	wantWarning := "library profile asset patterns/common-failure-patterns.md is not declared by profile.yaml and was not materialized (warning only)"
	if strings.Join(result.Warnings, "\n") != wantWarning {
		t.Fatalf("warnings=%q want %q", result.Warnings, wantWarning)
	}
	delivered, err := os.ReadFile(filepath.Join(target, "artifacts", "review-template.md"))
	if err != nil {
		t.Fatalf("open materialized declared artifact: %v", err)
	}
	if string(delivered) != "# Delivered review template\n" {
		t.Fatalf("materialized artifact=%q", delivered)
	}
	if _, err := os.Lstat(filepath.Join(target, "patterns", "common-failure-patterns.md")); !os.IsNotExist(err) {
		t.Fatalf("undeclared asset must remain unmaterialized: %v", err)
	}
}

func TestMaterializeLibraryProfilePayloadAllowsFoldedBlockMission(t *testing.T) {
	target := t.TempDir()
	opts := MaterializeLibraryProfilePayloadOptions{
		TargetDir:      target,
		ProfileRef:     "reviewer",
		ProfileVersion: "0.2.0",
		RuntimeKind:    "claude-code",
		Files: withPayloadFileSHA([]LibraryProfilePayloadFile{
			{Path: "profile.yaml", ContentUTF8: "id: reviewer\nname: Reviewer\nversion: 0.2.0\nmission: >\n  Give independent, fresh-eyes review before merge,\n  with blocking and non-blocking findings.\naccepted_work:\n  - >\n    reviewing a developer diff\n    against acceptance criteria\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
			{Path: "instructions.md", ContentUTF8: "Review changes carefully.\n"},
		}),
	}
	opts.ProfileDigest = mustPayloadDigest(t, opts.Files)
	_, err := MaterializeLibraryProfilePayload(opts)
	if err != nil {
		t.Fatalf("MaterializeLibraryProfilePayload: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(target, "AGENTS.md")); err != nil {
		t.Fatalf("profile was not materialized: %v", err)
	}
}

func TestMaterializeLocalProfileForceMigratesSkillFileProjection(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	target := t.TempDir()
	projectionDir := filepath.Join(target, ".claude", "skills", "implement")
	if err := os.MkdirAll(projectionDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../skills/implement/SKILL.md", filepath.Join(projectionDir, "SKILL.md")); err != nil {
		t.Fatal(err)
	}

	if _, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "developer", TargetDir: target, RuntimeKind: "claude-code", Force: true}); err != nil {
		t.Fatalf("migrate legacy Claude skill link: %v", err)
	}
	link := filepath.Join(target, ".claude", "skills", "implement")
	got, err := os.Readlink(link)
	if err != nil {
		t.Fatalf("directory skill link: %v", err)
	}
	if got != "../../skills/implement" {
		t.Fatalf("directory skill link target=%q", got)
	}
}

func TestMaterializeLocalProfileForceDoesNotReplaceUnmanagedClaudeSkillDirectory(t *testing.T) {
	fixture := engineeringFixtureRoot(t)
	target := t.TempDir()
	userFile := filepath.Join(target, ".claude", "skills", "implement", "notes.txt")
	if err := os.MkdirAll(filepath.Dir(userFile), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(userFile, []byte("keep me\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := MaterializeLocalProfile(MaterializeOptions{SourceDir: filepath.Join(fixture, "source"), ProfileID: "developer", TargetDir: target, RuntimeKind: "claude-code", Force: true})
	if err == nil || !strings.Contains(err.Error(), "already exists and is not a symlink") {
		t.Fatalf("error=%v", err)
	}
	if got, readErr := os.ReadFile(userFile); readErr != nil || string(got) != "keep me\n" {
		t.Fatalf("unmanaged skill directory was changed: content=%q err=%v", got, readErr)
	}
	if _, statErr := os.Stat(filepath.Join(target, "AGENTS.md")); !os.IsNotExist(statErr) {
		t.Fatalf("preflight should prevent partial writes, stat err=%v", statErr)
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

type materializedTreeRoots struct {
	Expected string
	Actual   string
}

func assertMaterializedTreesEqual(t *testing.T, trees materializedTreeRoots) {
	wantDir, gotDir := trees.Expected, trees.Actual
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
			wantLink, err := os.Readlink(wantPath)
			if err != nil {
				t.Fatal(err)
			}
			gotLink, err := os.Readlink(gotPath)
			if err != nil {
				t.Fatal(err)
			}
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
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	return files
}

// A profile payload digest is recorded when a profile is materialized and
// recomputed on refresh, so its canonical bytes write U+2028 and U+2029 in a
// file path as six-character escapes. This digest was computed at commit
// 8e8d008c8.
func TestLibraryProfilePayloadDigestOfPathWithLineSeparatorsIsStable(t *testing.T) {
	path := "docs/a" + string(rune(0x2028)) + "b" + string(rune(0x2029)) + "c.md"
	digest, err := libraryProfilePayloadDigest([]LibraryProfilePayloadFile{{
		Path:        path,
		SHA256:      "sha256:5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03",
		ContentUTF8: "hello\n",
	}})
	if err != nil {
		t.Fatal(err)
	}
	if want := "sha256:ac56d1908616e5e0e350e9d927f9106537fafaf5dde16a6269c14b91119a21d6"; digest != want {
		t.Fatalf("digest = %s, want %s", digest, want)
	}
}

func mustPayloadDigest(t *testing.T, files []LibraryProfilePayloadFile) string {
	t.Helper()
	digest, err := libraryProfilePayloadDigest(files)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func TestMaterializePublicationDoesNotOverwriteAConcurrentDestination(t *testing.T) {
	for _, operation := range []materializeWriteOp{
		{Kind: opFile, Rel: "AGENTS.md", Data: []byte("profile content")},
		{Kind: opSymlink, Rel: "CLAUDE.md", LinkTarget: "AGENTS.md"},
	} {
		t.Run(string(operation.Kind), func(t *testing.T) {
			root := t.TempDir()
			plan := materializeWritePlan{TargetRoot: root, Operations: []materializeWriteOp{operation}, CollisionPolicy: preserveExistingProfileFiles}
			if err := plan.preflight(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(root, operation.Rel)
			if err := os.WriteFile(path, []byte("operator content"), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := plan.write()
			if !errors.Is(err, os.ErrExist) {
				t.Fatalf("publication replaced a concurrent destination: %v", err)
			}
			if !strings.Contains(err.Error(), "Use another home or resolve the conflicting destination") {
				t.Fatalf("collision has no recovery action: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != "operator content" {
				t.Fatalf("publication changed operator file: %q", got)
			}
		})
	}
}

func TestRuntimeProjectionPublicationPreservesUnmanagedConcurrentContent(t *testing.T) {
	for _, conflict := range []struct{ name, child string }{
		{name: "file"}, {name: "directory", child: "operator.txt"},
	} {
		t.Run(conflict.name, func(t *testing.T) {
			root := t.TempDir()
			operation := materializeWriteOp{Kind: opSymlink, Rel: ".claude/skills/reviewer", LinkTarget: "../../skills/reviewer"}
			plan := materializeWritePlan{TargetRoot: root, Operations: []materializeWriteOp{operation}, CollisionPolicy: replaceExistingProfileFiles}
			if err := plan.preflight(); err != nil {
				t.Fatal(err)
			}
			operatorPath := filepath.Join(root, operation.Rel, conflict.child)
			if err := os.MkdirAll(filepath.Dir(operatorPath), 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(operatorPath, []byte("operator content"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := plan.write(); err == nil || !strings.Contains(err.Error(), "Repair the destination before retrying") {
				t.Fatalf("unmanaged projection conflict was not refused actionably: %v", err)
			}
			data, err := os.ReadFile(operatorPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != "operator content" {
				t.Fatalf("projection replaced operator content: %q", data)
			}
		})
	}
}
