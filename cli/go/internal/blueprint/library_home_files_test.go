package blueprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteLibraryHomeFilesWritesEvolvableHome(t *testing.T) {
	target := t.TempDir()
	files := []LibraryHomeFile{
		{Path: "AGENTS.md", Kind: "file", ContentUTF8: "# Coordinator\n"},
		{Path: "CLAUDE.md", Kind: "symlink", Target: "AGENTS.md"},
		{Path: ".aw/profile/ref.json", Kind: "file", ContentUTF8: "{}\n"},
		{Path: ".aw/profile/profile.yaml", Kind: "file", ContentUTF8: "id: coordinator\n"},
		{Path: ".aw/profile/instructions.md", Kind: "file", ContentUTF8: "Coordinate.\n"},
	}
	written, err := WriteLibraryHomeFiles(target, files, false)
	if err != nil {
		t.Fatalf("WriteLibraryHomeFiles: %v", err)
	}
	if strings.Join(written, ",") != "AGENTS.md,CLAUDE.md,.aw/profile/ref.json,.aw/profile/profile.yaml,.aw/profile/instructions.md" {
		t.Fatalf("written=%v", written)
	}
	data, err := os.ReadFile(filepath.Join(target, ".aw", "profile", "profile.yaml"))
	if err != nil || string(data) != "id: coordinator\n" {
		t.Fatalf("profile.yaml=%q err=%v", string(data), err)
	}
	link, err := os.Readlink(filepath.Join(target, "CLAUDE.md"))
	if err != nil || link != "AGENTS.md" {
		t.Fatalf("CLAUDE.md link=%q err=%v", link, err)
	}
}

func TestWriteLibraryHomeFilesRejectsSymlinkedParent(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".aw")); err != nil {
		t.Fatal(err)
	}
	_, err := WriteLibraryHomeFiles(root, []LibraryHomeFile{{Path: ".aw/profile/profile.yaml", Kind: "file", ContentUTF8: "id: x\n"}}, false)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
}

func TestWriteLibraryHomeFilesRejectsTraversal(t *testing.T) {
	_, err := WriteLibraryHomeFiles(t.TempDir(), []LibraryHomeFile{{Path: "../escape", Kind: "file", ContentUTF8: "x"}}, false)
	if err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("error=%v", err)
	}
}

func TestWriteLibraryHomeFilesRejectsEscapingSymlinkTargetWithoutPartialWrite(t *testing.T) {
	target := t.TempDir()
	_, err := WriteLibraryHomeFiles(target, []LibraryHomeFile{
		{Path: "AGENTS.md", Kind: "file", ContentUTF8: "# should not be written\n"},
		{Path: "CLAUDE.md", Kind: "symlink", Target: "../escape"},
	}, false)
	if err == nil || !strings.Contains(err.Error(), "escapes target directory") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(target, "AGENTS.md")); !os.IsNotExist(statErr) {
		t.Fatalf("partial file write occurred, stat err=%v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(target, "CLAUDE.md")); !os.IsNotExist(statErr) {
		t.Fatalf("partial symlink write occurred, stat err=%v", statErr)
	}
}

func TestMaterializeLibraryProfilePayloadRejectsTraversalWithoutTargetWrite(t *testing.T) {
	target := t.TempDir()
	_, err := MaterializeLibraryProfilePayload(MaterializeLibraryProfilePayloadOptions{
		TargetDir:        target,
		BlueprintRef:     "aweb.engineering",
		BlueprintVersion: "0.1.0",
		ProfileRef:       "coordinator",
		ProfileVersion:   "0.1.0",
		Files: withPayloadFileSHA([]LibraryProfilePayloadFile{
			{Path: "profile.yaml", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
			{Path: "instructions.md", ContentUTF8: "Coordinate.\n"},
			{Path: "../escape", ContentUTF8: "x"},
		}),
	})
	if err == nil || !strings.Contains(err.Error(), "traversal") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(target, "AGENTS.md")); !os.IsNotExist(statErr) {
		t.Fatalf("partial target write occurred, stat err=%v", statErr)
	}
}

func TestMaterializeLibraryProfilePayloadRejectsStructuralInvalidPayloads(t *testing.T) {
	validProfile := "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"
	for _, tc := range []struct {
		name    string
		files   []LibraryProfilePayloadFile
		wantErr string
	}{
		{name: "duplicate path", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: validProfile}, {Path: "profile.yaml", ContentUTF8: validProfile}}), wantErr: "duplicate"},
		{name: "dot segment", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "./profile.yaml", ContentUTF8: validProfile}, {Path: "instructions.md", ContentUTF8: "Coordinate.\n"}}), wantErr: "normalized"},
		{name: "repeated slash", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: validProfile}, {Path: "skills//x.md", ContentUTF8: "x"}}), wantErr: "normalized"},
		{name: "trailing slash", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: validProfile}, {Path: "skills/", ContentUTF8: "x"}}), wantErr: "normalized"},
		{name: "backslash", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: validProfile}, {Path: "skills\\x.md", ContentUTF8: "x"}}), wantErr: "POSIX"},
		{name: "u2028", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: strings.Replace(validProfile, "Coordinate.", "Coordinate.\u2028", 1)}, {Path: "instructions.md", ContentUTF8: "Coordinate.\n"}}), wantErr: "U+2028"},
		{name: "profile id mismatch", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: strings.Replace(validProfile, "id: coordinator", "id: other", 1)}, {Path: "instructions.md", ContentUTF8: "Coordinate.\n"}}), wantErr: "does not match response profile_ref"},
		{name: "profile version mismatch", files: withPayloadFileSHA([]LibraryProfilePayloadFile{{Path: "profile.yaml", ContentUTF8: strings.Replace(validProfile, "version: 0.1.0", "version: 0.2.0", 1)}, {Path: "instructions.md", ContentUTF8: "Coordinate.\n"}}), wantErr: "does not match response version"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			target := t.TempDir()
			_, err := MaterializeLibraryProfilePayload(MaterializeLibraryProfilePayloadOptions{TargetDir: target, BlueprintRef: "aweb.engineering", BlueprintVersion: "0.1.0", ProfileRef: "coordinator", ProfileVersion: "0.1.0", Files: tc.files})
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("error=%v, want %q", err, tc.wantErr)
			}
			if _, statErr := os.Lstat(filepath.Join(target, "AGENTS.md")); !os.IsNotExist(statErr) {
				t.Fatalf("partial target write occurred, stat err=%v", statErr)
			}
		})
	}
}

func TestMaterializeLibraryProfilePayloadRejectsHashMismatchWithoutTargetWrite(t *testing.T) {
	target := t.TempDir()
	_, err := MaterializeLibraryProfilePayload(MaterializeLibraryProfilePayloadOptions{
		TargetDir:        target,
		BlueprintRef:     "aweb.engineering",
		BlueprintVersion: "0.1.0",
		ProfileRef:       "coordinator",
		ProfileVersion:   "0.1.0",
		Files: []LibraryProfilePayloadFile{
			{Path: "profile.yaml", SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000", ContentUTF8: "id: coordinator\nname: Coordinator\nversion: 0.1.0\nmission: Coordinate.\naccepted_work: [coordination]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
			{Path: "instructions.md", SHA256: "sha256:0000000000000000000000000000000000000000000000000000000000000000", ContentUTF8: "Coordinate.\n"},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "sha256 mismatch") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(target, "AGENTS.md")); !os.IsNotExist(statErr) {
		t.Fatalf("partial target write occurred, stat err=%v", statErr)
	}
}

func TestWriteLibraryHomeFilesRejectsSymlinkTargetThroughExistingSymlinkWithoutPartialWrite(t *testing.T) {
	target := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(target, "outlink")); err != nil {
		t.Fatal(err)
	}
	_, err := WriteLibraryHomeFiles(target, []LibraryHomeFile{
		{Path: "AGENTS.md", Kind: "file", ContentUTF8: "# should not be written\n"},
		{Path: "CLAUDE.md", Kind: "symlink", Target: "outlink/secret"},
	}, false)
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(target, "AGENTS.md")); !os.IsNotExist(statErr) {
		t.Fatalf("partial file write occurred, stat err=%v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(target, "CLAUDE.md")); !os.IsNotExist(statErr) {
		t.Fatalf("partial symlink write occurred, stat err=%v", statErr)
	}
}
