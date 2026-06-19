package profilepack

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
