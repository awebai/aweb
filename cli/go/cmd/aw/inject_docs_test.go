package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInjectAgentDocsCreatesAgentsWhenNoFilesExist(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	result := InjectAgentDocs(tmp)
	if len(result.Created) != 1 || result.Created[0] != "AGENTS.md" {
		t.Fatalf("created=%v", result.Created)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, want := range []string{awDocsMarkerStart, "aw roles show", "aw chat send-and-wait"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in AGENTS.md:\n%s", want, text)
		}
	}
}

func TestInjectAgentDocsAppendsToExistingFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "CLAUDE.md")
	if err := os.WriteFile(path, []byte("# Local Notes\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result := InjectAgentDocs(tmp)
	if len(result.Injected) != 1 || result.Injected[0] != "CLAUDE.md" {
		t.Fatalf("injected=%v", result.Injected)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, "# Local Notes") || !strings.Contains(text, awDocsMarkerStart) {
		t.Fatalf("unexpected content:\n%s", text)
	}
}

func TestInjectAgentDocsReplacesExistingInjectedSection(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	path := filepath.Join(tmp, "AGENTS.md")
	content := "Header\n\n" + awDocsMarkerStart + "\nold docs\n" + awDocsMarkerEnd + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	InjectAgentDocs(tmp)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, awDocsMarkerStart) != 1 {
		t.Fatalf("expected one injected section:\n%s", text)
	}
	if strings.Contains(text, "old docs") {
		t.Fatalf("old docs should be replaced:\n%s", text)
	}
}

func TestInjectAgentDocsAvoidsDoubleWriteForSymlink(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	target := filepath.Join(tmp, "AGENTS.md")
	link := filepath.Join(tmp, "CLAUDE.md")
	if err := os.WriteFile(target, []byte("base\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	InjectAgentDocs(tmp)
	data, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if strings.Count(text, awDocsMarkerStart) != 1 {
		t.Fatalf("expected one injected section:\n%s", text)
	}
}
