package run

import (
	"strings"
	"testing"
)

func TestRenderCodexAssistantTextFormatsMarkdownAndAddsBulletLane(t *testing.T) {
	rendered := renderCodexAssistantText("## Title\n\n- first item\n- second item\n\nUse `code` here.\n", 60)
	plain := stripANSIEscapeCodes(rendered)

	if strings.Contains(plain, "## Title") {
		t.Fatalf("expected heading marker to be rendered away, got %q", plain)
	}
	if !strings.Contains(plain, "Title") {
		t.Fatalf("expected heading text to remain, got %q", plain)
	}
	if !strings.Contains(plain, "code") {
		t.Fatalf("expected inline code content to remain, got %q", plain)
	}
	lines := strings.Split(strings.TrimRight(plain, "\n"), "\n")
	if !strings.HasPrefix(lines[0], "● ") {
		t.Fatalf("expected first rendered line to start with bullet lane, got %#v", lines)
	}
	for _, line := range lines[1:] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			t.Fatalf("expected rendered line %q to keep a hanging indent", line)
		}
	}
}

func TestRenderCodexAssistantTextFallsBackToAssistantDisplayText(t *testing.T) {
	rendered := renderCodexAssistantText("", 60)
	if rendered != "" {
		t.Fatalf("expected empty output for empty input, got %q", rendered)
	}

	plain := stripANSIEscapeCodes(prefixAssistantDisplayText("plain line\nsecond line", true))
	lines := strings.Split(plain, "\n")
	if lines[0] != "● plain line" || lines[1] != "  second line" {
		t.Fatalf("expected assistant bullet formatting, got %#v", lines)
	}
}

func TestPrefixAssistantDisplayTextOnlyPrefixesLineStarts(t *testing.T) {
	first := prefixAssistantDisplayText("Hello ", true)
	second := prefixAssistantDisplayText("world\nnext line", false)

	if first != "● Hello " {
		t.Fatalf("unexpected first chunk %q", first)
	}
	if second != "world\n  next line" {
		t.Fatalf("unexpected second chunk %q", second)
	}
}
