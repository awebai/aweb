package run

import (
	"strings"
	"testing"
)

func TestRenderCodexAssistantTextFormatsMarkdownAndAddsMargin(t *testing.T) {
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
	for _, line := range strings.Split(strings.TrimRight(plain, "\n"), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, "  ") {
			t.Fatalf("expected rendered line %q to keep a left margin", line)
		}
	}
}

func TestRenderCodexAssistantTextFallsBackToIndentedPlainText(t *testing.T) {
	rendered := renderCodexAssistantText("", 60)
	if rendered != "" {
		t.Fatalf("expected empty output for empty input, got %q", rendered)
	}

	plain := stripANSIEscapeCodes(indentDisplayText("plain line\nsecond line", 2))
	lines := strings.Split(plain, "\n")
	if lines[0] != "  plain line" || lines[1] != "  second line" {
		t.Fatalf("expected plain text indentation, got %#v", lines)
	}
}

func TestIndentStreamingTextOnlyPrefixesLineStarts(t *testing.T) {
	first := indentStreamingText("Hello ", 2, true)
	second := indentStreamingText("world\nnext line", 2, false)

	if first != "  Hello " {
		t.Fatalf("unexpected first chunk %q", first)
	}
	if second != "world\n  next line" {
		t.Fatalf("unexpected second chunk %q", second)
	}
}
