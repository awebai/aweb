package run

import "testing"

func TestFormatToolCallLinesUsesMinimalShellStyle(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": "go test ./... 2>&1",
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != ">_ go test ./... 2>&1" {
		t.Fatalf("unexpected tool line %q", lines[0])
	}
}

func TestFormatToolCallLinesKeepsToolNameForNonShellTools(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "View",
		Input: map[string]any{
			"path": "/tmp/image.png",
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != ">_ View /tmp/image.png" {
		t.Fatalf("unexpected tool line %q", lines[0])
	}
}

func TestFormatToolCallLinesCompactsMailSendCommands(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": `aw mail send --to dave --subject "Review" --body "please take a look"`,
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != "-> dave (mail)" {
		t.Fatalf("unexpected mail tool line %q", lines[0])
	}
}

func TestFormatToolCallLinesCompactsChatSendCommands(t *testing.T) {
	lines := formatToolCallLines(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": `aw chat send-and-wait henry "can you review this?" --start-conversation`,
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0] != "-> henry (chat)" {
		t.Fatalf("unexpected chat tool line %q", lines[0])
	}
}

func TestFormatToolResultLinesPreservesLineBreaks(t *testing.T) {
	lines := formatToolResultLines("1\talpha\n2\tbeta\n3\tgamma")
	if len(lines) != 3 {
		t.Fatalf("expected 3 result lines, got %#v", lines)
	}
	if lines[0] != "  = 1\talpha" || lines[1] != "  = 2\tbeta" || lines[2] != "  = 3\tgamma" {
		t.Fatalf("unexpected result lines %#v", lines)
	}
}

func TestFormatToolResultLinesSummarizesExtraLines(t *testing.T) {
	lines := formatToolResultLines("1\n2\n3\n4\n5\n6\n7\n8")
	if len(lines) != 7 {
		t.Fatalf("expected 7 rendered lines, got %#v", lines)
	}
	if lines[6] != "  = ... +2 lines" {
		t.Fatalf("unexpected overflow summary %#v", lines)
	}
}
