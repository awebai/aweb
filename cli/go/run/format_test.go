package run

import (
	"strings"
	"testing"
)

func TestFormatToolCallLinesUsesMinimalShellStyle(t *testing.T) {
	lines := formatToolCallDisplay(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": "go test ./... 2>&1",
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0].Kind != DisplayKindTool || lines[0].Text != "· go test ./... 2>&1" {
		t.Fatalf("unexpected tool line %#v", lines[0])
	}
}

func TestFormatToolCallLinesKeepsToolNameForNonShellTools(t *testing.T) {
	lines := formatToolCallDisplay(ToolCall{
		Name: "View",
		Input: map[string]any{
			"path": "/tmp/image.png",
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0].Kind != DisplayKindTool || lines[0].Text != "· View /tmp/image.png" {
		t.Fatalf("unexpected tool line %#v", lines[0])
	}
}

func TestFormatToolCallLinesStayOnOneLineForMultipleArgs(t *testing.T) {
	lines := formatToolCallDisplay(ToolCall{
		Name: "browser_click",
		Input: map[string]any{
			"ref":         "abc",
			"element":     "Submit",
			"description": "click the primary submit button",
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0].Kind != DisplayKindTool {
		t.Fatalf("expected tool line, got %#v", lines[0])
	}
	if lines[0].Text == "" || !strings.HasPrefix(lines[0].Text, "· ") {
		t.Fatalf("expected compact tool line, got %#v", lines[0])
	}
}

func TestFormatToolCallLinesCompactsMailSendCommands(t *testing.T) {
	lines := formatToolCallDisplay(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": `aw mail send --to dave --subject "Review" --body "please take a look"`,
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0].Kind != DisplayKindCommunication || lines[0].Text != "● to dave (mail)" {
		t.Fatalf("unexpected mail tool line %#v", lines[0])
	}
}

func TestFormatToolCallLinesCompactsChatSendCommands(t *testing.T) {
	lines := formatToolCallDisplay(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": `aw chat send-and-wait henry "can you review this?" --start-conversation`,
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0].Kind != DisplayKindCommunication || lines[0].Text != "● to henry (chat)" {
		t.Fatalf("unexpected chat tool line %#v", lines[0])
	}
}

func TestFormatToolCallLinesCompactsTaskUpdateCommands(t *testing.T) {
	lines := formatToolCallDisplay(ToolCall{
		Name: "Bash",
		Input: map[string]any{
			"command": `aw task update aweb-aaat.1 --status in_progress`,
		},
	})
	if len(lines) != 1 {
		t.Fatalf("expected one line, got %#v", lines)
	}
	if lines[0].Kind != DisplayKindTaskActivity || lines[0].Text != "● task update aweb-aaat.1" {
		t.Fatalf("unexpected task tool line %#v", lines[0])
	}
}
