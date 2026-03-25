package run

import (
	"strings"
	"testing"
)

func TestClaudeProviderBuildCommand(t *testing.T) {
	provider := ClaudeProvider{}

	command, err := provider.BuildCommand("fix the bug", BuildOptions{
		AllowedTools: "exec_command,apply_patch",
		Model:        "claude-sonnet-4",
	})
	if err != nil {
		t.Fatalf("BuildCommand returned error: %v", err)
	}

	joined := strings.Join(command, " ")
	if !strings.Contains(joined, "claude -p fix the bug") {
		t.Fatalf("expected base command, got: %q", joined)
	}
	if !strings.Contains(joined, "--dangerously-skip-permissions") {
		t.Fatalf("expected skip permissions flag, got: %q", joined)
	}
	if strings.Contains(joined, "--continue") {
		t.Fatalf("did not expect continue flag by default, got: %q", joined)
	}
	if !strings.Contains(joined, "--allowedTools exec_command,apply_patch") {
		t.Fatalf("expected allowedTools flag, got: %q", joined)
	}
	if !strings.Contains(joined, "--model claude-sonnet-4") {
		t.Fatalf("expected model flag, got: %q", joined)
	}
}

func TestClaudeProviderParseOutput(t *testing.T) {
	provider := ClaudeProvider{}

	textEvent, err := provider.ParseOutput(`{"type":"stream_event","event":{"delta":{"type":"text_delta","text":"hello"}}}`)
	if err != nil {
		t.Fatalf("ParseOutput text returned error: %v", err)
	}
	if textEvent.Type != EventText || textEvent.Text != "hello" {
		t.Fatalf("unexpected text event: %#v", textEvent)
	}

	resultEvent, err := provider.ParseOutput(`{"type":"result","duration_ms":2500,"cost_usd":0.0042,"session_id":"s1"}`)
	if err != nil {
		t.Fatalf("ParseOutput result returned error: %v", err)
	}
	if resultEvent.Type != EventDone || resultEvent.DurationMS != 2500 || provider.SessionID(resultEvent) != "s1" {
		t.Fatalf("unexpected result event: %#v", resultEvent)
	}
}

func TestCodexProviderBuildCommand(t *testing.T) {
	provider := CodexProvider{}

	command, err := provider.BuildCommand("fix the bug", BuildOptions{Model: "gpt-5-codex"})
	if err != nil {
		t.Fatalf("BuildCommand returned error: %v", err)
	}

	joined := strings.Join(command, " ")
	if !strings.Contains(joined, "codex exec --skip-git-repo-check --full-auto --json -m gpt-5-codex fix the bug") {
		t.Fatalf("unexpected codex command: %q", joined)
	}
	if strings.Contains(joined, "resume --last") {
		t.Fatalf("did not expect resume mode by default: %q", joined)
	}
}

func TestCodexProviderParseOutput(t *testing.T) {
	provider := CodexProvider{}

	systemEvent, err := provider.ParseOutput(`{"type":"thread.started","thread_id":"019cca9b-364c-7c81-ae75-4fb21c9c5a4d"}`)
	if err != nil {
		t.Fatalf("ParseOutput thread.started returned error: %v", err)
	}
	if systemEvent.Type != EventSystem || provider.SessionID(systemEvent) == "" {
		t.Fatalf("unexpected thread.started event: %#v", systemEvent)
	}

	toolCallEvent, err := provider.ParseOutput(`{"type":"item.started","item":{"id":"item_0","type":"command_execution","command":"/bin/zsh -lc pwd","aggregated_output":"","exit_code":null,"status":"in_progress"}}`)
	if err != nil {
		t.Fatalf("ParseOutput item.started returned error: %v", err)
	}
	if toolCallEvent.Type != EventToolCall || len(toolCallEvent.ToolCalls) != 1 {
		t.Fatalf("unexpected tool call event: %#v", toolCallEvent)
	}
	if got := toolCallEvent.ToolCalls[0].Input["command"]; got != "pwd" {
		t.Fatalf("expected shell wrapper to be stripped, got %#v", got)
	}
}
