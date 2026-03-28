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
		AddDirs:      []string{"/tmp/gitdir", "/tmp/extra"},
		ProviderArgs: []string{"--debug"},
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
	if !strings.Contains(joined, "--add-dir /tmp/gitdir") || !strings.Contains(joined, "--add-dir /tmp/extra") {
		t.Fatalf("expected add-dir flags, got: %q", joined)
	}
	if !strings.Contains(joined, "--debug") {
		t.Fatalf("expected forwarded provider args, got: %q", joined)
	}
}

func TestClaudeProviderBuildResumeCommand(t *testing.T) {
	provider := ClaudeProvider{}

	command, err := provider.BuildResumeCommand(BuildOptions{
		SessionID:    "sess-42",
		Model:        "claude-sonnet-4",
		AddDirs:      []string{"/tmp/gitdir"},
		ProviderArgs: []string{"--debug"},
	})
	if err != nil {
		t.Fatalf("BuildResumeCommand returned error: %v", err)
	}

	joined := strings.Join(command, " ")
	if !strings.Contains(joined, "claude --resume sess-42") {
		t.Fatalf("expected resume command, got: %q", joined)
	}
	if !strings.Contains(joined, "--model claude-sonnet-4") {
		t.Fatalf("expected model flag, got: %q", joined)
	}
	if !strings.Contains(joined, "--add-dir /tmp/gitdir") {
		t.Fatalf("expected add-dir flag, got: %q", joined)
	}
	if !strings.Contains(joined, "--debug") {
		t.Fatalf("expected forwarded provider args, got: %q", joined)
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

	command, err := provider.BuildCommand("fix the bug", BuildOptions{
		Model:        "gpt-5-codex",
		AddDirs:      []string{"/tmp/gitdir"},
		ProviderArgs: []string{"--profile", "ci"},
	})
	if err != nil {
		t.Fatalf("BuildCommand returned error: %v", err)
	}

	joined := strings.Join(command, " ")
	if !strings.Contains(joined, "codex exec --skip-git-repo-check --full-auto --add-dir /tmp/gitdir --json") {
		t.Fatalf("expected --add-dir before --json in non-resume mode: %q", joined)
	}
	if strings.Contains(joined, "resume") {
		t.Fatalf("did not expect resume mode by default: %q", joined)
	}
	if !strings.Contains(joined, "-m gpt-5-codex") {
		t.Fatalf("expected model flag, got: %q", joined)
	}
	if !strings.Contains(joined, "--profile ci") {
		t.Fatalf("expected forwarded provider args, got: %q", joined)
	}
	if !strings.HasSuffix(joined, "fix the bug") {
		t.Fatalf("expected prompt at end of command, got: %q", joined)
	}

	// Resume mode must NOT include --add-dir (codex exec resume doesn't accept it)
	resumeCmd, err := provider.BuildCommand("continue working", BuildOptions{
		ContinueSession: true,
		AddDirs:         []string{"/tmp/gitdir"},
	})
	if err != nil {
		t.Fatalf("BuildCommand resume returned error: %v", err)
	}
	resumeJoined := strings.Join(resumeCmd, " ")
	if !strings.Contains(resumeJoined, "resume --last") {
		t.Fatalf("expected resume --last in continue mode: %q", resumeJoined)
	}
	if strings.Contains(resumeJoined, "--add-dir") {
		t.Fatalf("--add-dir must not appear in codex resume command: %q", resumeJoined)
	}
}

func TestCodexProviderBuildResumeCommand(t *testing.T) {
	provider := CodexProvider{}

	command, err := provider.BuildResumeCommand(BuildOptions{
		SessionID:    "sess-42",
		Model:        "gpt-5-codex",
		AddDirs:      []string{"/tmp/gitdir"},
		ProviderArgs: []string{"--profile", "ci"},
	})
	if err != nil {
		t.Fatalf("BuildResumeCommand returned error: %v", err)
	}

	joined := strings.Join(command, " ")
	if !strings.Contains(joined, "codex exec resume --skip-git-repo-check --full-auto") {
		t.Fatalf("expected codex exec base command, got: %q", joined)
	}
	if !strings.Contains(joined, "sess-42") {
		t.Fatalf("expected resume session id, got: %q", joined)
	}
	if !strings.Contains(joined, "-m gpt-5-codex") {
		t.Fatalf("expected model flag, got: %q", joined)
	}
	if strings.Contains(joined, "--add-dir /tmp/gitdir") {
		t.Fatalf("did not expect add-dir flag on codex resume command, got: %q", joined)
	}
	if !strings.Contains(joined, "--profile ci") {
		t.Fatalf("expected forwarded provider args, got: %q", joined)
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
