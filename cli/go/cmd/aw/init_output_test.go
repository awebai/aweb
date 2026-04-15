package main

import (
	"strings"
	"testing"
)

func TestInitNextStepLinesHostedPromoteChannelAndDashboard(t *testing.T) {
	lines := initNextStepLines(&initResult{
		ServerName:    "app.aweb.ai",
		ExportBaseURL: "https://app.aweb.ai/api",
	}, t.TempDir(), false, false, false)
	text := strings.Join(lines, "\n")

	for _, want := range []string{
		"aw init --setup-channel",
		"aw init --inject-docs",
		"aw claim-human --email you@example.com",
		"claude --dangerously-load-development-channels",
		"Agent guide: docs/agent-guide.txt",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in next steps:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"aw run codex", "aw run claude"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("unexpected %q in next steps:\n%s", unwanted, text)
		}
	}
}

func TestInitNextStepLinesLocalDirAllDoneStillShowsChannelLaunch(t *testing.T) {
	lines := initNextStepLines(&initResult{
		ServerName:    "localhost",
		ExportBaseURL: "http://127.0.0.1:8000/api",
	}, t.TempDir(), true, true, true)
	text := strings.Join(lines, "\n")

	if !strings.Contains(text, "claude --dangerously-load-development-channels") {
		t.Fatalf("missing channel launch instruction:\n%s", text)
	}
	if !strings.Contains(text, "Agent guide") {
		t.Fatalf("missing agent guide reference:\n%s", text)
	}
	for _, unwanted := range []string{"aw init --inject-docs", "aw init --setup-channel", "aw claim-human"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("unexpected %q in next steps:\n%s", unwanted, text)
		}
	}
}
