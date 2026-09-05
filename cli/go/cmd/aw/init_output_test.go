package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCLITutorialRouteIsNotAliasedToTaskWorkflow(t *testing.T) {
	docsDir := filepath.Join("..", "..", "..", "..", "docs")
	tutorial, err := os.ReadFile(filepath.Join(docsDir, "cli-tutorial.md"))
	if err != nil {
		t.Fatalf("read canonical CLI tutorial: %v", err)
	}
	startWorking, err := os.ReadFile(filepath.Join(docsDir, "start-working.md"))
	if err != nil {
		t.Fatalf("read task-first guide: %v", err)
	}

	if !strings.Contains(string(tutorial), `title: "First durable agent round trip with aw"`) {
		t.Fatal("CLI tutorial does not identify the durable round-trip audience")
	}
	if strings.Contains(string(startWorking), "/docs/cli-tutorial/") {
		t.Fatal("task-first guide aliases the canonical CLI tutorial route")
	}
	if string(tutorial) == string(startWorking) {
		t.Fatal("CLI tutorial and task-first guide must remain distinct audiences")
	}
}

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
		"claude plugin marketplace add awebai/claude-plugins",
		"claude plugin install aweb-channel@awebai-marketplace",
		"claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace",
		"channel messages are delivered to the session only in",
		"bypass-permissions mode today",
		"pi install npm:@awebai/pi@latest",
		"https://aweb.ai/docs/cli-tutorial.md",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in next steps:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"aw run codex", "aw run claude", "docs/agent-guide.md", "https://aweb.ai/agent-guide.md"} {
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

	if !strings.Contains(text, "claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace") {
		t.Fatalf("missing channel launch instruction:\n%s", text)
	}
	if !strings.Contains(text, "bypass-permissions mode today") {
		t.Fatalf("missing the reason both launch flags are required:\n%s", text)
	}
	if !strings.Contains(text, "pi install npm:@awebai/pi@latest") {
		t.Fatalf("missing the Pi wake-up path:\n%s", text)
	}
	if !strings.Contains(text, "https://aweb.ai/docs/cli-tutorial.md") {
		t.Fatalf("missing CLI tutorial URL:\n%s", text)
	}
	for _, unwanted := range []string{"aw init --inject-docs", "aw init --setup-channel", "aw claim-human", "docs/agent-guide.md", "https://aweb.ai/agent-guide.md"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("unexpected %q in next steps:\n%s", unwanted, text)
		}
	}
}

func TestChannelLaunchInstructionsCarryInstallLaunchWhyAndPi(t *testing.T) {
	var buf strings.Builder
	printChannelLaunchInstructions(&buf)
	text := buf.String()

	for _, want := range []string{
		"claude plugin marketplace add awebai/claude-plugins",
		"claude plugin install aweb-channel@awebai-marketplace",
		"claude --dangerously-skip-permissions --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace",
		"channel messages are delivered to the session only in",
		"bypass-permissions mode today",
		"--dangerously-skip-permissions there are no wake-ups",
		"confirm --dangerously-load-development-channels; that is expected",
		"pi install npm:@awebai/pi@latest",
		"sender's verification shown",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in channel launch instructions:\n%s", want, text)
		}
	}
}

func TestInitNextStepLinesAPIKeyAuthSuppressesClaimHuman(t *testing.T) {
	lines := initNextStepLines(&initResult{
		ServerName:    "app.aweb.ai",
		ExportBaseURL: "https://app.aweb.ai/api",
		APIKeyAuth:    true,
	}, t.TempDir(), false, false, false)
	text := strings.Join(lines, "\n")

	if strings.Contains(text, "aw claim-human") {
		t.Fatalf("API-key auth should suppress claim-human suggestion:\n%s", text)
	}
	for _, want := range []string{
		"aw init --setup-channel",
		"aw init --inject-docs",
		"https://aweb.ai/docs/cli-tutorial.md",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in next steps:\n%s", want, text)
		}
	}
}
