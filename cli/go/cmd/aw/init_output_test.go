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

	if !strings.Contains(string(tutorial), `title: "Connect two agents with aw"`) {
		t.Fatal("CLI tutorial does not identify itself as the page that connects two agents")
	}
	if strings.Contains(string(startWorking), "/docs/cli-tutorial/") {
		t.Fatal("task-first guide aliases the canonical CLI tutorial route")
	}
	if string(tutorial) == string(startWorking) {
		t.Fatal("CLI tutorial and task-first guide must remain distinct audiences")
	}
}

func TestInitNextStepLinesHostedPromoteChannelAndDashboard(t *testing.T) {
	lines := initStepLines(initNextStepsAfter(&initResult{
		Path:          initPathNewTeam,
		ServerName:    "app.aweb.ai",
		ExportBaseURL: "https://app.aweb.ai/api",
	}, t.TempDir(), initSetupDone{DocsInjected: false, ChannelSetUp: false}), true)
	text := strings.Join(lines, "\n")

	for _, want := range []string{
		"aw init --setup-channel",
		"aw init --inject-docs",
		"aw claim-human --email <your-email>",
		"claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace",
		"Channel delivery works in any permission mode, including auto and plan.",
		"pi install npm:@awebai/pi@latest",
		"https://aweb.ai/docs/cli-tutorial.md",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in next steps:\n%s", want, text)
		}
	}
	for _, unwanted := range []string{"--dangerously-skip-permissions", "aw run codex", "aw run claude", "docs/agent-guide.md", "https://aweb.ai/agent-guide.md"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("unexpected %q in next steps:\n%s", unwanted, text)
		}
	}
}

func TestInitNextStepLinesLocalDirAllDoneStillShowsChannelLaunch(t *testing.T) {
	lines := initStepLines(initNextStepsAfter(&initResult{
		Path:          initPathNewTeam,
		ServerName:    "localhost",
		ExportBaseURL: "http://127.0.0.1:8000/api",
	}, t.TempDir(), initSetupDone{DocsInjected: true, ChannelSetUp: true}), true)
	text := strings.Join(lines, "\n")

	if !strings.Contains(text, "claude --dangerously-load-development-channels plugin:aweb-channel@awebai-marketplace") {
		t.Fatalf("missing channel launch instruction:\n%s", text)
	}
	if !strings.Contains(text, "Channel delivery works in any permission mode, including auto and plan.") {
		t.Fatalf("missing the permission-mode guidance:\n%s", text)
	}
	if !strings.Contains(text, "pi install npm:@awebai/pi@latest") {
		t.Fatalf("missing the Pi wake-up path:\n%s", text)
	}
	if !strings.Contains(text, "https://aweb.ai/docs/cli-tutorial.md") {
		t.Fatalf("missing CLI tutorial URL:\n%s", text)
	}
	for _, unwanted := range []string{"--dangerously-skip-permissions", "aw init --inject-docs", "aw init --setup-channel", "aw claim-human", "docs/agent-guide.md", "https://aweb.ai/agent-guide.md"} {
		if strings.Contains(text, unwanted) {
			t.Fatalf("unexpected %q in next steps:\n%s", unwanted, text)
		}
	}
}

func TestInitNextStepLinesAPIKeyAuthSuppressesClaimHuman(t *testing.T) {
	lines := initStepLines(initNextStepsAfter(&initResult{
		Path:          initPathAPIKey,
		ServerName:    "app.aweb.ai",
		ExportBaseURL: "https://app.aweb.ai/api",
		APIKeyAuth:    true,
	}, t.TempDir(), initSetupDone{DocsInjected: false, ChannelSetUp: false}), true)
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

func TestInitNextStepLinesTellHowToAddASecondAgentToThisTeam(t *testing.T) {
	for _, tc := range []struct {
		name   string
		result *initResult
		done   bool
	}{
		{"hosted", &initResult{Path: initPathNewTeam, ServerName: "app.aweb.ai", ExportBaseURL: "https://app.aweb.ai/api"}, false},
		{"api-key", &initResult{Path: initPathAPIKey, ServerName: "app.aweb.ai", ExportBaseURL: "https://app.aweb.ai/api", APIKeyAuth: true}, false},
		{"local-all-done", &initResult{Path: initPathNewTeam, ServerName: "localhost", ExportBaseURL: "http://127.0.0.1:8000/api"}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text := strings.Join(initStepLines(initNextStepsAfter(tc.result, t.TempDir(), initSetupDone{DocsInjected: tc.done, ChannelSetUp: tc.done}), true), "\n")
			if tc.result.APIKeyAuth {
				if !strings.Contains(text, "create one from the dashboard") || strings.Contains(text, "separate account and team") {
					t.Fatalf("API-key second-agent advice contradicts same-team creation:\n%s", text)
				}
			} else if initResultIsHosted(tc.result) && (!strings.Contains(text, "separate account and team") || strings.Contains(text, "cannot message") || strings.Contains(text, "create one from the dashboard")) {
				t.Fatalf("hosted keyless advice missing qualified warning:\n%s", text)
			}
			for _, want := range []string{
				"aw team invite",
				"run the join command it prints in that agent's folder",
			} {
				if !strings.Contains(text, want) {
					t.Fatalf("missing %q in next steps:\n%s", want, text)
				}
			}
		})
	}
}
