package main

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitUsesGuidedOnboardingInTTY(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.

	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldPrintReady := initPrintGuidedOnboardingReady
	t.Cleanup(func() {
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initPrintGuidedOnboardingReady = oldPrintReady
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initURL = "https://app.aweb.ai"
	initRole = "reviewer"
	initPersistent = false
	initInjectDocs = false
	initSetupHooks = false
	initWriteContext = true
	initIsTTY = func() bool { return true }

	var captured guidedOnboardingRequest
	var readyCalls int
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		captured = req
		return &guidedOnboardingResult{InitialPrompt: "Download and study the agent guide at https://aweb.ai/agent-guide.txt before doing anything else."}, nil
	}
	initPrintGuidedOnboardingReady = func(result *guidedOnboardingResult) {
		readyCalls++
		if result == nil || !strings.Contains(result.InitialPrompt, "agent guide") {
			t.Fatalf("unexpected ready result: %+v", result)
		}
	}

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	if err := runInit(&cmd.Command, nil); err != nil {
		t.Fatalf("runInit returned error: %v", err)
	}
	wantDir, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("EvalSymlinks(tmp): %v", err)
	}
	gotDir, err := filepath.EvalSymlinks(captured.WorkingDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(captured): %v", err)
	}
	if gotDir != wantDir {
		t.Fatalf("working_dir=%q want %q", captured.WorkingDir, tmp)
	}
	if captured.BaseURL != "https://app.aweb.ai" {
		t.Fatalf("base_url=%q", captured.BaseURL)
	}
	if captured.Role != "reviewer" {
		t.Fatalf("role=%q", captured.Role)
	}
	if !captured.AskPostCreateSetup {
		t.Fatal("expected guided onboarding to include post-create setup prompts")
	}
	if readyCalls != 1 {
		t.Fatalf("expected post-wizard ready message once, got %d", readyCalls)
	}
}

func TestInitFailsNonInteractiveWhenWorkspaceMissing(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.

	oldIsTTY := initIsTTY
	t.Cleanup(func() {
		initIsTTY = oldIsTTY
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initInjectDocs = false
	initSetupHooks = false
	initIsTTY = func() bool { return false }

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	err := runInit(&cmd.Command, nil)
	if err == nil {
		t.Fatal("expected runInit to fail")
	}
	if !strings.Contains(err.Error(), "rerun `aw init` in a TTY for guided onboarding") {
		t.Fatalf("unexpected error: %v", err)
	}
}
