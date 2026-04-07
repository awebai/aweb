package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type singleByteReader struct {
	data string
}

func (r *singleByteReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	p[0] = r.data[0]
	r.data = r.data[1:]
	return 1, nil
}

func TestGuidedOnboardingReconnectSkipsWizardWhenIdentityAndCertExist(t *testing.T) {
	oldConnect := guidedOnboardingConnect
	oldHosted := guidedOnboardingExecuteHostedPath
	oldBYOD := guidedOnboardingExecuteBYODPath
	t.Cleanup(func() {
		guidedOnboardingConnect = oldConnect
		guidedOnboardingExecuteHostedPath = oldHosted
		guidedOnboardingExecuteBYODPath = oldBYOD
	})

	tmp := t.TempDir()
	awDir := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(awDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "identity.yaml"), []byte("name: alice\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(awDir, "team-cert.pem"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var connectWorkingDir, connectServerURL, connectRole string
	var hostedCalls, byodCalls int
	guidedOnboardingConnect = func(workingDir, serverURL, role string) (connectOutput, error) {
		connectWorkingDir = workingDir
		connectServerURL = serverURL
		connectRole = role
		return connectOutput{
			Status:      "connected",
			TeamAddress: "alice.aweb.ai/default",
			Alias:       "alice",
			ServerURL:   serverURL,
		}, nil
	}
	guidedOnboardingExecuteHostedPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		hostedCalls++
		return &guidedOnboardingResult{}, nil
	}
	guidedOnboardingExecuteBYODPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		byodCalls++
		return &guidedOnboardingResult{}, nil
	}

	result, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: tmp,
		PromptIn:   strings.NewReader("2\n"),
		PromptOut:  &bytes.Buffer{},
		ServerURL:  "https://app.aweb.ai",
		Role:       "reviewer",
	})
	if err != nil {
		t.Fatalf("executeGuidedOnboardingWizard: %v", err)
	}
	if result == nil {
		t.Fatal("expected result")
	}
	if connectWorkingDir != tmp {
		t.Fatalf("working_dir=%q", connectWorkingDir)
	}
	if connectServerURL != "https://app.aweb.ai" {
		t.Fatalf("server_url=%q", connectServerURL)
	}
	if connectRole != "reviewer" {
		t.Fatalf("role=%q", connectRole)
	}
	if hostedCalls != 0 || byodCalls != 0 {
		t.Fatalf("expected reconnect path only, got hosted=%d byod=%d", hostedCalls, byodCalls)
	}
}

func TestGuidedOnboardingDefaultsToHostedPath(t *testing.T) {
	oldHosted := guidedOnboardingExecuteHostedPath
	oldBYOD := guidedOnboardingExecuteBYODPath
	t.Cleanup(func() {
		guidedOnboardingExecuteHostedPath = oldHosted
		guidedOnboardingExecuteBYODPath = oldBYOD
	})

	var hostedReq guidedOnboardingRequest
	var hostedCalls, byodCalls int
	guidedOnboardingExecuteHostedPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		hostedCalls++
		hostedReq = req
		return &guidedOnboardingResult{InitialPrompt: "study the agent guide"}, nil
	}
	guidedOnboardingExecuteBYODPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		byodCalls++
		return &guidedOnboardingResult{}, nil
	}

	var out bytes.Buffer
	result, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("\n"),
		PromptOut:  &out,
	})
	if err != nil {
		t.Fatalf("executeGuidedOnboardingWizard: %v", err)
	}
	if hostedCalls != 1 || byodCalls != 0 {
		t.Fatalf("expected hosted path, got hosted=%d byod=%d", hostedCalls, byodCalls)
	}
	if strings.TrimSpace(result.InitialPrompt) != "study the agent guide" {
		t.Fatalf("initial_prompt=%q", result.InitialPrompt)
	}
	if hostedReq.WorkingDir == "" {
		t.Fatal("expected hosted path to receive request")
	}
	if !strings.Contains(out.String(), "Hosted is the fastest path") {
		t.Fatalf("expected onboarding choice copy, got %q", out.String())
	}
}

func TestGuidedOnboardingCanSelectBYODPath(t *testing.T) {
	oldHosted := guidedOnboardingExecuteHostedPath
	oldBYOD := guidedOnboardingExecuteBYODPath
	t.Cleanup(func() {
		guidedOnboardingExecuteHostedPath = oldHosted
		guidedOnboardingExecuteBYODPath = oldBYOD
	})

	var hostedCalls, byodCalls int
	guidedOnboardingExecuteHostedPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		hostedCalls++
		return &guidedOnboardingResult{}, nil
	}
	guidedOnboardingExecuteBYODPath = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		byodCalls++
		return &guidedOnboardingResult{InitialPrompt: "byod"}, nil
	}

	result, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("2\n"),
		PromptOut:  &bytes.Buffer{},
	})
	if err != nil {
		t.Fatalf("executeGuidedOnboardingWizard: %v", err)
	}
	if hostedCalls != 0 || byodCalls != 1 {
		t.Fatalf("expected byod path, got hosted=%d byod=%d", hostedCalls, byodCalls)
	}
	if strings.TrimSpace(result.InitialPrompt) != "byod" {
		t.Fatalf("initial_prompt=%q", result.InitialPrompt)
	}
}

func TestGuidedOnboardingHostedStubReturnsUsageErrorInsteadOfPanicking(t *testing.T) {
	var out bytes.Buffer
	_, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("\n"),
		PromptOut:  &out,
	})
	if err == nil {
		t.Fatal("expected hosted path to return an error")
	}
	if !strings.Contains(err.Error(), "guided Hosted onboarding is not available in this build yet") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestGuidedOnboardingBYODStubReturnsUsageErrorInsteadOfPanicking(t *testing.T) {
	var out bytes.Buffer
	_, err := executeGuidedOnboardingWizard(guidedOnboardingRequest{
		WorkingDir: t.TempDir(),
		PromptIn:   strings.NewReader("2\n"),
		PromptOut:  &out,
	})
	if err == nil {
		t.Fatal("expected BYOD path to return an error")
	}
	if !strings.Contains(err.Error(), "guided BYOD onboarding is not available in this build yet") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunGuidedPostInitSetupKeepsDocsChannelHooksPrompts(t *testing.T) {
	oldInjectDocs := guidedOnboardingInjectDocs
	oldSetupHooks := guidedOnboardingSetupHooks
	oldSetupChannel := guidedOnboardingSetupChannel
	t.Cleanup(func() {
		guidedOnboardingInjectDocs = oldInjectDocs
		guidedOnboardingSetupHooks = oldSetupHooks
		guidedOnboardingSetupChannel = oldSetupChannel
	})

	tmp := t.TempDir()
	var docsRepo, hooksRepo, channelRepo string
	var hooksAsk bool
	guidedOnboardingInjectDocs = func(repoRoot string) *injectDocsResult {
		docsRepo = repoRoot
		return &injectDocsResult{}
	}
	guidedOnboardingSetupChannel = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		channelRepo = repoRoot
		return &claudeHooksResult{}
	}
	guidedOnboardingSetupHooks = func(repoRoot string, askConfirmation bool) *claudeHooksResult {
		hooksRepo = repoRoot
		hooksAsk = askConfirmation
		return &claudeHooksResult{}
	}

	err := runGuidedPostInitSetup(guidedOnboardingRequest{
		WorkingDir:         tmp,
		PromptIn:           &singleByteReader{data: "y\nn\ny\n"},
		PromptOut:          &bytes.Buffer{},
		AskPostCreateSetup: true,
	})
	if err != nil {
		t.Fatalf("runGuidedPostInitSetup: %v", err)
	}
	if docsRepo != tmp {
		t.Fatalf("docs_repo=%q", docsRepo)
	}
	if channelRepo != "" {
		t.Fatalf("expected channel setup to be skipped, got %q", channelRepo)
	}
	if hooksRepo != tmp {
		t.Fatalf("hooks_repo=%q", hooksRepo)
	}
	if hooksAsk {
		t.Fatal("expected wizard to handle hooks confirmation before setup call")
	}
}

func TestPromptIdentityLifetimeShowsDescriptions(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("\n") // accept default (ephemeral)
	var out bytes.Buffer
	permanent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if permanent {
		t.Fatal("expected ephemeral (default), got permanent")
	}
	output := out.String()
	if !strings.Contains(output, "workspace-bound") {
		t.Fatalf("expected ephemeral description, got %q", output)
	}
	if !strings.Contains(output, "public addresses") {
		t.Fatalf("expected permanent description, got %q", output)
	}
	if strings.Contains(output, "number") {
		t.Fatalf("prompt should not say 'number', got %q", output)
	}
}

func TestPromptIdentityLifetimePermanent(t *testing.T) {
	t.Parallel()
	in := strings.NewReader("2\n")
	var out bytes.Buffer
	permanent, err := promptIdentityLifetime(in, &out)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !permanent {
		t.Fatal("expected permanent, got ephemeral")
	}
}
