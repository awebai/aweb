package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	guidedOnboardingWizard            = executeGuidedOnboardingWizard
	guidedOnboardingConnect           = initCertificateConnect
	guidedOnboardingExecuteHostedPath = executeHostedPath
	guidedOnboardingExecuteBYODPath   = executeBYODPath
	guidedOnboardingInjectDocs        = InjectAgentDocs
	guidedOnboardingSetupHooks        = SetupClaudeHooks
	guidedOnboardingSetupChannel      = SetupChannelMCP
)

type guidedOnboardingRequest struct {
	WorkingDir         string
	PromptIn           io.Reader
	PromptOut          io.Writer
	ServerURL          string
	ServerName         string
	Alias              string
	Name               string
	Reachability       string
	HumanName          string
	AgentType          string
	Role               string
	AskPostCreateSetup bool
}

type guidedOnboardingResult struct {
	InitialPrompt string
}

type guidedOnboardingPath string

const (
	guidedOnboardingPathHosted guidedOnboardingPath = "Use the aweb.ai managed identity"
	guidedOnboardingPathBYOD   guidedOnboardingPath = "I have a domain I control (BYOD)"
)

func executeGuidedOnboardingWizard(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	if strings.TrimSpace(req.WorkingDir) == "" {
		return nil, fmt.Errorf("working directory is required")
	}

	if guidedOnboardingHasReconnectState(req.WorkingDir) {
		return executeReconnectPath(req)
	}

	path, err := promptGuidedOnboardingPath(req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}

	var result *guidedOnboardingResult
	switch path {
	case guidedOnboardingPathHosted:
		result, err = guidedOnboardingExecuteHostedPath(req)
	case guidedOnboardingPathBYOD:
		result, err = guidedOnboardingExecuteBYODPath(req)
	default:
		return nil, fmt.Errorf("unsupported onboarding path %q", path)
	}
	if err != nil {
		return nil, err
	}

	if err := runGuidedPostInitSetup(req); err != nil {
		return nil, err
	}
	return result, nil
}

func executeReconnectPath(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	serverURL := strings.TrimSpace(req.ServerURL)
	if serverURL == "" {
		serverURL = defaultWizardServerURL()
	}

	result, err := guidedOnboardingConnect(req.WorkingDir, serverURL, req.Role)
	if err != nil {
		return nil, err
	}
	printOutput(result, formatConnect)

	if err := runGuidedPostInitSetup(req); err != nil {
		return nil, err
	}
	return &guidedOnboardingResult{}, nil
}

func executeHostedPath(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	return nil, usageError(
		"guided Hosted onboarding is not available in this build yet; use the aweb.ai managed onboarding flow outside the CLI for now, or rerun after aweb-aafx.3 lands",
	)
}

func executeBYODPath(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	return nil, usageError(
		"guided BYOD onboarding is not available in this build yet; create or accept your identity first, then rerun `aw init --server <server>` after aweb-aafx.4 lands",
	)
}

func guidedOnboardingHasReconnectState(workingDir string) bool {
	_, err := os.Stat(filepath.Join(workingDir, ".aw", "identity.yaml"))
	if err != nil {
		return false
	}
	_, err = os.Stat(filepath.Join(workingDir, ".aw", "team-cert.pem"))
	return err == nil
}

func promptGuidedOnboardingPath(in io.Reader, out io.Writer) (guidedOnboardingPath, error) {
	fmt.Fprintln(out, "How should this agent get its identity?")
	fmt.Fprintln(out, "  Hosted is the fastest path. BYOD uses a domain you already control.")
	choice, err := promptIndexedChoice(
		"Choose onboarding path",
		[]string{string(guidedOnboardingPathHosted), string(guidedOnboardingPathBYOD)},
		0,
		in,
		out,
	)
	if err != nil {
		return "", err
	}
	return guidedOnboardingPath(choice), nil
}

func runGuidedPostInitSetup(req guidedOnboardingRequest) error {
	if !req.AskPostCreateSetup {
		return nil
	}

	repoRoot := resolveRepoRoot(req.WorkingDir)
	if docs, err := promptYesNoWithIO("Inject agent docs into this repo?", false, req.PromptIn, req.PromptOut); err == nil && docs {
		printInjectDocsResult(guidedOnboardingInjectDocs(repoRoot))
	} else if err != nil {
		return err
	}
	if channel, err := promptYesNoWithIO(
		"Set up Claude Code channel for real-time coordination?\n"+
			"  (Alternative: install the plugin with /plugin install aweb-channel@awebai-marketplace)",
		false, req.PromptIn, req.PromptOut,
	); err == nil && channel {
		printChannelMCPResult(guidedOnboardingSetupChannel(repoRoot, false))
	} else if err != nil {
		return err
	} else if !channel {
		if hooks, err := promptYesNoWithIO("Set up Claude hooks for aw notify? (polling fallback)", false, req.PromptIn, req.PromptOut); err == nil && hooks {
			printClaudeHooksResult(guidedOnboardingSetupHooks(repoRoot, false))
		} else if err != nil {
			return err
		}
	}
	return nil
}

func promptYesNoWithIO(label string, defaultYes bool, in io.Reader, out io.Writer) (bool, error) {
	defaultValue := "y"
	if !defaultYes {
		defaultValue = "n"
	}
	answer, err := promptStringWithIO(label+" (y/n)", defaultValue, in, out)
	if err != nil {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(answer)) {
	case "y", "yes":
		return true, nil
	case "n", "no":
		return false, nil
	default:
		return false, usageError("please answer y or n")
	}
}

func defaultWizardServerURL() string {
	if serverURL := strings.TrimSpace(os.Getenv("AWEB_URL")); serverURL != "" {
		return serverURL
	}
	return DefaultServerURL
}
