package main

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	guidedOnboardingWizard           = executeGuidedOnboardingWizard
	guidedOnboardingExecuteInitFlow  = executeInit
	guidedOnboardingPrintInitSummary = printInitSummary
	guidedOnboardingInjectDocs       = InjectAgentDocs
	guidedOnboardingSetupHooks       = SetupClaudeHooks
	guidedOnboardingSetupChannel     = SetupChannelMCP
)

type guidedOnboardingRequest struct {
	WorkingDir         string
	PromptIn           io.Reader
	PromptOut          io.Writer
	ServerURL          string
	ServerName         string
	ProjectSlug        string
	NamespaceSlug      string
	Alias              string
	Name               string
	Reachability       string
	HumanName          string
	AgentType          string
	Role               string
	AuthToken          string
	AskPostCreateSetup bool
}

type guidedOnboardingResult struct {
	InitialPrompt string
}

func executeGuidedOnboardingWizard(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	if strings.TrimSpace(req.WorkingDir) == "" {
		return nil, fmt.Errorf("working directory is required")
	}

	if strings.TrimSpace(req.AuthToken) != "" {
		return executeGuidedExistingProjectInit(req)
	}
	return executeGuidedProjectCreate(req)
}

func executeGuidedExistingProjectInit(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	serverURL, err := promptRequiredStringWithIO("Server URL", defaultWizardServerURL(), req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}
	permanent, err := promptIdentityLifetime(req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}

	opts, err := collectInitOptionsWithInput(flowProjectKey, guidedOnboardingInitInput(req, initCollectionInput{
		WorkingDir:   req.WorkingDir,
		Interactive:  true,
		PromptIn:     req.PromptIn,
		PromptOut:    req.PromptOut,
		ServerURL:    serverURL,
		ServerName:   req.ServerName,
		Alias:        req.Alias,
		Name:         req.Name,
		Reachability: req.Reachability,
		HumanName:    req.HumanName,
		AgentType:    req.AgentType,
		Role:         req.Role,
		Permanent:    permanent,
		PromptRole:   true,
		PromptName:   true,
		AuthToken:    strings.TrimSpace(req.AuthToken),
	}))
	if err != nil {
		return nil, err
	}

	result, err := guidedOnboardingExecuteInitFlow(opts)
	if err != nil {
		return nil, err
	}
	guidedOnboardingPrintInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, req.WorkingDir, "Initialized workspace")
	return &guidedOnboardingResult{}, nil
}

func executeGuidedProjectCreate(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	serverURL, err := promptRequiredStringWithIO("Server URL", defaultWizardServerURL(), req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}
	slugDefault := firstNonEmpty(req.ProjectSlug, sanitizeSlug(filepath.Base(req.WorkingDir)))
	projectSlug, err := promptProjectSlug(padSlug(slugDefault, 3), req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}
	permanent, err := promptIdentityLifetime(req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}

	opts, err := collectInitOptionsWithInput(flowHeadless, guidedOnboardingInitInput(req, initCollectionInput{
		WorkingDir:       req.WorkingDir,
		Interactive:      true,
		PromptIn:         req.PromptIn,
		PromptOut:        req.PromptOut,
		ServerURL:        serverURL,
		ServerName:       req.ServerName,
		ProjectSlug:      sanitizeSlug(projectSlug),
		NamespaceSlug:    req.NamespaceSlug,
		Alias:            "",
		Name:             req.Name,
		Reachability:     req.Reachability,
		HumanName:        req.HumanName,
		AgentType:        req.AgentType,
		Role:             req.Role,
		Permanent:        permanent,
		PromptName:       true,
		DeferAliasPrompt: true,
		DeferRolePrompt:  true,
	}))
	if err != nil {
		return nil, err
	}

	result, err := guidedOnboardingExecuteInitFlow(opts)
	if err != nil {
		return nil, err
	}
	guidedOnboardingPrintInitSummary(result.Response, result.AccountName, result.ServerName, result.Role, result.AttachResult, result.SigningKeyPath, req.WorkingDir, "Created project and initialized workspace")

	if req.AskPostCreateSetup {
		repoRoot := resolveRepoRoot(req.WorkingDir)
		if docs, err := promptYesNoWithIO("Inject agent docs into this repo?", false, req.PromptIn, req.PromptOut); err == nil && docs {
			printInjectDocsResult(guidedOnboardingInjectDocs(repoRoot))
		} else if err != nil {
			return nil, err
		}
		if channel, err := promptYesNoWithIO(
			"Set up Claude Code channel for real-time coordination?\n"+
				"  (Alternative: install the plugin with /plugin install aweb-channel@awebai-marketplace)",
			false, req.PromptIn, req.PromptOut,
		); err == nil && channel {
			printChannelMCPResult(guidedOnboardingSetupChannel(repoRoot, false))
		} else if err != nil {
			return nil, err
		} else if !channel {
			if hooks, err := promptYesNoWithIO("Set up Claude hooks for aw notify? (polling fallback)", false, req.PromptIn, req.PromptOut); err == nil && hooks {
				printClaudeHooksResult(guidedOnboardingSetupHooks(repoRoot, false))
			} else if err != nil {
				return nil, err
			}
		}
	}

	return &guidedOnboardingResult{InitialPrompt: "Download and study the agent guide at https://aweb.ai/agent-guide.txt before doing anything else."}, nil
}

func guidedOnboardingInitInput(req guidedOnboardingRequest, input initCollectionInput) initCollectionInput {
	input.WorkingDir = req.WorkingDir
	input.PromptIn = req.PromptIn
	input.PromptOut = req.PromptOut
	input.SaveConfig = false
	input.SetDefault = false
	input.WriteContext = true
	return input
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

const minProjectSlugLength = 3

func padSlug(slug string, minLen int) string {
	for len(slug) < minLen {
		slug += "x"
	}
	return slug
}

func promptProjectSlug(defaultSlug string, in io.Reader, out io.Writer) (string, error) {
	reader := bufferedPromptReader(in)
	for {
		fmt.Fprintf(out, "Project [%s]: ", defaultSlug)
		line, err := reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			line = defaultSlug
		}
		slug := sanitizeSlug(line)
		if len(slug) < minProjectSlugLength {
			fmt.Fprintf(out, "Project slug must be at least %d characters.\n", minProjectSlugLength)
			continue
		}
		return slug, nil
	}
}

func defaultWizardServerURL() string {
	if serverURL := strings.TrimSpace(os.Getenv("AWEB_URL")); serverURL != "" {
		return serverURL
	}
	return DefaultServerURL
}
