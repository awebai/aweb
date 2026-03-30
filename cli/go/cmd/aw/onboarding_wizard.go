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
)

type guidedOnboardingRequest struct {
	WorkingDir         string
	PromptIn           io.Reader
	PromptOut          io.Writer
	ServerURL          string
	ServerName         string
	AccountName        string
	ProjectSlug        string
	NamespaceSlug      string
	Alias              string
	Name               string
	Reachability       string
	HumanName          string
	AgentType          string
	SaveConfig         bool
	SetDefault         bool
	WriteContext       bool
	Role               string
	Permanent          bool
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

	opts, err := collectInitOptionsWithInput(flowProjectKey, initCollectionInput{
		WorkingDir:   req.WorkingDir,
		Interactive:  true,
		PromptIn:     req.PromptIn,
		PromptOut:    req.PromptOut,
		ServerURL:    serverURL,
		ServerName:   req.ServerName,
		AccountName:  req.AccountName,
		Alias:        req.Alias,
		Name:         req.Name,
		Reachability: req.Reachability,
		HumanName:    req.HumanName,
		AgentType:    req.AgentType,
		SaveConfig:   req.SaveConfig,
		SetDefault:   req.SetDefault,
		WriteContext: req.WriteContext,
		Role:         req.Role,
		Permanent:    permanent,
		PromptRole:   true,
		PromptName:   true,
		AuthToken:    strings.TrimSpace(req.AuthToken),
	})
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
	projectSlug, err := promptStringWithIO("Project", sanitizeSlug(filepath.Base(req.WorkingDir)), req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}
	permanent, err := promptIdentityLifetime(req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}

	opts, err := collectInitOptionsWithInput(flowHeadless, initCollectionInput{
		WorkingDir:       req.WorkingDir,
		Interactive:      true,
		PromptIn:         req.PromptIn,
		PromptOut:        req.PromptOut,
		ServerURL:        serverURL,
		ServerName:       req.ServerName,
		AccountName:      req.AccountName,
		ProjectSlug:      firstNonEmpty(req.ProjectSlug, sanitizeSlug(projectSlug)),
		NamespaceSlug:    req.NamespaceSlug,
		Alias:            "",
		Name:             req.Name,
		Reachability:     req.Reachability,
		HumanName:        req.HumanName,
		AgentType:        req.AgentType,
		SaveConfig:       req.SaveConfig,
		SetDefault:       req.SetDefault,
		WriteContext:     req.WriteContext,
		Role:             req.Role,
		Permanent:        permanent,
		PromptName:       true,
		DeferAliasPrompt: true,
		DeferRolePrompt:  true,
	})
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
		if hooks, err := promptYesNoWithIO("Set up Claude hooks for aw notify?", false, req.PromptIn, req.PromptOut); err == nil && hooks {
			printClaudeHooksResult(guidedOnboardingSetupHooks(repoRoot, false))
		} else if err != nil {
			return nil, err
		}
	}

	return &guidedOnboardingResult{InitialPrompt: "Download and study the agent guide at https://aweb.ai/agent-guide.txt before doing anything else."}, nil
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
