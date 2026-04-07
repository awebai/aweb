package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

var (
	guidedOnboardingWizard                = executeGuidedOnboardingWizard
	guidedOnboardingConnect               = initCertificateConnectWithOptions
	guidedOnboardingExecuteHostedPath     = executeHostedPath
	guidedOnboardingExecuteBYODPath       = executeBYODPath
	guidedOnboardingProvisionBYODIdentity = provisionBYODIdentity
	guidedOnboardingInjectDocs            = InjectAgentDocs
	guidedOnboardingSetupHooks            = SetupClaudeHooks
	guidedOnboardingSetupChannel          = SetupChannelMCP
)

const guidedOnboardingDefaultTeamName = "default"

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

type guidedBYODProvision struct {
	Identity    *preparedIDCreate
	Certificate *awid.TeamCertificate
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
	req.PromptIn = bufferedPromptReader(guidedPromptIn(req.PromptIn))
	req.PromptOut = guidedPromptOut(req.PromptOut)

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
	return result, nil
}

func executeReconnectPath(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	serverURL := strings.TrimSpace(req.ServerURL)
	if serverURL == "" {
		serverURL = defaultWizardServerURL()
	}

	result, err := guidedOnboardingConnect(req.WorkingDir, serverURL, certificateConnectOptions{
		Role: req.Role,
	})
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
	req.PromptIn = bufferedPromptReader(guidedPromptIn(req.PromptIn))
	req.PromptOut = guidedPromptOut(req.PromptOut)

	name, err := resolveGuidedBYODName(req)
	if err != nil {
		return nil, err
	}
	domain, err := promptRequiredStringWithIO("Domain", "", req.PromptIn, req.PromptOut)
	if err != nil {
		return nil, err
	}

	provisioned, err := guidedOnboardingProvisionBYODIdentity(req, name, domain)
	if err != nil {
		return nil, err
	}
	if err := persistGuidedBYODIdentity(provisioned); err != nil {
		return nil, err
	}

	serverURL := strings.TrimSpace(req.ServerURL)
	if serverURL == "" {
		serverURL = defaultWizardServerURL()
	}
	result, err := guidedOnboardingConnect(req.WorkingDir, serverURL, certificateConnectOptions{
		Role:      req.Role,
		HumanName: req.HumanName,
		AgentType: req.AgentType,
	})
	if err != nil {
		return nil, err
	}
	printOutput(result, formatConnect)
	if err := runGuidedPostInitSetup(req); err != nil {
		return nil, err
	}
	return &guidedOnboardingResult{}, nil
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

func resolveGuidedBYODName(req guidedOnboardingRequest) (string, error) {
	name := strings.TrimSpace(req.Name)
	if name == "" {
		prompted, err := promptRequiredStringWithIO("Name", "", req.PromptIn, req.PromptOut)
		if err != nil {
			return "", err
		}
		name = prompted
	}
	return normalizeIDCreateName(name)
}

func provisionBYODIdentity(req guidedOnboardingRequest, name, domain string) (*guidedBYODProvision, error) {
	opts := idCreateOptions{
		Name:      name,
		Domain:    domain,
		PromptIn:  req.PromptIn,
		PromptOut: req.PromptOut,
		Now:       time.Now,
	}
	prepared, err := prepareIDCreatePlan(req.WorkingDir, opts)
	if err != nil {
		return nil, err
	}
	if err := printIDCreateDNSInstructions(prepared.Plan, opts.PromptOut); err != nil {
		return nil, err
	}
	if err := confirmAndVerifyIDCreateDNS(prepared.Plan, opts); err != nil {
		return nil, err
	}

	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, err
	}
	if err := registry.SetFallbackRegistryURL(prepared.Plan.RegistryURL); err != nil {
		return nil, fmt.Errorf("invalid planned registry URL: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ensureStandaloneRegistryRegistration(ctx, registry, prepared.Plan, prepared.ControllerKey, prepared.IdentityKey); err != nil {
		return nil, err
	}

	alias := strings.TrimSpace(req.Alias)
	if alias == "" {
		alias = prepared.Plan.Name
	}
	team, err := bootstrapFirstLocalTeamMember(
		ctx,
		registry,
		prepared.Plan.RegistryURL,
		prepared.Plan.Domain,
		guidedOnboardingDefaultTeamName,
		"",
		prepared.ControllerKey,
		prepared.IdentityKey,
		prepared.Plan.DIDAW,
		prepared.Plan.Address,
		alias,
	)
	if err != nil {
		return nil, err
	}

	return &guidedBYODProvision{
		Identity:    prepared,
		Certificate: team.Certificate,
	}, nil
}

func persistGuidedBYODIdentity(provisioned *guidedBYODProvision) error {
	if provisioned == nil || provisioned.Identity == nil || provisioned.Identity.Plan == nil {
		return fmt.Errorf("missing BYOD identity material")
	}
	if provisioned.Certificate == nil {
		return fmt.Errorf("missing BYOD team certificate")
	}
	plan := provisioned.Identity.Plan
	if err := awid.SaveSigningKey(plan.SigningKeyPath, provisioned.Identity.IdentityKey); err != nil {
		return err
	}
	certPath := filepath.Join(filepath.Dir(plan.IdentityPath), "team-cert.pem")
	if err := awid.SaveTeamCertificate(certPath, provisioned.Certificate); err != nil {
		return err
	}
	return awconfig.SaveWorktreeIdentityTo(plan.IdentityPath, &awconfig.WorktreeIdentity{
		DID:            plan.DIDKey,
		StableID:       plan.DIDAW,
		Address:        plan.Address,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    plan.RegistryURL,
		RegistryStatus: "registered",
		CreatedAt:      plan.CreatedAt,
	})
}

func guidedPromptIn(in io.Reader) io.Reader {
	if in != nil {
		return in
	}
	return os.Stdin
}

func guidedPromptOut(out io.Writer) io.Writer {
	if out != nil {
		return out
	}
	return os.Stderr
}
