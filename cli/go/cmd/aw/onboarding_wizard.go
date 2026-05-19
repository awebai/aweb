package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
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
	guidedOnboardingCheckUsername         = awid.CheckUsername
	guidedOnboardingCliSignup             = awid.CliSignup
	guidedOnboardingClaimHuman            = claimHumanWithOptions
	guidedOnboardingInjectDocs            = InjectAgentDocs
	guidedOnboardingSetupHooks            = SetupClaudeHooks
	guidedOnboardingSetupChannel          = SetupChannelMCP
)

const guidedOnboardingDefaultTeamName = "default"

type guidedOnboardingRequest struct {
	WorkingDir         string
	PromptIn           io.Reader
	PromptOut          io.Writer
	BaseURL            string
	RegistryURL        string
	ServerName         string
	BYOD               bool
	Username           string
	Domain             string
	Alias              string
	Name               string
	HumanName          string
	AgentType          string
	Role               string
	Persistent         bool
	InjectAgentDocs    bool
	DoNotTouchAgentsMD bool
	AskPostCreateSetup bool
	NonInteractive     bool
}

type guidedOnboardingResult struct {
	InitialPrompt string
}

type guidedBYODProvision struct {
	Identity    *preparedIDCreate
	Certificate *awid.TeamCertificate
}

func executeGuidedOnboardingWizard(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	if strings.TrimSpace(req.WorkingDir) == "" {
		return nil, fmt.Errorf("working directory is required")
	}
	req.PromptIn = bufferedPromptReader(guidedPromptIn(req.PromptIn))
	req.PromptOut = guidedPromptOut(req.PromptOut)

	if guidedOnboardingHasReconnectState(req.WorkingDir) {
		return executeReconnectPath(req)
	}

	if req.BYOD {
		return guidedOnboardingExecuteBYODPath(req)
	}
	return guidedOnboardingExecuteHostedPath(req)
}

func executeReconnectPath(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	serviceURLs, err := resolveReconnectServiceURLs(req)
	if err != nil {
		return nil, err
	}

	result, err := guidedOnboardingConnect(req.WorkingDir, serviceURLs.AwebURL, certificateConnectOptions{
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
	req.PromptIn = bufferedPromptReader(guidedPromptIn(req.PromptIn))
	req.PromptOut = guidedPromptOut(req.PromptOut)

	if err := validateHostedNonInteractiveRequired(req); err != nil {
		return nil, err
	}

	serviceURLs, err := discoverOnboardingServiceURLs(req.BaseURL)
	if err != nil {
		if req.NonInteractive {
			return nil, usageError("hosted onboarding is not available on this server; use --byod with a domain you control")
		}
		fmt.Fprintln(req.PromptOut, "Managed onboarding is not available here. Switching to BYOD.")
		return executeBYODPath(req)
	}

	username, err := resolveGuidedHostedUsername(req, serviceURLs.OnboardingURL)
	if err != nil {
		return nil, err
	}
	persistent, err := resolveGuidedHostedPersistent(req)
	if err != nil {
		return nil, err
	}
	req.Persistent = persistent
	alias, err := resolveGuidedHostedAlias(req)
	if err != nil {
		return nil, err
	}

	var provisioned hostedIdentityProvision
	for {
		provisioned, err = provisionHostedIdentity(serviceURLs.OnboardingURL, serviceURLs.RegistryURL, username, alias, req.Persistent)
		if err != nil {
			if hostedUsernameTakenOnSignup(err) {
				if req.NonInteractive {
					return nil, usageError("username %q is not available (taken)", username)
				}
				fmt.Fprintf(req.PromptOut, "Username %q was taken during signup. Choose another.\n", username)
				username, err = promptAvailableHostedUsername(req.PromptIn, req.PromptOut, serviceURLs.OnboardingURL)
				if err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		if err := persistGuidedHostedState(
			req.WorkingDir,
			provisioned.RegistryURL,
			provisioned.SigningKey,
			provisioned.Certificate,
			provisioned.DIDKey,
			provisioned.DIDAW,
			provisioned.MemberAddress,
			req.Persistent,
		); err != nil {
			return nil, err
		}
		break
	}

	result, err := guidedOnboardingConnect(req.WorkingDir, serviceURLs.AwebURL, certificateConnectOptions{
		Role:      req.Role,
		HumanName: req.HumanName,
		AgentType: req.AgentType,
		APIKey:    provisioned.APIKey,
	})
	if err != nil {
		return nil, err
	}
	printOutput(result, formatConnect)

	if err := runGuidedPostInitSetup(req); err != nil {
		return nil, err
	}
	if req.AskPostCreateSetup && !req.NonInteractive {
		if err := promptHostedClaimHuman(req, serviceURLs.OnboardingURL); err != nil {
			return nil, err
		}
	}
	return &guidedOnboardingResult{}, nil
}

func validateHostedNonInteractiveRequired(req guidedOnboardingRequest) error {
	if !req.NonInteractive {
		return nil
	}
	if strings.TrimSpace(req.Username) == "" {
		return usageError("missing required flag: --username")
	}
	if req.Persistent {
		if strings.TrimSpace(req.Name) == "" && strings.TrimSpace(req.Alias) == "" {
			return usageError("missing required flag: --name")
		}
		return nil
	}
	if strings.TrimSpace(req.Alias) == "" && strings.TrimSpace(req.Name) == "" {
		return usageError("missing required flag: --alias")
	}
	return nil
}

func executeBYODPath(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
	req.PromptIn = bufferedPromptReader(guidedPromptIn(req.PromptIn))
	req.PromptOut = guidedPromptOut(req.PromptOut)

	persistent, err := resolveGuidedBYODPersistent(req)
	if err != nil {
		return nil, err
	}
	req.Persistent = persistent

	name, err := resolveGuidedBYODName(req, persistent)
	if err != nil {
		return nil, err
	}
	domain, err := resolveGuidedBYODDomain(req)
	if err != nil {
		return nil, err
	}
	printGuidedBYODIdentityPlan(req.PromptOut, persistent, name, domain)

	serviceURLs, err := resolveOnboardingServiceURLs(req.BaseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(req.RegistryURL) == "" && strings.TrimSpace(serviceURLs.RegistryURL) != "" {
		req.RegistryURL = strings.TrimSpace(serviceURLs.RegistryURL)
	}

	provisioned, err := guidedOnboardingProvisionBYODIdentity(req, name, domain)
	if err != nil {
		return nil, err
	}
	if err := persistGuidedBYODIdentity(provisioned); err != nil {
		return nil, err
	}

	result, err := guidedOnboardingConnect(req.WorkingDir, serviceURLs.AwebURL, certificateConnectOptions{
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
	stored, err := awconfig.ListTeamCertificates(workingDir)
	return err == nil && len(stored) > 0
}

func runGuidedPostInitSetup(req guidedOnboardingRequest) error {
	repoRoot := resolveRepoRoot(req.WorkingDir)
	if req.InjectAgentDocs && !req.DoNotTouchAgentsMD {
		printInjectDocsResult(guidedOnboardingInjectDocs(repoRoot))
	}
	if !req.AskPostCreateSetup {
		return nil
	}
	if channel, err := promptYesNoWithIO(
		"Set up Claude Code channel for real-time coordination?\n"+
			"  (Alternative: install the plugin with /plugin install aweb-channel@awebai-marketplace)",
		true, req.PromptIn, req.PromptOut,
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

func defaultWizardAwebURL() string {
	if awebURL := strings.TrimSpace(os.Getenv("AWEB_URL")); awebURL != "" {
		return awebURL
	}
	return DefaultAwebURL
}

func resolveGuidedOnboardingAwebURL(raw string) (string, error) {
	awebURL := strings.TrimSpace(raw)
	if awebURL == "" {
		awebURL = defaultWizardAwebURL()
	}
	return normalizeAwebBaseURL(awebURL)
}

func guidedOnboardingSkipDNSVerify() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AWID_SKIP_DNS_VERIFY"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
}

func resolveGuidedBYODPersistent(req guidedOnboardingRequest) (bool, error) {
	// Default ephemeral; the --persistent flag is the only signal that promotes
	// the identity to a durable did:aw. --name no longer implies persistent —
	// it's just the agent name.
	return req.Persistent, nil
}

func resolveGuidedHostedPersistent(req guidedOnboardingRequest) (bool, error) {
	// Default ephemeral; --persistent is the only signal. Matches BYOD shape.
	return req.Persistent, nil
}

func resolveGuidedBYODName(req guidedOnboardingRequest, persistent bool) (string, error) {
	name := strings.TrimSpace(req.Name)
	label := "Agent name"
	if !persistent {
		name = strings.TrimSpace(req.Alias)
		if name == "" {
			name = strings.TrimSpace(req.Name)
		}
		label = "Agent alias"
	}
	if name == "" {
		if req.NonInteractive {
			if persistent {
				return "", usageError("missing required flag: --name")
			}
			return "", usageError("missing required flag: --alias")
		}
		prompted, err := promptRequiredStringWithIO(label, "", req.PromptIn, req.PromptOut)
		if err != nil {
			return "", err
		}
		name = prompted
	}
	return normalizeIDCreateName(name)
}

func resolveGuidedBYODDomain(req guidedOnboardingRequest) (string, error) {
	domain := strings.TrimSpace(req.Domain)
	if domain != "" {
		return domain, nil
	}
	if req.NonInteractive {
		return "", usageError("missing required flag: --domain")
	}
	return promptRequiredStringWithIO("Domain", "", req.PromptIn, req.PromptOut)
}

func printGuidedBYODIdentityPlan(out io.Writer, persistent bool, name, domain string) {
	if out == nil {
		return
	}
	normalizedDomain := awconfig.NormalizeDomain(domain)
	if persistent {
		fmt.Fprintln(out, "Creating persistent BYOD identity.")
		fmt.Fprintf(out, "  Agent name %q becomes public address %s/%s.\n", name, normalizedDomain, name)
		return
	}
	fmt.Fprintln(out, "Creating ephemeral BYOD identity.")
	fmt.Fprintf(out, "  Agent alias %q is used inside team %s:%s.\n", name, guidedOnboardingDefaultTeamName, normalizedDomain)
	fmt.Fprintln(out, "  No public did:aw address will be registered for this workspace.")
}

func provisionBYODIdentity(req guidedOnboardingRequest, name, domain string) (*guidedBYODProvision, error) {
	opts := idCreateOptions{
		Name:          name,
		Domain:        domain,
		RegistryURL:   strings.TrimSpace(req.RegistryURL),
		PromptIn:      req.PromptIn,
		PromptOut:     req.PromptOut,
		SkipDNSVerify: guidedOnboardingSkipDNSVerify(),
		Now:           time.Now,
	}
	prepared, err := prepareIDCreatePlan(req.WorkingDir, opts)
	if err != nil {
		return nil, err
	}
	if req.NonInteractive && prepared.Plan.NeedsDNSSetup && !opts.SkipDNSVerify {
		return nil, usageError("BYOD DNS setup for %s requires a TTY; rerun `aw init --byod --domain %s` interactively after publishing the required TXT record", prepared.Plan.Domain, prepared.Plan.Domain)
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

	if req.Persistent {
		// Persistent BYOD shares the id-create registry path: namespace, identity,
		// then controller-signed address binding.
		if err := ensureStandaloneRegistryRegistration(ctx, registry, prepared.Plan, prepared.ControllerKey, prepared.IdentityKey); err != nil {
			return nil, err
		}
	} else if err := ensureStandaloneNamespace(ctx, registry, prepared.Plan, prepared.ControllerKey); err != nil {
		return nil, err
	}

	alias := strings.TrimSpace(req.Alias)
	if alias == "" {
		alias = prepared.Plan.Name
	}
	lifetime := awid.LifetimeEphemeral
	memberDIDAW := ""
	memberAddress := ""
	if req.Persistent {
		lifetime = awid.LifetimePersistent
		memberDIDAW = prepared.Plan.DIDAW
		memberAddress = prepared.Plan.Address
	}
	team, err := bootstrapLocalTeamMemberWithLifetime(
		ctx,
		registry,
		prepared.Plan.RegistryURL,
		prepared.Plan.Domain,
		guidedOnboardingDefaultTeamName,
		"",
		prepared.ControllerKey,
		prepared.IdentityKey,
		memberDIDAW,
		memberAddress,
		alias,
		lifetime,
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
	workingDir := filepath.Dir(filepath.Dir(plan.IdentityPath))
	if err := persistLocalSigningKeyAndCertificate(workingDir, provisioned.Identity.IdentityKey, provisioned.Certificate); err != nil {
		return err
	}
	if strings.TrimSpace(provisioned.Certificate.Lifetime) == awid.LifetimeEphemeral {
		return nil
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

func persistLocalSigningKeyAndCertificate(workingDir string, signingKey ed25519.PrivateKey, cert *awid.TeamCertificate) error {
	if strings.TrimSpace(workingDir) == "" {
		return fmt.Errorf("working directory is required")
	}
	if signingKey == nil {
		return fmt.Errorf("signing key is required")
	}
	if cert == nil {
		return fmt.Errorf("team certificate is required")
	}
	if err := ensureAwebRuntimeGitIgnored(workingDir); err != nil {
		return err
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), signingKey); err != nil {
		return err
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(workingDir, cert.Team, cert); err != nil {
		return err
	}
	return nil
}

func ensureHostedOnboardingAvailable(awebURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := guidedOnboardingCheckUsername(ctx, awebURL, "Invalid_Probe")
	if err == nil && resp != nil {
		return nil
	}

	var regErr *awid.RegistryError
	if errors.As(err, &regErr) {
		if regErr.StatusCode == http.StatusNotFound {
			return usageError("hosted onboarding is not available on this server; rerun `aw init --byod` with a domain you control")
		}
		if hostedCheckUsernameReason(regErr.Detail) == "invalid_format" {
			return nil
		}
	}
	return err
}

func resolveGuidedHostedAlias(req guidedOnboardingRequest) (string, error) {
	alias := strings.TrimSpace(req.Alias)
	if alias != "" {
		return alias, nil
	}
	if name := strings.TrimSpace(req.Name); name != "" {
		return name, nil
	}
	if req.NonInteractive {
		if req.Persistent {
			return "", usageError("missing required flag: --name")
		}
		return "", usageError("missing required flag: --alias")
	}
	// "alice" is the canonical first-agent name from cli-tutorial.md. The
	// developer who hits Enter at the prompt lands at <username>.aweb.ai/alice
	// for persistent or inside the local team for ephemeral. Sibling worktrees
	// for a second identity pass --alias explicitly (e.g., "bob"). $USER is
	// deliberately not used as a default — that previous behavior silently
	// bound the developer's OS login name to a public did:aw address.
	if req.Persistent {
		return promptRequiredStringWithIO("Agent name", defaultGuidedHostedAlias(), req.PromptIn, req.PromptOut)
	}
	return promptRequiredStringWithIO("Agent alias", defaultGuidedHostedAlias(), req.PromptIn, req.PromptOut)
}

func defaultGuidedHostedAlias() string {
	return "alice"
}

func resolveGuidedHostedUsername(req guidedOnboardingRequest, onboardingURL string) (string, error) {
	username := strings.TrimSpace(req.Username)
	if username == "" {
		if req.NonInteractive {
			return "", usageError("missing required flag: --username")
		}
		return promptAvailableHostedUsername(req.PromptIn, req.PromptOut, onboardingURL)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	resp, err := guidedOnboardingCheckUsername(ctx, onboardingURL, username)
	cancel()
	if err != nil {
		var regErr *awid.RegistryError
		if errors.As(err, &regErr) && regErr.StatusCode == http.StatusNotFound {
			return "", usageError("hosted onboarding is not available on this server; use --byod with a domain you control")
		}
		return "", err
	}
	if resp != nil && resp.Available {
		return username, nil
	}

	reason := ""
	if resp != nil {
		reason = strings.TrimSpace(resp.Reason)
	}
	if reason == "" {
		reason = "unavailable"
	}
	return "", usageError("username %q is not available (%s)", username, reason)
}

func promptAvailableHostedUsername(in io.Reader, out io.Writer, onboardingURL string) (string, error) {
	for {
		username, err := promptRequiredStringWithIO("Username", "", in, out)
		if err != nil {
			return "", err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := guidedOnboardingCheckUsername(ctx, onboardingURL, username)
		cancel()
		if err != nil {
			var regErr *awid.RegistryError
			if errors.As(err, &regErr) && regErr.StatusCode == http.StatusNotFound {
				return "", usageError("hosted onboarding is not available on this server; rerun `aw init --byod` with a domain you control")
			}
			return "", err
		}
		if resp != nil && resp.Available {
			return username, nil
		}

		switch strings.TrimSpace(resp.Reason) {
		case "taken":
			fmt.Fprintf(out, "Username %q is already taken. Try another.\n", username)
		case "reserved":
			fmt.Fprintf(out, "Username %q is reserved. Choose another.\n", username)
		case "invalid_format":
			fmt.Fprintln(out, "Username must use lowercase letters, numbers, or hyphens and be 3-39 characters.")
		default:
			fmt.Fprintf(out, "Username %q is not available. Try another.\n", username)
		}
	}
}

type hostedIdentityProvision struct {
	SigningKey    ed25519.PrivateKey
	Certificate   *awid.TeamCertificate
	DIDKey        string
	DIDAW         string
	MemberAddress string
	RegistryURL   string
	APIKey        string
}

func provisionHostedIdentity(
	onboardingURL, registryURL, username, alias string, persistent bool,
) (hostedIdentityProvision, error) {
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return hostedIdentityProvision{}, err
	}
	if strings.TrimSpace(registryURL) != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return hostedIdentityProvision{}, err
		}
	}

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return hostedIdentityProvision{}, err
	}
	didKey := awid.ComputeDIDKey(pub)
	didAW := ""
	if persistent {
		didAW = awid.ComputeStableID(pub)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if persistent {
		// Hosted onboarding receives the managed address from cli-signup; the CLI
		// publishes only the did:aw identity before asking the cloud to bind it.
		if err := registerHostedDID(ctx, registry, didKey, didAW, signingKey); err != nil {
			return hostedIdentityProvision{}, err
		}
	}

	resp, err := guidedOnboardingCliSignup(ctx, onboardingURL, &awid.CliSignupRequest{
		Username: username,
		DIDKey:   didKey,
		DIDAW:    didAW,
		Alias:    alias,
	}, signingKey)
	if err != nil {
		return hostedIdentityProvision{}, err
	}

	cert, err := validateHostedSignupResponse(resp, didKey, didAW, alias)
	if err != nil {
		return hostedIdentityProvision{}, err
	}
	apiKey := strings.TrimSpace(resp.APIKey)
	if apiKey == "" {
		return hostedIdentityProvision{}, fmt.Errorf("hosted signup response missing api_key")
	}

	return hostedIdentityProvision{
		SigningKey:    signingKey,
		Certificate:   cert,
		DIDKey:        didKey,
		DIDAW:         didAW,
		MemberAddress: strings.TrimSpace(cert.MemberAddress),
		RegistryURL:   strings.TrimSpace(registry.DefaultRegistryURL),
		APIKey:        apiKey,
	}, nil
}

func registerHostedDID(
	ctx context.Context,
	registry *awid.RegistryClient,
	didKey, didAW string,
	signingKey ed25519.PrivateKey,
) error {
	if registry == nil {
		return fmt.Errorf("nil registry client")
	}
	_, err := registry.RegisterIdentity(ctx, registry.DefaultRegistryURL, didKey, didAW, signingKey)
	if already := new(awid.AlreadyRegisteredError); errors.As(err, &already) {
		if strings.TrimSpace(already.ExistingDIDKey) == strings.TrimSpace(didKey) {
			return nil
		}
	}
	return err
}

func validateHostedSignupResponse(
	resp *awid.CliSignupResponse,
	didKey, didAW, alias string,
) (*awid.TeamCertificate, error) {
	if resp == nil {
		return nil, fmt.Errorf("missing hosted signup response")
	}
	if strings.TrimSpace(resp.DIDAW) != strings.TrimSpace(didAW) {
		return nil, fmt.Errorf("hosted signup returned did_aw %q, expected %q", resp.DIDAW, didAW)
	}
	if gotAlias := strings.TrimSpace(resp.Alias); gotAlias != "" && gotAlias != strings.TrimSpace(alias) {
		return nil, fmt.Errorf("hosted signup returned alias %q, expected %q", resp.Alias, alias)
	}

	cert, err := awid.DecodeTeamCertificateHeader(strings.TrimSpace(resp.Certificate))
	if err != nil {
		return nil, fmt.Errorf("decode hosted signup certificate: %w", err)
	}
	if cert.MemberDIDKey != didKey {
		return nil, fmt.Errorf("hosted signup certificate member_did_key %q does not match %q", cert.MemberDIDKey, didKey)
	}
	if cert.MemberDIDAW != didAW {
		return nil, fmt.Errorf("hosted signup certificate member_did_aw %q does not match %q", cert.MemberDIDAW, didAW)
	}
	if strings.TrimSpace(resp.MemberAddress) != strings.TrimSpace(cert.MemberAddress) {
		return nil, fmt.Errorf("hosted signup certificate member_address %q does not match response member_address %q", cert.MemberAddress, resp.MemberAddress)
	}
	if strings.TrimSpace(didAW) != "" && strings.TrimSpace(cert.MemberAddress) == "" {
		return nil, fmt.Errorf("hosted signup response missing member_address for persistent identity")
	}
	if strings.TrimSpace(didAW) == "" && strings.TrimSpace(cert.MemberAddress) != "" {
		return nil, fmt.Errorf("hosted signup response returned member_address %q for ephemeral identity", cert.MemberAddress)
	}
	if cert.Alias != alias {
		return nil, fmt.Errorf("hosted signup certificate alias %q does not match %q", cert.Alias, alias)
	}
	if teamID := strings.TrimSpace(resp.TeamID); teamID != "" && cert.Team != teamID {
		return nil, fmt.Errorf("hosted signup certificate team %q does not match response team_id %q", cert.Team, resp.TeamID)
	}
	return cert, nil
}

func persistGuidedHostedState(
	workingDir, registryURL string,
	signingKey ed25519.PrivateKey,
	cert *awid.TeamCertificate,
	didKey, didAW, memberAddress string,
	persistent bool,
) error {
	if err := persistLocalSigningKeyAndCertificate(workingDir, signingKey, cert); err != nil {
		return err
	}
	if !persistent {
		return nil
	}
	identityPath := filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	return awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{
		DID:            didKey,
		StableID:       didAW,
		Address:        memberAddress,
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    strings.TrimSpace(registryURL),
		RegistryStatus: "registered",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	})
}

func promptHostedClaimHuman(req guidedOnboardingRequest, onboardingURL string) error {
	fmt.Fprintln(req.PromptOut, "Your identity is in .aw/signing.key.")
	fmt.Fprintln(req.PromptOut, "If you lose this file before running 'aw claim-human --email you@example.com', this account cannot be recovered. We recommend claiming now.")

	runNow, err := promptYesNoWithIO("Run aw claim-human now?", true, req.PromptIn, req.PromptOut)
	if err != nil {
		return err
	}
	if !runNow {
		return nil
	}

	email, err := promptRequiredStringWithIO("Email", "", req.PromptIn, req.PromptOut)
	if err != nil {
		return err
	}
	resp, _, err := guidedOnboardingClaimHuman(claimHumanOptions{
		WorkingDir: req.WorkingDir,
		BaseURL:    onboardingURL,
		Email:      email,
	})
	if err != nil {
		return err
	}
	return printClaimHumanSuccess(req.PromptOut, email, resp)
}

func resolveReconnectServiceURLs(req guidedOnboardingRequest) (onboardingServiceURLs, error) {
	if strings.TrimSpace(req.BaseURL) != "" {
		return resolveOnboardingServiceURLs(req.BaseURL)
	}

	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(req.WorkingDir)
	if err == nil {
		rawURL := strings.TrimSpace(workspace.AwebURL)
		if rawURL != "" {
			return resolveOnboardingServiceURLs(rawURL)
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return onboardingServiceURLs{}, err
	}

	awebURL, err := resolveGuidedOnboardingAwebURL(req.BaseURL)
	if err != nil {
		return onboardingServiceURLs{}, err
	}
	return onboardingServiceURLs{
		AwebURL: awebURL,
	}, nil
}

func hostedUsernameTakenOnSignup(err error) bool {
	var regErr *awid.RegistryError
	if !errors.As(err, &regErr) || regErr.StatusCode != http.StatusConflict {
		return false
	}
	return true
}

func hostedCheckUsernameReason(detail string) string {
	body := strings.TrimSpace(detail)
	if body == "" {
		return ""
	}

	var envelope map[string]any
	if err := json.Unmarshal([]byte(body), &envelope); err == nil {
		if reason, ok := envelope["reason"].(string); ok {
			return strings.TrimSpace(reason)
		}
	}
	return ""
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
