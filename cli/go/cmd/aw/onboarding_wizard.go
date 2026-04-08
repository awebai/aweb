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
const guidedOnboardingManagedDomainSuffix = ".aweb.ai"

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
	serviceURLs, err := resolveReconnectServiceURLs(req)
	if err != nil {
		return nil, err
	}

	result, err := guidedOnboardingConnect(req.WorkingDir, serviceURLs.AwebURL, certificateConnectOptions{
		Role:     req.Role,
		CloudURL: serviceURLs.CloudURL,
		AwidURL:  serviceURLs.AwidURL,
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

	serviceURLs, err := discoverOnboardingServiceURLs(req.ServerURL)
	if err != nil {
		fmt.Fprintln(req.PromptOut, "Managed onboarding is not available here. Switching to BYOD.")
		return executeBYODPath(req)
	}

	username, err := promptAvailableHostedUsername(req.PromptIn, req.PromptOut, serviceURLs.CloudURL)
	if err != nil {
		return nil, err
	}
	alias, err := resolveGuidedHostedAlias(req)
	if err != nil {
		return nil, err
	}

	for {
		signingKey, cert, didKey, didAW, memberAddress, registryURL, err := provisionHostedIdentity(serviceURLs.CloudURL, serviceURLs.AwidURL, username, alias)
		if err != nil {
			if hostedUsernameTakenOnSignup(err) {
				fmt.Fprintf(req.PromptOut, "Username %q was taken during signup. Choose another.\n", username)
				username, err = promptAvailableHostedUsername(req.PromptIn, req.PromptOut, serviceURLs.CloudURL)
				if err != nil {
					return nil, err
				}
				continue
			}
			return nil, err
		}
		if err := persistGuidedHostedIdentity(req.WorkingDir, registryURL, signingKey, cert, didKey, didAW, memberAddress); err != nil {
			return nil, err
		}
		break
	}

	result, err := guidedOnboardingConnect(req.WorkingDir, serviceURLs.AwebURL, certificateConnectOptions{
		Role:      req.Role,
		HumanName: req.HumanName,
		AgentType: req.AgentType,
		CloudURL:  serviceURLs.CloudURL,
		AwidURL:   serviceURLs.AwidURL,
	})
	if err != nil {
		return nil, err
	}
	printOutput(result, formatConnect)

	if err := promptHostedClaimHuman(req, serviceURLs.CloudURL); err != nil {
		return nil, err
	}
	if err := runGuidedPostInitSetup(req); err != nil {
		return nil, err
	}
	return &guidedOnboardingResult{}, nil
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

	serverURL, err := resolveGuidedOnboardingServerURL(req.ServerURL)
	if err != nil {
		return nil, err
	}
	result, err := guidedOnboardingConnect(req.WorkingDir, serverURL, certificateConnectOptions{
		Role:      req.Role,
		HumanName: req.HumanName,
		AgentType: req.AgentType,
		AwidURL:   provisioned.Identity.Plan.RegistryURL,
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

func resolveGuidedOnboardingServerURL(raw string) (string, error) {
	serverURL := strings.TrimSpace(raw)
	if serverURL == "" {
		serverURL = defaultWizardServerURL()
	}
	return cloudRootBaseURL(serverURL)
}

func guidedOnboardingSkipDNSVerify() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("AWID_SKIP_DNS_VERIFY"))) {
	case "1", "true", "yes", "on":
		return true
	default:
		return false
	}
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
		Name:          name,
		Domain:        domain,
		PromptIn:      req.PromptIn,
		PromptOut:     req.PromptOut,
		SkipDNSVerify: guidedOnboardingSkipDNSVerify(),
		Now:           time.Now,
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

func ensureHostedOnboardingAvailable(serverURL string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	resp, err := guidedOnboardingCheckUsername(ctx, serverURL, "Invalid_Probe")
	if err == nil && resp != nil {
		return nil
	}

	var regErr *awid.RegistryError
	if errors.As(err, &regErr) {
		if regErr.StatusCode == http.StatusNotFound {
			return usageError("hosted onboarding is not available on this server; rerun `aw init` and choose BYOD with a domain you control")
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
	return promptRequiredStringWithIO("Agent alias", defaultGuidedHostedAlias(), req.PromptIn, req.PromptOut)
}

func defaultGuidedHostedAlias() string {
	if v := strings.TrimSpace(os.Getenv("USER")); v != "" {
		if sanitized := strings.TrimSpace(sanitizeKeyComponent(v)); sanitized != "" {
			return sanitized
		}
	}
	return "laptop"
}

func promptAvailableHostedUsername(in io.Reader, out io.Writer, cloudURL string) (string, error) {
	for {
		username, err := promptRequiredStringWithIO("Username", "", in, out)
		if err != nil {
			return "", err
		}

		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		resp, err := guidedOnboardingCheckUsername(ctx, cloudURL, username)
		cancel()
		if err != nil {
			var regErr *awid.RegistryError
			if errors.As(err, &regErr) && regErr.StatusCode == http.StatusNotFound {
				return "", usageError("hosted onboarding is not available on this server; rerun `aw init` and choose BYOD with a domain you control")
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

func provisionHostedIdentity(
	cloudURL, registryURL, username, alias string,
) (ed25519.PrivateKey, *awid.TeamCertificate, string, string, string, string, error) {
	registry, err := newConfiguredRegistryClient(nil, "")
	if err != nil {
		return nil, nil, "", "", "", "", err
	}
	if strings.TrimSpace(registryURL) != "" {
		if err := registry.SetFallbackRegistryURL(registryURL); err != nil {
			return nil, nil, "", "", "", "", err
		}
	}

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return nil, nil, "", "", "", "", err
	}
	didKey := awid.ComputeDIDKey(pub)
	didAW := awid.ComputeStableID(pub)
	memberAddress := username + guidedOnboardingManagedDomainSuffix + "/" + alias

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := registerHostedDID(ctx, registry, didKey, didAW, memberAddress, alias, signingKey); err != nil {
		return nil, nil, "", "", "", "", err
	}

	resp, err := guidedOnboardingCliSignup(ctx, cloudURL, &awid.CliSignupRequest{
		Username: username,
		DIDKey:   didKey,
		DIDAW:    didAW,
		Alias:    alias,
	}, signingKey)
	if err != nil {
		return nil, nil, "", "", "", "", err
	}

	cert, err := validateHostedSignupResponse(resp, didKey, didAW, memberAddress, alias)
	if err != nil {
		return nil, nil, "", "", "", "", err
	}

	return signingKey, cert, didKey, didAW, memberAddress, strings.TrimSpace(registry.DefaultRegistryURL), nil
}

func registerHostedDID(
	ctx context.Context,
	registry *awid.RegistryClient,
	didKey, didAW, memberAddress, alias string,
	signingKey ed25519.PrivateKey,
) error {
	if registry == nil {
		return fmt.Errorf("nil registry client")
	}
	_, err := registry.RegisterDID(ctx, registry.DefaultRegistryURL, "", memberAddress, alias, didKey, didAW, signingKey)
	if already := new(awid.AlreadyRegisteredError); errors.As(err, &already) {
		if strings.TrimSpace(already.ExistingDIDKey) == strings.TrimSpace(didKey) {
			return nil
		}
	}
	return err
}

func validateHostedSignupResponse(
	resp *awid.CliSignupResponse,
	didKey, didAW, memberAddress, alias string,
) (*awid.TeamCertificate, error) {
	if resp == nil {
		return nil, fmt.Errorf("missing hosted signup response")
	}
	if strings.TrimSpace(resp.DIDAW) != strings.TrimSpace(didAW) {
		return nil, fmt.Errorf("hosted signup returned did_aw %q, expected %q", resp.DIDAW, didAW)
	}
	if strings.TrimSpace(resp.MemberAddress) != strings.TrimSpace(memberAddress) {
		return nil, fmt.Errorf("hosted signup returned member_address %q, expected %q", resp.MemberAddress, memberAddress)
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
	if cert.MemberAddress != memberAddress {
		return nil, fmt.Errorf("hosted signup certificate member_address %q does not match %q", cert.MemberAddress, memberAddress)
	}
	if cert.Alias != alias {
		return nil, fmt.Errorf("hosted signup certificate alias %q does not match %q", cert.Alias, alias)
	}
	if teamAddress := strings.TrimSpace(resp.TeamAddress); teamAddress != "" && cert.Team != teamAddress {
		return nil, fmt.Errorf("hosted signup certificate team %q does not match response team_address %q", cert.Team, resp.TeamAddress)
	}
	return cert, nil
}

func persistGuidedHostedIdentity(
	workingDir, registryURL string,
	signingKey ed25519.PrivateKey,
	cert *awid.TeamCertificate,
	didKey, didAW, memberAddress string,
) error {
	signingKeyPath := awconfig.WorktreeSigningKeyPath(workingDir)
	if err := awid.SaveSigningKey(signingKeyPath, signingKey); err != nil {
		return err
	}
	certPath := filepath.Join(workingDir, ".aw", "team-cert.pem")
	if err := awid.SaveTeamCertificate(certPath, cert); err != nil {
		return err
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

func promptHostedClaimHuman(req guidedOnboardingRequest, serverURL string) error {
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
		BaseURL:    serverURL,
		Email:      email,
	})
	if err != nil {
		return err
	}
	return printClaimHumanSuccess(req.PromptOut, email, resp)
}

func resolveReconnectServiceURLs(req guidedOnboardingRequest) (onboardingServiceURLs, error) {
	if strings.TrimSpace(req.ServerURL) != "" {
		return resolveOnboardingServiceURLs(req.ServerURL)
	}

	workspace, _, err := awconfig.LoadWorktreeWorkspaceFromDir(req.WorkingDir)
	if err == nil {
		if strings.TrimSpace(workspace.CloudURL) != "" {
			urls, normalizeErr := normalizeOnboardingServiceURLs(onboardingServiceURLs{
				CloudURL: workspace.CloudURL,
				AwebURL:  workspace.AwebURL,
				AwidURL:  workspace.AwidURL,
			})
			if normalizeErr != nil {
				return onboardingServiceURLs{}, normalizeErr
			}
			if strings.TrimSpace(urls.AwebURL) != "" {
				return urls, nil
			}
		}

		rawURL := strings.TrimSpace(workspace.AwebURL)
		if rawURL != "" {
			return resolveOnboardingServiceURLs(rawURL)
		}
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return onboardingServiceURLs{}, err
	}

	awebURL, err := resolveGuidedOnboardingServerURL(req.ServerURL)
	if err != nil {
		return onboardingServiceURLs{}, err
	}
	return onboardingServiceURLs{
		CloudURL: awebURL,
		AwebURL:  awebURL,
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
