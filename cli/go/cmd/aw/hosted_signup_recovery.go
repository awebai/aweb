package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

const (
	hostedSignupRecoveryFile  = "signup-recovery.json"
	hostedSignupRecoveryLimit = 2 * awid.MaxResponseSize
)

type hostedSignupContext struct {
	WorkingDir    string `json:"working_dir"`
	DiscoveryURL  string `json:"discovery_url"`
	OnboardingURL string `json:"onboarding_url"`
	AwebURL       string `json:"aweb_url"`
	RegistryURL   string `json:"registry_url"`
}

const hostedSignupPrepared awconfig.RecoveryState = "prepared"

var errHostedSignupUsernameTaken = errors.New("hosted signup username taken")

type hostedSignupRecovery struct {
	awconfig.RecoveryProgress
	Context     hostedSignupContext `json:"context"`
	SigningSeed string              `json:"signing_seed"`
	// A byte slice retains the original serialized request, including whitespace,
	// rather than letting an outer journal encoding reformat a RawMessage.
	RequestJSON  []byte          `json:"request_json"`
	ResponseJSON json.RawMessage `json:"response_json,omitempty"`
}

type hostedSignupCreation struct {
	Context     hostedSignupContext
	Username    string
	Alias       string
	InboundMode string
	Scope       awid.IdentityScope
}

func signupRecoveryFile(workingDir string) awconfig.RecoveryFile {
	return awconfig.RecoveryFile{Home: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(workingDir)}, Name: hostedSignupRecoveryFile}
}

func loadHostedSignupRecovery(workingDir string) (*hostedSignupRecovery, error) {
	if !filepath.IsAbs(workingDir) {
		return nil, errors.New("signup recovery requires an explicit absolute working directory")
	}
	raw, err := signupRecoveryFile(workingDir).ReadBounded(hostedSignupRecoveryLimit)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state hostedSignupRecovery
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, errors.New("signup recovery is malformed; retain signup-recovery.json for reconciliation")
	}
	if err := state.validateProgress(); err != nil {
		return nil, err
	}
	if state.Context.WorkingDir != workingDir || state.Context.OnboardingURL == "" || state.Context.AwebURL == "" {
		return nil, errors.New("signup recovery selection changed; retain signup-recovery.json for reconciliation")
	}
	if _, _, err := state.identity(); err != nil {
		return nil, err
	}
	if (state.State == awconfig.RecoveryConfirmed) != (len(state.ResponseJSON) > 0) {
		return nil, errors.New("signup recovery result is inconsistent; retain signup-recovery.json for reconciliation")
	}
	return &state, nil
}

func (state *hostedSignupRecovery) validateProgress() error {
	if state.Version == 1 && state.State == hostedSignupPrepared {
		return nil
	}
	return state.RecoveryProgress.Validate()
}

func (state *hostedSignupRecovery) save() error {
	raw, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return signupRecoveryFile(state.Context.WorkingDir).Write(append(raw, '\n'))
}

func (state *hostedSignupRecovery) identity() (awid.CliSignupRequest, ed25519.PrivateKey, error) {
	var request awid.CliSignupRequest
	if err := json.Unmarshal(state.RequestJSON, &request); err != nil {
		return request, nil, errors.New("signup recovery request is malformed")
	}
	seed, err := hex.DecodeString(state.SigningSeed)
	if err != nil || len(seed) != ed25519.SeedSize {
		return request, nil, errors.New("signup recovery signer is malformed")
	}
	// The journal retains seed bytes; the shared signing-key codec owns their
	// reconstruction, as it does for the installed private-key file.
	key, err := awid.ParseSigningKey(pem.EncodeToMemory(&pem.Block{Type: "ED25519 PRIVATE KEY", Bytes: seed}))
	if err != nil {
		return request, nil, errors.New("signup recovery signer is malformed")
	}
	public := ed25519.PublicKey(key[ed25519.SeedSize:])
	if request.DIDKey != awid.ComputeDIDKey(public) || (request.DIDAW != "" && request.DIDAW != awid.ComputeStableID(public)) || request.Username == "" || request.Alias == "" {
		return request, nil, errors.New("signup recovery request does not match its signer")
	}
	return request, key, nil
}

// prepareHostedSignup retains the signer and exact request before either the
// registry claim or signup effect (docs/identity.md#cli-signup-recovery).
// It shares the versioned progress and private
// atomic writer with init/id-create recovery; only the operation payload differs.
func prepareHostedSignup(input hostedSignupCreation) (*hostedSignupRecovery, error) {
	state, err := loadHostedSignupRecovery(input.Context.WorkingDir)
	if err != nil {
		return nil, err
	}
	if state != nil {
		request, _, err := state.identity()
		if err != nil {
			return nil, err
		}
		scope := awid.IdentityScopeLocal
		if request.DIDAW != "" {
			scope = awid.IdentityScopeGlobal
		}
		if state.Context != input.Context || request.Username != input.Username || request.Alias != input.Alias || request.InboundMode != input.InboundMode || scope != input.Scope {
			return nil, errors.New("signup retry changed the original selection; resume the original request in this home")
		}
		return state, nil
	}
	if input.Scope != awid.IdentityScopeLocal && input.Scope != awid.IdentityScopeGlobal {
		return nil, errors.New("signup identity scope is required")
	}
	if err := ensureConnectTargetClean(input.Context.WorkingDir); err != nil {
		return nil, err
	}
	public, key, err := awid.GenerateKeypair()
	if err != nil {
		return nil, err
	}
	request := awid.CliSignupRequest{Username: input.Username, Alias: input.Alias, DIDKey: awid.ComputeDIDKey(public), InboundMode: input.InboundMode}
	if input.Scope == awid.IdentityScopeGlobal {
		request.DIDAW = awid.ComputeStableID(public)
	}
	body, err := json.Marshal(request)
	if err != nil {
		return nil, err
	}
	state = &hostedSignupRecovery{RecoveryProgress: awconfig.RecoveryProgress{Version: 1, State: hostedSignupPrepared}, Context: input.Context, SigningSeed: hex.EncodeToString(key.Seed()), RequestJSON: body}
	if err := state.save(); err != nil {
		return nil, err
	}
	return state, nil
}

func (state *hostedSignupRecovery) provision() (hostedIdentityProvision, error) {
	request, key, err := state.identity()
	if err != nil {
		return hostedIdentityProvision{}, err
	}
	existing, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(state.Context.WorkingDir))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return hostedIdentityProvision{}, err
	}
	if err == nil && !existing.Equal(key) {
		return hostedIdentityProvision{}, errors.New("signup retry signing key changed; restore the original home")
	}
	if state.State != awconfig.RecoveryConfirmed {
		firstLocalSubmission := state.State == hostedSignupPrepared && request.DIDAW == ""
		state.State = awconfig.RecoveryAttempted
		if err := state.save(); err != nil {
			return hostedIdentityProvision{}, err
		}
		ctx, cancel := commandAPIContext(nil)
		defer cancel()
		if request.DIDAW != "" {
			registry, err := newConfiguredRegistryClient(nil)
			if err != nil {
				return hostedIdentityProvision{}, err
			}
			if err := registry.SetFallbackRegistryURL(state.Context.RegistryURL); err != nil {
				return hostedIdentityProvision{}, err
			}
			if err := registerHostedDID(ctx, registry, request.DIDKey, request.DIDAW, key); err != nil {
				return hostedIdentityProvision{}, err
			}
		}
		response, err := awid.SubmitCliSignup(ctx, awid.CliSignupSubmission{OnboardingURL: state.Context.OnboardingURL, RequestJSON: state.RequestJSON, SigningKey: key})
		if err != nil {
			// This endpoint's 409 rejects the username. On a replay an
			// earlier request may have committed, so keep its original signer.
			var refusal *awid.RegistryError
			if firstLocalSubmission && errors.As(err, &refusal) && refusal.StatusCode == http.StatusConflict {
				return hostedIdentityProvision{}, errHostedSignupUsernameTaken
			}
			return hostedIdentityProvision{}, fmt.Errorf("signup attempt retained in %s; rerun aw init in this directory to resume the same request: %w", hostedSignupRecoveryFile, err)
		}
		raw, err := json.Marshal(response)
		if err != nil {
			return hostedIdentityProvision{}, err
		}
		state.ResponseJSON = raw
		state.State = awconfig.RecoveryConfirmed
		// Retain the credential before validation, installation, connect or output.
		if err := state.save(); err != nil {
			return hostedIdentityProvision{}, err
		}
	}
	var response awid.CliSignupResponse
	if err := json.Unmarshal(state.ResponseJSON, &response); err != nil {
		return hostedIdentityProvision{}, errors.New("retained signup response is malformed")
	}
	cert, err := validateHostedSignupResponse(&response, request.DIDKey, request.DIDAW, request.Alias)
	if err != nil {
		return hostedIdentityProvision{}, err
	}
	if strings.TrimSpace(response.APIKey) == "" {
		return hostedIdentityProvision{}, errors.New("hosted signup response missing api_key")
	}
	return hostedIdentityProvision{SigningKey: key, Certificate: cert, DIDKey: request.DIDKey, DIDAW: request.DIDAW, MemberAddress: strings.TrimSpace(cert.MemberAddress), RegistryURL: state.Context.RegistryURL, APIKey: strings.TrimSpace(response.APIKey)}, nil
}

type hostedSignupCompletion struct {
	Wizard   guidedOnboardingRequest
	Creation hostedSignupCreation
}

func completeRecoverableHostedSignup(input hostedSignupCompletion) (result *guidedOnboardingResult, resultErr error) {
	req := input.Wizard
	if !filepath.IsAbs(req.WorkingDir) || input.Creation.Context.WorkingDir != req.WorkingDir {
		return nil, errors.New("signup recovery requires the original absolute working directory")
	}
	// Keep the per-checkout lock outside .aw so a refused first signup can
	// remove its empty home without unlinking a lock used by another process.
	checkout, err := filepath.EvalSymlinks(req.WorkingDir)
	if err != nil {
		return nil, err
	}
	lockPath, err := awconfig.PathInUserState("signup-locks", fmt.Sprintf("%x.lock", sha256.Sum256([]byte(checkout))))
	if err != nil {
		return nil, err
	}
	lock, err := awconfig.LockExclusive(lockPath)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()

	home := awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(req.WorkingDir)}
	info, err := os.Lstat(home.Root)
	freshHome := errors.Is(err, os.ErrNotExist)
	if err == nil {
		if !info.IsDir() || info.Mode().Perm() != 0700 {
			return nil, errors.New("signup recovery requires a private identity directory with mode 0700")
		}
	} else if !freshHome {
		return nil, err
	}

	var provisioned hostedIdentityProvision
	for {
		state, err := prepareHostedSignup(input.Creation)
		if err != nil {
			return nil, err
		}
		provisioned, err = state.provision()
		if err == nil {
			break
		}
		if !errors.Is(err, errHostedSignupUsernameTaken) {
			return nil, err
		}
		if err := signupRecoveryFile(req.WorkingDir).Remove(); err != nil {
			return nil, fmt.Errorf("remove refused signup recovery: %w", err)
		}
		if freshHome {
			if err := os.Remove(home.Root); err != nil && !errors.Is(err, os.ErrNotExist) {
				return nil, fmt.Errorf("remove empty signup home: %w", err)
			}
		}
		username := input.Creation.Username
		if req.NonInteractive {
			return nil, usageError("username %q is not available (taken)", username)
		}
		fmt.Fprintf(req.PromptOut, "Username %q was taken during signup. Choose another.\n", username)
		input.Creation.Username, err = promptAvailableHostedUsername(req.PromptIn, req.PromptOut, input.Creation.Context.OnboardingURL)
		if err != nil {
			return nil, err
		}
	}
	scope := localHostedIdentity
	if input.Creation.Scope == awid.IdentityScopeGlobal {
		scope = globalHostedIdentity
	}
	if err := persistHostedIdentityState(hostedStatePersistence{WorkingDir: req.WorkingDir, IdentityHome: home, RegistryURL: provisioned.RegistryURL, SigningKey: provisioned.SigningKey, Certificate: provisioned.Certificate, DIDKey: provisioned.DIDKey, DIDAW: provisioned.DIDAW, MemberAddress: provisioned.MemberAddress, Scope: scope}); err != nil {
		return nil, err
	}
	connected, err := guidedOnboardingConnect(req.WorkingDir, input.Creation.Context.AwebURL, certificateConnectOptions{ContextFile: req.ContextFile, Role: req.Role, HumanName: req.HumanName, AgentType: req.AgentType, APIKey: provisioned.APIKey})
	if err != nil {
		return nil, err
	}
	if req.Global && strings.TrimSpace(req.InboundMode) != "" {
		if err := requireCreatedIdentityInboundMode(nil, req.WorkingDir, "", input.Creation.Context.AwebURL, provisioned.Certificate.Team, req.InboundMode); err != nil {
			return nil, err
		}
	}
	// The signer, membership and credential are installed. Losing terminal output
	// now cannot lose the credential; a subsequent init reconnects normally.
	if err := signupRecoveryFile(req.WorkingDir).Remove(); err != nil {
		return nil, err
	}
	if err := printInitOutcome(connected, &initResult{ServerName: hostFromBaseURL(connected.AwebURL), ExportBaseURL: connected.AwebURL, Alias: strings.TrimSpace(connected.Alias), Path: initPathNewTeam}, req.WorkingDir, guidedSetup(req)); err != nil {
		return nil, err
	}
	if req.AskPostCreateSetup && !req.NonInteractive {
		if err := promptHostedClaimHuman(req, input.Creation.Context.OnboardingURL); err != nil {
			return nil, err
		}
	}
	return &guidedOnboardingResult{}, nil
}

func resumeHostedSignup(req guidedOnboardingRequest, state *hostedSignupRecovery) (*guidedOnboardingResult, error) {
	saved, _, err := state.identity()
	if err != nil {
		return nil, err
	}
	requestedAlias := firstNonEmptyString(req.Name, req.Alias)
	if (req.Username != "" && req.Username != saved.Username) || (requestedAlias != "" && requestedAlias != saved.Alias) || (req.InboundMode != "" && req.InboundMode != saved.InboundMode) || (req.BaseURL != "" && strings.TrimRight(req.BaseURL, "/") != strings.TrimRight(state.Context.DiscoveryURL, "/")) || (req.Global && saved.DIDAW == "") || req.BYOD {
		return nil, errors.New("signup retry changed the original selection; resume the original request in this home")
	}
	req.Username, req.Alias, req.Name, req.BaseURL, req.InboundMode = saved.Username, saved.Alias, "", state.Context.DiscoveryURL, saved.InboundMode
	req.Global = saved.DIDAW != ""
	scope := awid.IdentityScopeLocal
	if req.Global {
		scope = awid.IdentityScopeGlobal
	}
	return completeRecoverableHostedSignup(hostedSignupCompletion{Wizard: req, Creation: hostedSignupCreation{Context: state.Context, Username: saved.Username, Alias: saved.Alias, InboundMode: saved.InboundMode, Scope: scope}})
}
