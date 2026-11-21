package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
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
	"github.com/awebai/aw/internal/pathpreflight"
)

const initAPIKeyEnvVar = "AWEB_API_KEY"
const maxWorkspaceAPIKeyLength = 4096
const apiKeyPartialInitVersion = 1

type apiKeyInitRequest struct {
	EncryptionPublication encryptionPublicationPolicy
	ContextFile           workspaceContextPolicy
	SelectedTeam          *apiKeyCreationTeam
	CreationInvitation    *awid.IDCreationInvitation
	WorkingDir            string
	IdentityHome          string
	AwebURL               string
	RegistryURL           string
	APIKey                string
	Name                  string
	Alias                 string
	Role                  string
	HumanName             string
	AgentType             string
	Global                bool
	SelectedTeamID        string
	CanonicalTeamID       string
	// InboundMode is "open", "team_and_contacts" or "contacts_only" when --inbound-mode is
	// set on a global init, "" otherwise. The runner forwards it to
	// /api/v1/workspaces/init only when non-empty; the server defaults
	// to "open" when the field is absent.
	InboundMode string
}

type apiKeyBootstrapRequest struct {
	IDTree        *awid.IDTreeCreationRequest `json:"id_tree,omitempty"`
	DID           string                      `json:"did"`
	PublicKey     string                      `json:"public_key"`
	Name          string                      `json:"name,omitempty"`
	Alias         string                      `json:"alias,omitempty"`
	Custody       string                      `json:"custody"`
	RoleName      string                      `json:"role_name,omitempty"`
	HumanName     string                      `json:"human_name,omitempty"`
	AgentType     string                      `json:"agent_type,omitempty"`
	IdentityScope string                      `json:"identity_scope"`
	InboundMode   string                      `json:"inbound_mode,omitempty"`
}

type apiKeyBootstrapResponse struct {
	awid.IDTreeCreationResponse
	ServerURL     string `json:"server_url"`
	TeamCert      string `json:"team_cert"`
	Alias         string `json:"alias"`
	TeamID        string `json:"team_id"`
	WorkspaceID   string `json:"workspace_id"`
	DID           string `json:"did"`
	StableID      string `json:"stable_id"`
	IdentityScope string `json:"identity_scope"`
	Custody       string `json:"custody"`
	APIKey        string `json:"api_key"`
}

type apiKeyPartialInitState struct {
	ResponseJSON    string                `yaml:"response_json,omitempty"`
	IDTree          *hostedIDTreeRecovery `yaml:"id_tree,omitempty"`
	IdentityScope   string                `yaml:"identity_scope,omitempty"`
	Alias           string                `yaml:"alias,omitempty"`
	InboundMode     string                `yaml:"inbound_mode,omitempty"`
	CanonicalTeamID string                `yaml:"canonical_team_id,omitempty"`
	Version         int                   `yaml:"version"`
	DIDKey          string                `yaml:"did_key"`
	StableID        string                `yaml:"stable_id"`
	SigningKeyB64   string                `yaml:"signing_key_b64"`
	Name            string                `yaml:"name"`
	AwebURL         string                `yaml:"aweb_url"`
	RegistryURL     string                `yaml:"registry_url"`
	TeamIDHint      string                `yaml:"team_id_hint,omitempty"`
	RoleName        string                `yaml:"role_name,omitempty"`
	HumanName       string                `yaml:"human_name,omitempty"`
	AgentType       string                `yaml:"agent_type,omitempty"`
	// Reachability is a legacy partial-init field. It is accepted on read for
	// one-release compatibility but ignored and never sent to cloud.
	Reachability      string `yaml:"reachability,omitempty"`
	APIKeyFingerprint string `yaml:"api_key_fingerprint"`
	CreatedAt         string `yaml:"created_at"`
}

type apiKeyBootstrapIdentityMaterial struct {
	PublicKey  ed25519.PublicKey
	SigningKey ed25519.PrivateKey
	DIDKey     string
	StableID   string
}

type apiKeyInitAuthorityPreflight struct {
	WorkingDir string
	APIKey     string
}

func (state *apiKeyPartialInitState) matchesAPIKey(apiKey string) bool {
	return state.APIKeyFingerprint == apiKeyFingerprint(apiKey)
}

// loadAPIKeyInitRecoveryForKey refuses a changed key before team selection can
// contact the service (docs/hosted-global-bootstrap.md:180-190). The full
// recovery context is checked again under the bootstrap lock before effects.
func loadAPIKeyInitRecoveryForKey(in apiKeyInitAuthorityPreflight) (*apiKeyPartialInitState, error) {
	path := apiKeyPartialInitPath(awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(in.WorkingDir)})
	state, err := loadAPIKeyPartialInit(path)
	if err != nil || state == nil {
		return state, err
	}
	if !state.matchesAPIKey(in.APIKey) {
		return nil, usageError("partial API-key init state at %s was created for a different bootstrap context (api_key_fingerprint differs); retry the original command or remove the file explicitly", path)
	}
	return state, nil
}

func resolveInitAPIKey() string {
	return strings.TrimSpace(os.Getenv(initAPIKeyEnvVar))
}

func resolveAPIKeyInitAwebURL() (string, error) {
	return normalizeAPIKeyBootstrapBaseURL(awebURLOrDefault(resolveInitAwebURLOverride()))
}

func runAPIKeyBootstrapInit(req apiKeyInitRequest) (out connectOutput, resultErr error) {
	if err := req.ContextFile.validate(); err != nil {
		return out, err
	}
	if err := req.EncryptionPublication.validate(); err != nil {
		return out, err
	}
	if strings.TrimSpace(req.WorkingDir) == "" {
		return connectOutput{}, fmt.Errorf("working directory is required")
	}
	if strings.TrimSpace(req.APIKey) == "" {
		return connectOutput{}, usageError("AWEB_API_KEY is required for API key bootstrap")
	}
	if strings.TrimSpace(req.IdentityHome) == "" {
		req.IdentityHome = filepath.Join(filepath.Clean(req.WorkingDir), ".aw")
	}
	req.AwebURL = awebURLOrDefault(req.AwebURL)
	if err := ensureConnectTargetClean(req.WorkingDir); err != nil {
		return connectOutput{}, err
	}

	lockPath := apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome}) + ".lock"
	if err := pathpreflight.PreflightFile(lockPath, "API-key creation recovery lock", pathpreflight.Options{}); err != nil {
		return connectOutput{}, err
	}
	lock, err := awconfig.TryLockExclusive(lockPath)
	if err != nil {
		return connectOutput{}, fmt.Errorf("API-key creation already in progress or recovery lock unavailable: %w", err)
	}
	defer func() { resultErr = errors.Join(resultErr, lock.Close()) }()

	// Cloud contract: global uses name (not alias), local uses alias (not name).
	name := strings.TrimSpace(req.Name)
	alias := strings.TrimSpace(req.Alias)
	if req.Global {
		if name == "" {
			return connectOutput{}, usageError("--name is required for global API-key bootstrap")
		}
		alias = "" // cloud rejects alias for global identity bootstrap
	}

	selectedRegistryURL, err := resolveRegistryURLSetting(registryURLSettingInput{ExplicitURL: req.RegistryURL})
	if err != nil {
		return connectOutput{}, err
	}
	registry, err := newRegistryClientWithPreferredBaseURL(selectedRegistryURL)
	if err != nil {
		return connectOutput{}, err
	}
	if selectedRegistryURL != "" {
		selectedRegistryURL = registry.DefaultRegistryURL
	}
	if previous, loadErr := loadAPIKeyPartialInit(apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome})); loadErr != nil {
		return connectOutput{}, loadErr
	} else if previous != nil {
		original := req
		original.SelectedTeamID, original.CanonicalTeamID = previous.TeamIDHint, previous.CanonicalTeamID
		if err := validateAPIKeyPartialInitContext(apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome}), previous, original, name, registry.DefaultRegistryURL); err != nil {
			return connectOutput{}, err
		}
	}
	req, err = selectAPIKeyInitTeam(req)
	if err != nil {
		return connectOutput{}, err
	}

	material, err := prepareAPIKeyBootstrapIdentity(req, name, registry)
	if err != nil {
		return connectOutput{}, err
	}
	// Only failures with the original resumable material receive retry guidance.
	// A rejected server identity must be reconciled, never selected automatically.
	recoveryState := apiKeyInitRecoverable
	defer func() {
		resultErr = finalizeAPIKeyInitFailure(apiKeyInitFailure{Cause: resultErr, Home: awconfig.IdentityHome{Root: req.IdentityHome}, State: recoveryState})
	}()
	state, err := loadAPIKeyPartialInit(apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome}))
	if err != nil {
		return connectOutput{}, err
	}
	pub := material.PublicKey
	signingKey := material.SigningKey
	didKey := material.DIDKey
	localStableID := material.StableID

	if req.Global {
		ctx, cancel := commandAPIContext(nil)
		defer cancel()
		if _, regErr := registry.RegisterIdentity(
			ctx,
			registry.DefaultRegistryURL,
			didKey,
			localStableID,
			signingKey,
		); regErr != nil {
			var already *awid.AlreadyRegisteredError
			if !errors.As(regErr, &already) || strings.TrimSpace(already.ExistingDIDKey) != didKey {
				return connectOutput{}, fmt.Errorf("failed to register did:aw at awid before workspace init: %w", regErr)
			}
		}
	}

	resp := &apiKeyBootstrapResponse{}
	err = readHostedCreationResponse(state.ResponseJSON, resp, func() error {
		created, createErr := postAPIKeyWorkspaceInit(context.Background(), strings.TrimSpace(req.AwebURL), strings.TrimSpace(req.APIKey), apiKeyBootstrapRequest{
			IDTree:        state.IDTree.request(nil),
			DID:           didKey,
			PublicKey:     base64.StdEncoding.EncodeToString(pub),
			Name:          name,
			Alias:         alias,
			Custody:       awid.CustodySelf,
			RoleName:      strings.TrimSpace(req.Role),
			HumanName:     strings.TrimSpace(req.HumanName),
			AgentType:     strings.TrimSpace(req.AgentType),
			IdentityScope: string(identityScopeFromFlags(identityScopeFlags{Global: req.Global})),
			InboundMode:   strings.TrimSpace(req.InboundMode),
		}, signingKey)
		if createErr == nil {
			*resp = *created
		}
		return createErr
	})
	if err != nil {
		return connectOutput{}, err
	}

	if req.Global {
		if responseDID := strings.TrimSpace(resp.DID); responseDID != "" && responseDID != didKey {
			recoveryState = apiKeyInitReconciliationOnly
			rejected, quarantineErr := quarantineAPIKeyPartialInit(awconfig.IdentityHome{Root: req.IdentityHome})
			if quarantineErr != nil {
				return connectOutput{}, fmt.Errorf("global name %q is already registered with a different identity; could not quarantine partial signing material (original retained at %s): %w; operator reconciliation is required", name, apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome}), quarantineErr)
			}
			return connectOutput{}, fmt.Errorf(
				"global name %q is already registered with a different identity: the server returned did %s but this machine generated %s.\nThe signing key material was preserved at %s. Use a different directory for a new identity, or ask an operator to reconcile the existing identity binding; rejected material is never restored automatically.",
				name, responseDID, didKey, rejected,
			)
		}
	}

	encodedCert := strings.TrimSpace(resp.TeamCert)
	if encodedCert == "" {
		return connectOutput{}, fmt.Errorf("workspace init response is missing team_cert")
	}
	cert, err := awid.DecodeTeamCertificateHeader(encodedCert)
	if err != nil {
		return connectOutput{}, fmt.Errorf("decode workspace init team cert: %w", err)
	}
	global, serverURL, stableID, err := validateAPIKeyBootstrapResponse(resp, cert, didKey, req.Global)
	if err != nil {
		return connectOutput{}, err
	}
	if global && stableID != localStableID {
		return connectOutput{}, fmt.Errorf("workspace init response stable_id %q does not match locally computed %q", stableID, localStableID)
	}
	if strings.TrimSpace(resp.APIKey) == "" {
		return connectOutput{}, fmt.Errorf("workspace init response is missing api_key")
	}

	if cert.Team != req.CanonicalTeamID {
		return connectOutput{}, errors.New("workspace creation returned a different team than the API key selected")
	}
	admissionContext, admissionCancel := commandAPIContext(nil)
	defer admissionCancel()
	keyObservation, err := registry.CheckTeamCertificateCurrentKey(admissionContext, awid.CurrentTeamCertificateCheck{RegistryURL: selectedRegistryURL, Certificate: cert})
	if err != nil {
		return connectOutput{}, fmt.Errorf("workspace certificate is not current: %w; ask the team controller for a current certificate", err)
	}
	if err := state.IDTree.retainResponse(resp.IDTreeCreationResponse); err != nil {
		return connectOutput{}, err
	}
	if state.ResponseJSON == "" {
		state.ResponseJSON, err = canonicalHostedCreationResponse(resp, resp.IDTreeCreationResponse)
		if err != nil {
			return connectOutput{}, err
		}
	}
	if err := saveAPIKeyPartialInit(awconfig.IdentityHome{Root: req.IdentityHome}, state); err != nil {
		return connectOutput{}, err
	}
	treeContext, treeCancel := commandAPIContext(nil)
	responsibility, treeErr := finishHostedIDTree(treeContext, state.IDTree, resp.IDTreeCreationResponse, workspaceTeamIdentityMaterial{SigningKey: signingKey, DIDKey: didKey, StableID: localStableID, IdentityScope: string(identityScopeFromFlags(identityScopeFlags{Global: req.Global}))}, req.IdentityHome, registry, nil)
	treeCancel()
	if treeErr != nil {
		return connectOutput{}, fmt.Errorf("hosted membership created; attribution installation incomplete: %w", treeErr)
	}
	snapshot, err := snapshotAwTree(awconfig.IdentityHome{Root: req.IdentityHome})
	if err != nil {
		return connectOutput{}, err
	}
	if err := persistAPIKeyBootstrapState(req.WorkingDir, req.IdentityHome, selectedRegistryURL, signingKey, didKey, stableID, cert, global); err != nil {
		return connectOutput{}, errors.Join(err, rollbackAwTree(awconfig.IdentityHome{Root: req.IdentityHome}, snapshot))
	}

	out, err = connectAPIKeyInitializedMember(apiKeyMemberConnection{
		Request: req, ServerURL: serverURL, WorkspaceAPIKey: resp.APIKey, Snapshot: snapshot,
		TeamKeyObservation: keyObservation, TeamRegistryURL: selectedRegistryURL,
	})
	if err != nil {
		var connected *connectedMemberSetupError
		if errors.As(err, &connected) {
			recoveryState = apiKeyInitReconciliationOnly
		}
		return connectOutput{}, err
	}
	recoveryState = apiKeyInitReconciliationOnly // Connected state must not be retried as an incomplete init.
	if global && strings.TrimSpace(req.InboundMode) != "" {
		if err := requireCreatedIdentityInboundMode(nil, req.WorkingDir, req.IdentityHome, serverURL, cert.Team, req.InboundMode); err != nil {
			return connectOutput{}, err
		}
	}
	if err := removeAPIKeyPartialInit(awconfig.IdentityHome{Root: req.IdentityHome}); err != nil {
		return connectOutput{}, fmt.Errorf("remove partial API-key init state: %w", err)
	}
	out.IDRegistration = identityRegistrationUnknown
	out.Responsibility = responsibilityWithoutInstalledChain()
	if responsibility != nil {
		out.IDRegistration = identityRegistrationRegistered
		if !global {
			out.IDRegistration = identityRegistrationNotRequired
		}
		out.Responsibility = responsibility
	}
	return out, nil
}

// retainedAPIKeyCreationTeam uses the original team selection from the same
// private journal as the child key and invitation. Released 1.36.58 writes both
// team fields, so resumption does not need another teams/current read.
func retainedAPIKeyCreationTeam(path string, state *apiKeyPartialInitState) (*apiKeyCreationTeam, error) {
	if state == nil {
		return nil, nil
	}
	if strings.TrimSpace(state.TeamIDHint) == "" || strings.TrimSpace(state.CanonicalTeamID) == "" {
		return nil, usageError("partial API-key creation at %s is missing its original team selection; retain the file for reconciliation", path)
	}
	if _, _, err := awid.ParseTeamID(state.CanonicalTeamID); err != nil {
		return nil, fmt.Errorf("retained API-key creation team: %w", err)
	}
	return &apiKeyCreationTeam{TeamID: state.TeamIDHint, CanonicalTeamID: state.CanonicalTeamID}, nil
}

func selectAPIKeyInitTeam(req apiKeyInitRequest) (apiKeyInitRequest, error) {
	path := apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome})
	state, err := loadAPIKeyPartialInit(path)
	if err != nil {
		return apiKeyInitRequest{}, err
	}
	selectedTeam, err := retainedAPIKeyCreationTeam(path, state)
	if err != nil {
		return apiKeyInitRequest{}, err
	}
	if selectedTeam == nil {
		selectedTeam = req.SelectedTeam
	}
	if selectedTeam == nil {
		readContext, readCancel := commandAPIContext(nil)
		selectedTeam, err = readAPIKeyCreationTeam(readContext, req.AwebURL, req.APIKey)
		readCancel()
		if err != nil {
			return apiKeyInitRequest{}, err
		}
	}
	req.SelectedTeamID, req.CanonicalTeamID = selectedTeam.TeamID, selectedTeam.CanonicalTeamID
	req.CreationInvitation = selectedTeam.CreationInvitation
	return req, nil
}

func prepareAPIKeyBootstrapIdentity(
	req apiKeyInitRequest,
	name string,
	registry *awid.RegistryClient,
) (apiKeyBootstrapIdentityMaterial, error) {
	if err := refuseRejectedAPIKeyPartialInit(apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome})); err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	registryURL := ""
	if registry != nil {
		registryURL = registry.DefaultRegistryURL
	} else if req.Global {
		return apiKeyBootstrapIdentityMaterial{}, errors.New("identity registry client is required for global API-key bootstrap")
	}

	path := apiKeyPartialInitPath(awconfig.IdentityHome{Root: req.IdentityHome})
	state, err := loadAPIKeyPartialInit(path)
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	if state != nil {
		if err := validateAPIKeyPartialInitContext(path, state, req, name, registryURL); err != nil {
			return apiKeyBootstrapIdentityMaterial{}, err
		}
		if err := reconcileAPIKeyCreationRecovery(state, req); err != nil {
			return apiKeyBootstrapIdentityMaterial{}, err
		}

		return materialFromAPIKeyPartialInit(path, state)
	}

	material, err := generateAPIKeyBootstrapIdentity()
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	state, err = newAPIKeyPartialInitState(req, name, registryURL, material)
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	state.IDTree, err = newAPIKeyCreationRecovery(req)
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	if err := saveAPIKeyPartialInit(awconfig.IdentityHome{Root: req.IdentityHome}, state); err != nil {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("write partial API-key init state: %w", err)
	}
	return material, nil
}

// reconcileAPIKeyCreationRecovery keeps the first invitation and request ID.
// A renewed preview is not authority to replace a possibly submitted child.
func reconcileAPIKeyCreationRecovery(state *apiKeyPartialInitState, req apiKeyInitRequest) error {
	if state.IDTree != nil {
		return nil
	}
	tree, err := newAPIKeyCreationRecovery(req)
	if err != nil {
		return err
	}
	state.IDTree = tree
	return saveAPIKeyPartialInit(awconfig.IdentityHome{Root: req.IdentityHome}, state)
}

func generateAPIKeyBootstrapIdentity() (apiKeyBootstrapIdentityMaterial, error) {
	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	return apiKeyBootstrapIdentityMaterial{
		PublicKey:  pub,
		SigningKey: signingKey,
		DIDKey:     awid.ComputeDIDKey(pub),
		StableID:   awid.ComputeStableID(pub),
	}, nil
}

func newAPIKeyPartialInitState(
	req apiKeyInitRequest,
	name string,
	registryURL string,
	material apiKeyBootstrapIdentityMaterial,
) (*apiKeyPartialInitState, error) {
	awebURL, err := canonicalPartialInitAwebURL(req.AwebURL)
	if err != nil {
		return nil, err
	}
	return &apiKeyPartialInitState{
		Version:           apiKeyPartialInitVersion,
		IdentityScope:     string(identityScopeFromFlags(identityScopeFlags{Global: req.Global})),
		Alias:             strings.TrimSpace(req.Alias),
		InboundMode:       strings.TrimSpace(req.InboundMode),
		CanonicalTeamID:   req.CanonicalTeamID,
		DIDKey:            material.DIDKey,
		StableID:          material.StableID,
		SigningKeyB64:     base64.StdEncoding.EncodeToString([]byte(material.SigningKey)),
		Name:              strings.TrimSpace(name),
		AwebURL:           awebURL,
		RegistryURL:       strings.TrimSpace(registryURL),
		TeamIDHint:        req.SelectedTeamID,
		RoleName:          strings.TrimSpace(req.Role),
		HumanName:         strings.TrimSpace(req.HumanName),
		AgentType:         strings.TrimSpace(req.AgentType),
		APIKeyFingerprint: apiKeyFingerprint(req.APIKey),
		CreatedAt:         time.Now().UTC().Format(time.RFC3339),
	}, nil
}

func materialFromAPIKeyPartialInit(path string, state *apiKeyPartialInitState) (apiKeyBootstrapIdentityMaterial, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(state.SigningKeyB64))
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("decode signing key from partial API-key init state %s: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("partial API-key init state %s has invalid signing key size %d", path, len(raw))
	}
	signingKey := ed25519.PrivateKey(raw)
	pub, ok := signingKey.Public().(ed25519.PublicKey)
	if !ok {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("partial API-key init state %s has invalid signing key", path)
	}
	didKey := awid.ComputeDIDKey(pub)
	if didKey != strings.TrimSpace(state.DIDKey) {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("partial API-key init state %s did_key does not match signing key", path)
	}
	stableID := awid.ComputeStableID(pub)
	if stableID != strings.TrimSpace(state.StableID) {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("partial API-key init state %s stable_id does not match signing key", path)
	}
	return apiKeyBootstrapIdentityMaterial{
		PublicKey:  pub,
		SigningKey: signingKey,
		DIDKey:     didKey,
		StableID:   stableID,
	}, nil
}

func validateAPIKeyPartialInitContext(
	path string,
	state *apiKeyPartialInitState,
	req apiKeyInitRequest,
	name string,
	registryURL string,
) error {
	expected, err := newAPIKeyPartialInitState(req, name, registryURL, apiKeyBootstrapIdentityMaterial{})
	if err != nil {
		return err
	}
	var mismatches []string
	scope := state.IdentityScope
	if scope == "" {
		scope = awid.IdentityModeGlobal
	}
	if scope != expected.IdentityScope {
		mismatches = append(mismatches, "identity_scope differs (partial global/local init)")
	}
	if state.Alias != expected.Alias {
		mismatches = append(mismatches, "alias differs")
	}
	if state.InboundMode != expected.InboundMode {
		mismatches = append(mismatches, "inbound_mode differs")
	}
	if state.TeamIDHint != expected.TeamIDHint || state.CanonicalTeamID != expected.CanonicalTeamID {
		mismatches = append(mismatches, "selected team or namespace differs")
	}

	if state.Name != expected.Name {
		mismatches = append(mismatches, fmt.Sprintf("name %q != %q", state.Name, expected.Name))
	}
	if state.AwebURL != expected.AwebURL {
		mismatches = append(mismatches, fmt.Sprintf("aweb_url %q != %q", state.AwebURL, expected.AwebURL))
	}
	if state.RegistryURL != expected.RegistryURL {
		mismatches = append(mismatches, fmt.Sprintf("registry_url %q != %q", state.RegistryURL, expected.RegistryURL))
	}
	if state.RoleName != expected.RoleName {
		mismatches = append(mismatches, fmt.Sprintf("role_name %q != %q", state.RoleName, expected.RoleName))
	}
	if state.HumanName != expected.HumanName {
		mismatches = append(mismatches, fmt.Sprintf("human_name %q != %q", state.HumanName, expected.HumanName))
	}
	if state.AgentType != expected.AgentType {
		mismatches = append(mismatches, fmt.Sprintf("agent_type %q != %q", state.AgentType, expected.AgentType))
	}
	if !state.matchesAPIKey(req.APIKey) {
		mismatches = append(mismatches, "api_key_fingerprint differs")
	}
	if len(mismatches) > 0 {
		return usageError(
			"partial API-key init state at %s was created for a different bootstrap context (%s); retry the original command or remove the file explicitly",
			path,
			strings.Join(mismatches, "; "),
		)
	}
	return nil
}

func canonicalPartialInitAwebURL(raw string) (string, error) {
	return normalizeAPIKeyBootstrapBaseURL(raw)
}

func apiKeyFingerprint(value string) string {
	sum := sha256.Sum256([]byte(strings.TrimSpace(value)))
	return hex.EncodeToString(sum[:])
}

func validateAPIKeyBootstrapResponse(
	resp *apiKeyBootstrapResponse,
	cert *awid.TeamCertificate,
	didKey string,
	requestedGlobal bool,
) (global bool, serverURL, stableID string, err error) {
	if resp == nil {
		return false, "", "", fmt.Errorf("missing workspace init response")
	}
	serverURL, err = normalizeBootstrapServerURL(strings.TrimSpace(resp.ServerURL))
	if err != nil {
		return false, "", "", fmt.Errorf("invalid server_url in workspace init response: %w", err)
	}
	if cert == nil {
		return false, "", "", fmt.Errorf("workspace init response is missing a team cert")
	}
	if err := verifyAPIKeyBootstrapCertificate(cert); err != nil {
		return false, "", "", err
	}
	responseDID := strings.TrimSpace(resp.DID)
	if responseDID == "" {
		return false, "", "", fmt.Errorf("workspace init response is missing did")
	}
	if responseDID != strings.TrimSpace(didKey) {
		return false, "", "", fmt.Errorf("workspace init response did %q does not match generated did:key %q", responseDID, didKey)
	}
	if strings.TrimSpace(cert.MemberDIDKey) != strings.TrimSpace(didKey) {
		return false, "", "", fmt.Errorf("workspace init team cert member_did_key %q does not match generated did:key %q", cert.MemberDIDKey, didKey)
	}
	if teamID := strings.TrimSpace(resp.TeamID); teamID == "" {
		return false, "", "", fmt.Errorf("workspace init response is missing team_id")
	} else if strings.TrimSpace(cert.Team) != teamID {
		return false, "", "", fmt.Errorf("workspace init response team_id %q does not match team cert team %q", teamID, cert.Team)
	}
	if custody := strings.TrimSpace(resp.Custody); custody == "" {
		return false, "", "", fmt.Errorf("workspace init response is missing custody")
	} else if custody != awid.CustodySelf {
		return false, "", "", fmt.Errorf("workspace init response custody %q is not self-custodial", custody)
	}
	if len(strings.TrimSpace(resp.APIKey)) > maxWorkspaceAPIKeyLength {
		return false, "", "", fmt.Errorf("workspace init response api_key exceeds %d bytes", maxWorkspaceAPIKeyLength)
	}
	identityScope := awid.NormalizeIdentityScope(firstNonEmpty(resp.IdentityScope, cert.IdentityScope))
	switch identityScope {
	case awid.IdentityModeGlobal:
		global = true
	case awid.IdentityModeLocal:
		global = false
	default:
		return false, "", "", fmt.Errorf("workspace init response has unsupported identity_scope %q", resp.IdentityScope)
	}
	if global != requestedGlobal {
		return false, "", "", fmt.Errorf(
			"workspace init response identity_scope %q does not match requested identity_scope %q",
			identityScope,
			string(identityScopeFromFlags(identityScopeFlags{Global: requestedGlobal})),
		)
	}
	stableID = strings.TrimSpace(resp.StableID)
	if global {
		if stableID == "" {
			return false, "", "", fmt.Errorf("global identity workspace init response is missing stable_id")
		}
		if strings.TrimSpace(cert.MemberDIDAW) == "" {
			return false, "", "", fmt.Errorf("global identity workspace init response is missing member_did_aw")
		}
		if strings.TrimSpace(cert.MemberAddress) == "" {
			return false, "", "", fmt.Errorf("global identity workspace init response is missing member_address")
		}
		if strings.TrimSpace(cert.MemberDIDAW) != stableID {
			return false, "", "", fmt.Errorf(
				"workspace init response stable_id %q does not match team cert member_did_aw %q",
				stableID,
				cert.MemberDIDAW,
			)
		}
		return global, serverURL, stableID, nil
	}
	if stableID != "" {
		return false, "", "", fmt.Errorf("local workspace init response unexpectedly returned stable_id %q", stableID)
	}
	if strings.TrimSpace(cert.MemberDIDAW) != "" || strings.TrimSpace(cert.MemberAddress) != "" {
		return false, "", "", fmt.Errorf("local workspace init response unexpectedly contains global identity fields")
	}
	return global, serverURL, "", nil
}

func normalizeBootstrapServerURL(raw string) (string, error) {
	u, err := parseAwebSelectionURL(raw)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("server_url must include scheme and host")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	return awebSelectionURLString(u), nil
}

func normalizeAPIKeyBootstrapBaseURL(raw string) (string, error) {
	baseURL, err := normalizeAwebBaseURL(raw)
	if err != nil {
		return "", err
	}
	u, err := parseAwebSelectionURL(baseURL)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/api")
	return awebSelectionURLString(u), nil
}

func verifyAPIKeyBootstrapCertificate(cert *awid.TeamCertificate) error {
	teamDIDKey := strings.TrimSpace(cert.TeamDIDKey)
	if teamDIDKey == "" {
		return fmt.Errorf("workspace init team cert is missing team_did_key")
	}
	if _, err := awid.ExtractPublicKey(teamDIDKey); err != nil {
		return fmt.Errorf("workspace init team cert has invalid team_did_key %q: %w", teamDIDKey, err)
	}
	if err := awid.CheckDecodedTeamCertificate(cert, teamDIDKey); err != nil {
		return fmt.Errorf("workspace init team cert is invalid: %w", err)
	}
	return nil
}

func persistAPIKeyBootstrapState(
	workingDir, identityHome, registryURL string,
	signingKey ed25519.PrivateKey,
	didKey string,
	stableID string,
	cert *awid.TeamCertificate,
	global bool,
) error {
	if err := persistLocalSigningKeyAndCertificateAt(workingDir, identityHome, signingKey, cert); err != nil {
		return err
	}
	if !global {
		return nil
	}
	identityPath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "identity.yaml")
	if err != nil {
		return err
	}
	return awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{
		DID:            strings.TrimSpace(didKey),
		StableID:       strings.TrimSpace(stableID),
		Address:        strings.TrimSpace(cert.MemberAddress),
		Custody:        awid.CustodySelf,
		IdentityScope:  awid.IdentityModeGlobal,
		RegistryURL:    strings.TrimSpace(registryURL),
		RegistryStatus: "registered",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	})
}

// postAPIKeyWorkspaceInit admits the agent with the team API key and proves,
// with signingKey, that the caller holds the agent's did:key.
func postAPIKeyWorkspaceInit(ctx context.Context, awebURL, apiKey string, payload apiKeyBootstrapRequest, signingKey ed25519.PrivateKey) (out *apiKeyBootstrapResponse, resultErr error) {
	if len(signingKey) != ed25519.PrivateKeySize {
		return nil, errors.New("workspace init needs the agent's signing key to prove its did:key")
	}
	var cancel context.CancelFunc
	ctx, cancel = commandAPIContext(nil, ctx)
	defer cancel()

	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(awebURL, "/")+"/api/v1/workspaces/init", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(apiKey))
	req.Header.Set("Content-Type", "application/json")
	for name, value := range awid.DIDKeyProofHeaders(http.MethodPost, "/api/v1/workspaces/init", body, signingKey) {
		req.Header.Set(name, value)
	}

	resp, err := awid.DoServerRequest(&http.Client{Timeout: awid.APITimeout(), Transport: awid.NewAPITransport()}, req, awebURL)
	if err != nil {
		return nil, err
	}
	defer func() { resultErr = errors.Join(resultErr, resp.Body.Close()) }()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("read workspace init refusal: %w", readErr)
		}
		diagnostic, code := workspaceInitHTTPDiagnostic(resp, respBody, apiKey)
		if code != "unknown" {
			if mismatch, ok := parseWorkspaceInitIdentityKeyMismatch(respBody); ok && code == "identity_key_mismatch" {
				guidance := fmt.Sprintf("workspace init cannot use agent name %q: it is bound to a different identity key. Choose a different agent name and retry, or ask a team operator to resolve the existing identity binding.", mismatch.Alias)
				if mismatch.StrandedNamespace != "" {
					guidance += fmt.Sprintf(" The server reported stranded namespace %q.", mismatch.StrandedNamespace)
				}
				return nil, withErrorCode(code, errors.New(guidance+" "+diagnostic))
			}
			return nil, withErrorCode(code, fmt.Errorf("workspace init was refused (%d %s): %s %s", resp.StatusCode, code, workspaceInitRefusalRemedies[code].remedy, diagnostic))
		}
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("workspace init rejected the API key (401): %s", diagnostic)
		case http.StatusNotFound:
			return nil, fmt.Errorf("workspace init target was not found or the team was deleted (404): %s", diagnostic)
		default:
			return nil, fmt.Errorf("POST /api/v1/workspaces/init returned %d: %s", resp.StatusCode, diagnostic)
		}
	}

	responseBody, err := awid.ReadAllBounded(resp.Body, awid.MaxResponseSize)
	if err != nil {
		return nil, fmt.Errorf("read workspace init response: %w", err)
	}
	var result apiKeyBootstrapResponse
	if err := json.Unmarshal(responseBody, &result); err != nil {
		return nil, fmt.Errorf("decode workspace init response: %w", err)
	}
	return &result, nil
}

type workspaceInitIdentityKeyMismatch struct {
	Alias             string
	StrandedNamespace string
}

func parseWorkspaceInitIdentityKeyMismatch(body []byte) (workspaceInitIdentityKeyMismatch, bool) {
	var envelope struct {
		Detail json.RawMessage `json:"detail"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil || len(envelope.Detail) == 0 {
		return workspaceInitIdentityKeyMismatch{}, false
	}
	var detail struct {
		Code              string `json:"code"`
		Alias             string `json:"alias"`
		StrandedNamespace string `json:"stranded_namespace"`
	}
	if err := json.Unmarshal(envelope.Detail, &detail); err != nil || strings.TrimSpace(detail.Code) != "identity_key_mismatch" || strings.TrimSpace(detail.Alias) == "" {
		return workspaceInitIdentityKeyMismatch{}, false
	}
	return workspaceInitIdentityKeyMismatch{Alias: strings.TrimSpace(detail.Alias), StrandedNamespace: strings.TrimSpace(detail.StrandedNamespace)}, true
}

func (response *apiKeyBootstrapResponse) UnmarshalJSON(raw []byte) error {
	type plain apiKeyBootstrapResponse
	if err := json.Unmarshal(raw, (*plain)(response)); err != nil {
		return err
	}
	tree, err := awid.DecodeIDTreeCreationResponse(raw)
	if err != nil {
		return err
	}
	response.IDTreeCreationResponse = tree
	return nil
}

func newAPIKeyCreationRecovery(req apiKeyInitRequest) (*hostedIDTreeRecovery, error) {
	if inv := req.CreationInvitation; inv != nil {
		if err := inv.Validate(); err != nil {
			return nil, err
		}
		name := strings.TrimSpace(req.Alias)
		if req.Global {
			name = strings.TrimSpace(req.Name)
		}
		if name != inv.Name || string(identityScopeFromFlags(identityScopeFlags{Global: req.Global})) != inv.IdentityScope {
			return nil, errors.New("creation invitation differs from requested name or identity scope")
		}
		tree, err := newHostedIDTreeRecovery(hostedIdentityContext{Domain: inv.Domain, ParentKind: "identity", ParentID: fmt.Sprint(inv.Parent["id"])})
		if err != nil {
			return nil, err
		}
		tree.InvitationID = inv.ID
		return tree, nil
	}
	association := hostedIdentityContext{}
	if req.CanonicalTeamID != "" {
		domain, _, err := awid.ParseTeamID(req.CanonicalTeamID)
		if err != nil {
			return nil, err
		}
		association.Domain, association.ParentKind, association.ParentID = domain, "namespace", domain
	}
	return newHostedIDTreeRecovery(association)
}
