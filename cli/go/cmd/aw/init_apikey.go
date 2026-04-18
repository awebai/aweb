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
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"gopkg.in/yaml.v3"
)

const initAPIKeyEnvVar = "AWEB_API_KEY"
const maxWorkspaceAPIKeyLength = 4096
const apiKeyPartialInitVersion = 1

type apiKeyInitRequest struct {
	WorkingDir   string
	AwebURL      string
	RegistryURL  string
	APIKey       string
	Name         string
	Alias        string
	Reachability string
	Role         string
	HumanName    string
	AgentType    string
	Persistent   bool
}

type apiKeyBootstrapRequest struct {
	DID                 string `json:"did"`
	PublicKey           string `json:"public_key"`
	Name                string `json:"name,omitempty"`
	Alias               string `json:"alias,omitempty"`
	Custody             string `json:"custody"`
	AddressReachability string `json:"address_reachability,omitempty"`
	RoleName            string `json:"role_name,omitempty"`
	HumanName           string `json:"human_name,omitempty"`
	AgentType           string `json:"agent_type,omitempty"`
	Lifetime            string `json:"lifetime"`
}

type apiKeyBootstrapResponse struct {
	ServerURL   string `json:"server_url"`
	TeamCert    string `json:"team_cert"`
	Alias       string `json:"alias"`
	TeamID      string `json:"team_id"`
	WorkspaceID string `json:"workspace_id"`
	DID         string `json:"did"`
	StableID    string `json:"stable_id"`
	Lifetime    string `json:"lifetime"`
	Custody     string `json:"custody"`
	APIKey      string `json:"api_key"`
}

type apiKeyPartialInitState struct {
	Version           int    `yaml:"version"`
	DIDKey            string `yaml:"did_key"`
	StableID          string `yaml:"stable_id"`
	SigningKeyB64     string `yaml:"signing_key_b64"`
	Name              string `yaml:"name"`
	AwebURL           string `yaml:"aweb_url"`
	RegistryURL       string `yaml:"registry_url"`
	TeamIDHint        string `yaml:"team_id_hint,omitempty"`
	RoleName          string `yaml:"role_name,omitempty"`
	HumanName         string `yaml:"human_name,omitempty"`
	AgentType         string `yaml:"agent_type,omitempty"`
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

func resolveInitAPIKey() string {
	return strings.TrimSpace(os.Getenv(initAPIKeyEnvVar))
}

func resolveAPIKeyInitAwebURL() (string, error) {
	value := resolveInitAwebURLOverride()
	if value == "" {
		return "", usageError("--aweb-url, --url, or AWEB_URL is required when AWEB_API_KEY is set")
	}
	return normalizeAPIKeyBootstrapBaseURL(value)
}

func runAPIKeyBootstrapInit(req apiKeyInitRequest) (connectOutput, error) {
	if strings.TrimSpace(req.WorkingDir) == "" {
		return connectOutput{}, fmt.Errorf("working directory is required")
	}
	if strings.TrimSpace(req.APIKey) == "" {
		return connectOutput{}, usageError("AWEB_API_KEY is required for API key bootstrap")
	}
	if strings.TrimSpace(req.AwebURL) == "" {
		return connectOutput{}, usageError("--aweb-url, --url, or AWEB_URL is required when AWEB_API_KEY is set")
	}
	if err := ensureConnectTargetClean(req.WorkingDir); err != nil {
		return connectOutput{}, err
	}

	// Cloud contract: persistent uses name (not alias), ephemeral uses alias (not name).
	name := strings.TrimSpace(req.Name)
	alias := strings.TrimSpace(req.Alias)
	if req.Persistent {
		if name == "" {
			return connectOutput{}, usageError("--name is required for persistent API key bootstrap")
		}
		alias = "" // cloud rejects alias for persistent
	}

	var registry *awid.RegistryClient
	if req.Persistent {
		var regErr error
		registry, regErr = newRegistryClientWithPreferredBaseURL(strings.TrimSpace(req.RegistryURL))
		if regErr != nil {
			return connectOutput{}, regErr
		}
	}

	material, err := prepareAPIKeyBootstrapIdentity(req, name, registry)
	if err != nil {
		return connectOutput{}, err
	}
	pub := material.PublicKey
	signingKey := material.SigningKey
	didKey := material.DIDKey
	localStableID := material.StableID

	if req.Persistent {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
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

	resp, err := postAPIKeyWorkspaceInit(context.Background(), strings.TrimSpace(req.AwebURL), strings.TrimSpace(req.APIKey), apiKeyBootstrapRequest{
		DID:                 didKey,
		PublicKey:           base64.StdEncoding.EncodeToString(pub),
		Name:                name,
		Alias:               alias,
		Custody:             awid.CustodySelf,
		AddressReachability: strings.TrimSpace(req.Reachability),
		RoleName:            strings.TrimSpace(req.Role),
		HumanName:           strings.TrimSpace(req.HumanName),
		AgentType:           strings.TrimSpace(req.AgentType),
		Lifetime:            initLifetimeValue(req.Persistent),
	})
	if err != nil {
		return connectOutput{}, err
	}

	encodedCert := strings.TrimSpace(resp.TeamCert)
	if encodedCert == "" {
		return connectOutput{}, fmt.Errorf("workspace init response is missing team_cert")
	}
	cert, err := awid.DecodeTeamCertificateHeader(encodedCert)
	if err != nil {
		return connectOutput{}, fmt.Errorf("decode workspace init team cert: %w", err)
	}
	persistent, serverURL, stableID, err := validateAPIKeyBootstrapResponse(resp, cert, didKey, req.Persistent)
	if err != nil {
		return connectOutput{}, err
	}
	if persistent && stableID != localStableID {
		return connectOutput{}, fmt.Errorf("workspace init response stable_id %q does not match locally computed %q", stableID, localStableID)
	}
	if strings.TrimSpace(resp.APIKey) == "" {
		return connectOutput{}, fmt.Errorf("workspace init response is missing api_key")
	}

	if err := persistAPIKeyBootstrapState(req.WorkingDir, req.RegistryURL, signingKey, didKey, stableID, cert, persistent); err != nil {
		return connectOutput{}, err
	}
	if persistent {
		if err := removeAPIKeyPartialInit(req.WorkingDir); err != nil {
			return connectOutput{}, fmt.Errorf("remove partial API-key init state: %w", err)
		}
	}

	return initCertificateConnectWithOptions(req.WorkingDir, serverURL, certificateConnectOptions{
		Role:      strings.TrimSpace(req.Role),
		HumanName: strings.TrimSpace(req.HumanName),
		AgentType: strings.TrimSpace(req.AgentType),
		APIKey:    strings.TrimSpace(resp.APIKey),
	})
}

func initLifetimeValue(persistent bool) string {
	if persistent {
		return awid.LifetimePersistent
	}
	return awid.LifetimeEphemeral
}

func prepareAPIKeyBootstrapIdentity(
	req apiKeyInitRequest,
	name string,
	registry *awid.RegistryClient,
) (apiKeyBootstrapIdentityMaterial, error) {
	if !req.Persistent {
		if _, err := os.Stat(apiKeyPartialInitPath(req.WorkingDir)); err == nil {
			return apiKeyBootstrapIdentityMaterial{}, usageError(
				"found partial persistent API-key init state at %s; retry the persistent init or remove the file explicitly",
				apiKeyPartialInitPath(req.WorkingDir),
			)
		} else if !os.IsNotExist(err) {
			return apiKeyBootstrapIdentityMaterial{}, err
		}
		return generateAPIKeyBootstrapIdentity()
	}
	if registry == nil {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("identity registry client is required for persistent API-key bootstrap")
	}

	path := apiKeyPartialInitPath(req.WorkingDir)
	state, err := loadAPIKeyPartialInit(path)
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	if state != nil {
		if err := validateAPIKeyPartialInitContext(path, state, req, name, registry.DefaultRegistryURL); err != nil {
			return apiKeyBootstrapIdentityMaterial{}, err
		}
		return materialFromAPIKeyPartialInit(path, state)
	}

	material, err := generateAPIKeyBootstrapIdentity()
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	state, err = newAPIKeyPartialInitState(req, name, registry.DefaultRegistryURL, material)
	if err != nil {
		return apiKeyBootstrapIdentityMaterial{}, err
	}
	if err := saveAPIKeyPartialInit(req.WorkingDir, state); err != nil {
		return apiKeyBootstrapIdentityMaterial{}, fmt.Errorf("write partial API-key init state: %w", err)
	}
	return material, nil
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

func apiKeyPartialInitPath(workingDir string) string {
	return filepath.Join(workingDir, ".aw", "partial-init.yaml")
}

func loadAPIKeyPartialInit(path string) (*apiKeyPartialInitState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var state apiKeyPartialInitState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read partial API-key init state %s: %w", path, err)
	}
	if state.Version != apiKeyPartialInitVersion {
		return nil, usageError(
			"partial API-key init state at %s has unsupported version %d; retry with a matching aw version or remove the file explicitly",
			path,
			state.Version,
		)
	}
	return &state, nil
}

func saveAPIKeyPartialInit(workingDir string, state *apiKeyPartialInitState) error {
	if state == nil {
		return fmt.Errorf("nil partial API-key init state")
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(apiKeyPartialInitPath(workingDir), data)
}

func removeAPIKeyPartialInit(workingDir string) error {
	if err := os.Remove(apiKeyPartialInitPath(workingDir)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
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
		DIDKey:            material.DIDKey,
		StableID:          material.StableID,
		SigningKeyB64:     base64.StdEncoding.EncodeToString([]byte(material.SigningKey)),
		Name:              strings.TrimSpace(name),
		AwebURL:           awebURL,
		RegistryURL:       strings.TrimSpace(registryURL),
		TeamIDHint:        "",
		RoleName:          strings.TrimSpace(req.Role),
		HumanName:         strings.TrimSpace(req.HumanName),
		AgentType:         strings.TrimSpace(req.AgentType),
		Reachability:      strings.TrimSpace(req.Reachability),
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
	if state.Reachability != expected.Reachability {
		mismatches = append(mismatches, fmt.Sprintf("reachability %q != %q", state.Reachability, expected.Reachability))
	}
	if state.APIKeyFingerprint != expected.APIKeyFingerprint {
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
	requestedPersistent bool,
) (persistent bool, serverURL, stableID string, err error) {
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
	lifetime := strings.TrimSpace(resp.Lifetime)
	switch lifetime {
	case awid.LifetimePersistent:
		persistent = true
	case awid.LifetimeEphemeral:
		persistent = false
	default:
		return false, "", "", fmt.Errorf("workspace init response has unsupported lifetime %q", resp.Lifetime)
	}
	if persistent != requestedPersistent {
		return false, "", "", fmt.Errorf(
			"workspace init response lifetime %q does not match requested lifetime %q",
			lifetime,
			initLifetimeValue(requestedPersistent),
		)
	}
	stableID = strings.TrimSpace(resp.StableID)
	if persistent {
		if stableID == "" {
			return false, "", "", fmt.Errorf("persistent workspace init response is missing stable_id")
		}
		if strings.TrimSpace(cert.MemberDIDAW) == "" {
			return false, "", "", fmt.Errorf("persistent workspace init response is missing member_did_aw")
		}
		if strings.TrimSpace(cert.MemberAddress) == "" {
			return false, "", "", fmt.Errorf("persistent workspace init response is missing member_address")
		}
		if strings.TrimSpace(cert.MemberDIDAW) != stableID {
			return false, "", "", fmt.Errorf(
				"workspace init response stable_id %q does not match team cert member_did_aw %q",
				stableID,
				cert.MemberDIDAW,
			)
		}
		return persistent, serverURL, stableID, nil
	}
	if stableID != "" {
		return false, "", "", fmt.Errorf("ephemeral workspace init response unexpectedly returned stable_id %q", stableID)
	}
	if strings.TrimSpace(cert.MemberDIDAW) != "" || strings.TrimSpace(cert.MemberAddress) != "" {
		return false, "", "", fmt.Errorf("ephemeral workspace init response unexpectedly contains persistent identity fields")
	}
	return persistent, serverURL, "", nil
}

func normalizeBootstrapServerURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(u.Scheme) == "" || strings.TrimSpace(u.Host) == "" {
		return "", fmt.Errorf("server_url must include scheme and host")
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func normalizeAPIKeyBootstrapBaseURL(raw string) (string, error) {
	baseURL, err := normalizeAwebBaseURL(raw)
	if err != nil {
		return "", err
	}
	u, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	u.Path = strings.TrimSuffix(u.Path, "/")
	u.Path = strings.TrimSuffix(u.Path, "/api")
	u.RawPath = ""
	u.RawQuery = ""
	u.Fragment = ""
	return strings.TrimSuffix(u.String(), "/"), nil
}

func verifyAPIKeyBootstrapCertificate(cert *awid.TeamCertificate) error {
	teamDIDKey := strings.TrimSpace(cert.TeamDIDKey)
	if teamDIDKey == "" {
		return fmt.Errorf("workspace init team cert is missing team_did_key")
	}
	teamPub, err := awid.ExtractPublicKey(teamDIDKey)
	if err != nil {
		return fmt.Errorf("workspace init team cert has invalid team_did_key %q: %w", teamDIDKey, err)
	}
	if err := awid.VerifyTeamCertificate(cert, teamPub); err != nil {
		return fmt.Errorf("workspace init team cert signature verification failed: %w", err)
	}
	return nil
}

func persistAPIKeyBootstrapState(
	workingDir, registryURL string,
	signingKey ed25519.PrivateKey,
	didKey string,
	stableID string,
	cert *awid.TeamCertificate,
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
		DID:            strings.TrimSpace(didKey),
		StableID:       strings.TrimSpace(stableID),
		Address:        strings.TrimSpace(cert.MemberAddress),
		Custody:        awid.CustodySelf,
		Lifetime:       awid.LifetimePersistent,
		RegistryURL:    strings.TrimSpace(registryURL),
		RegistryStatus: "registered",
		CreatedAt:      time.Now().UTC().Format(time.RFC3339),
	})
}

func postAPIKeyWorkspaceInit(ctx context.Context, awebURL, apiKey string, payload apiKeyBootstrapRequest) (*apiKeyBootstrapResponse, error) {
	var cancel context.CancelFunc
	ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
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

	resp, err := (&http.Client{}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		detail := strings.TrimSpace(string(respBody))
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			if detail != "" {
				return nil, fmt.Errorf("workspace init rejected the API key (401): %s", detail)
			}
			return nil, fmt.Errorf("workspace init rejected the API key (401)")
		case http.StatusNotFound:
			return nil, fmt.Errorf("workspace init target was not found or the team was deleted (404)")
		default:
			return nil, fmt.Errorf("POST /api/v1/workspaces/init returned %d: %s", resp.StatusCode, detail)
		}
	}

	var result apiKeyBootstrapResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode workspace init response: %w", err)
	}
	return &result, nil
}

func runRequestedInitPostSetup(workingDir string) error {
	repoRoot := resolveRepoRoot(workingDir)
	if initInjectDocs {
		printInjectDocsResult(InjectAgentDocs(repoRoot))
	}
	if initSetupChannel {
		printChannelMCPResult(SetupChannelMCP(repoRoot, initIsTTY()))
	}
	if initSetupHooks {
		printClaudeHooksResult(SetupClaudeHooks(repoRoot, initIsTTY()))
	}
	return nil
}
