package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
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

const initAPIKeyEnvVar = "AWEB_API_KEY"

type apiKeyInitRequest struct {
	WorkingDir  string
	AwebURL     string
	RegistryURL string
	APIKey      string
	Role        string
	HumanName   string
	AgentType   string
	Persistent  bool
}

type apiKeyBootstrapRequest struct {
	DIDKey    string `json:"did_key"`
	PublicKey string `json:"public_key"`
	Role      string `json:"role,omitempty"`
	Lifetime  string `json:"lifetime"`
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

func resolveInitAPIKey() string {
	return strings.TrimSpace(os.Getenv(initAPIKeyEnvVar))
}

func resolveAPIKeyInitAwebURL() (string, error) {
	value := resolveInitAwebURLOverride()
	if value == "" {
		return "", usageError("--aweb-url, --url, or AWEB_URL is required when AWEB_API_KEY is set")
	}
	return normalizeAwebBaseURL(value)
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
	if initBaseURLIsLocalhost(req.AwebURL) {
		return connectOutput{}, usageError("AWEB_API_KEY bootstrap is only supported against non-localhost AWEB_URL values")
	}
	if err := ensureConnectTargetClean(req.WorkingDir); err != nil {
		return connectOutput{}, err
	}

	pub, signingKey, err := awid.GenerateKeypair()
	if err != nil {
		return connectOutput{}, err
	}
	didKey := awid.ComputeDIDKey(pub)

	resp, err := postAPIKeyWorkspaceInit(context.Background(), strings.TrimSpace(req.AwebURL), strings.TrimSpace(req.APIKey), apiKeyBootstrapRequest{
		DIDKey:    didKey,
		PublicKey: base64.StdEncoding.EncodeToString(pub),
		Role:      strings.TrimSpace(req.Role),
		Lifetime:  initLifetimeValue(req.Persistent),
	})
	if err != nil {
		return connectOutput{}, err
	}

	cert, err := awid.DecodeTeamCertificateHeader(strings.TrimSpace(resp.TeamCert))
	if err != nil {
		return connectOutput{}, fmt.Errorf("decode workspace init team cert: %w", err)
	}
	persistent, serverURL, stableID, err := validateAPIKeyBootstrapResponse(resp, cert, didKey, req.Persistent)
	if err != nil {
		return connectOutput{}, err
	}
	if err := persistAPIKeyBootstrapState(req.WorkingDir, req.RegistryURL, signingKey, didKey, stableID, cert, persistent); err != nil {
		return connectOutput{}, err
	}

	return initCertificateConnectWithOptions(req.WorkingDir, serverURL, certificateConnectOptions{
		Role:      strings.TrimSpace(req.Role),
		HumanName: strings.TrimSpace(req.HumanName),
		AgentType: strings.TrimSpace(req.AgentType),
	})
}

func initLifetimeValue(persistent bool) string {
	if persistent {
		return awid.LifetimePersistent
	}
	return awid.LifetimeEphemeral
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
	serverURL, err = normalizeAwebBaseURL(strings.TrimSpace(resp.ServerURL))
	if err != nil {
		return false, "", "", fmt.Errorf("invalid server_url in workspace init response: %w", err)
	}
	if strings.TrimSpace(resp.TeamCert) == "" {
		return false, "", "", fmt.Errorf("workspace init response is missing team_cert")
	}
	if cert == nil {
		return false, "", "", fmt.Errorf("workspace init response is missing a team cert")
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
	if ctx == nil {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
	} else {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}

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

	resp, err := (&http.Client{Timeout: 30 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return nil, fmt.Errorf("workspace init rejected the API key (401)")
		case http.StatusNotFound:
			return nil, fmt.Errorf("workspace init target was not found or the team was deleted (404)")
		default:
			return nil, fmt.Errorf("POST /api/v1/workspaces/init returned %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
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
