package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// connectOutput is the JSON output for `aw init` when using certificate auth.
type connectOutput struct {
	Status      string `json:"status"`
	TeamID      string `json:"team_id"`
	Alias       string `json:"alias"`
	AwebURL     string `json:"aweb_url"`
	WorkspaceID string `json:"workspace_id,omitempty"`
}

// connectResponse is the server response from POST /v1/connect.
type connectResponse struct {
	TeamID      string `json:"team_id"`
	Alias       string `json:"alias"`
	AgentID     string `json:"agent_id"`
	WorkspaceID string `json:"workspace_id"`
	RepoID      string `json:"repo_id"`
	TeamDIDKey  string `json:"team_did_key"`
}

// connectRequest is the body sent to POST /v1/connect.
type connectRequest struct {
	Hostname      string `json:"hostname"`
	WorkspacePath string `json:"workspace_path"`
	RepoOrigin    string `json:"repo_origin,omitempty"`
	Role          string `json:"role,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
	AgentType     string `json:"agent_type,omitempty"`
}

type certificateConnectOptions struct {
	Role      string
	HumanName string
	AgentType string
}

// initCertificateConnect implements the certificate-based init flow.
// Reads team cert + signing key, calls POST /v1/connect, writes workspace.yaml.
func initCertificateConnect(workingDir, awebURL, role string) (connectOutput, error) {
	return initCertificateConnectWithOptions(workingDir, awebURL, certificateConnectOptions{
		Role: strings.TrimSpace(role),
	})
}

func initCertificateConnectWithOptions(workingDir, awebURL string, opts certificateConnectOptions) (connectOutput, error) {
	certPath := filepath.Join(workingDir, ".aw", "team-cert.pem")
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		return connectOutput{}, fmt.Errorf("load team certificate: %w\n(run `aw id team accept-invite` or `aw id team add-member` first to get a certificate at %s)", err, certPath)
	}

	signingKey, err := awid.LoadSigningKey(awconfig.WorktreeSigningKeyPath(workingDir))
	if err != nil {
		return connectOutput{}, fmt.Errorf("load signing key: %w", err)
	}

	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if didKey != cert.MemberDIDKey {
		return connectOutput{}, fmt.Errorf("signing key did:key %s does not match certificate member_did_key %s", didKey, cert.MemberDIDKey)
	}

	hostname, _ := os.Hostname()
	repoOrigin := discoverRepoOrigin(workingDir)

	reqBody := connectRequest{
		Hostname:      hostname,
		WorkspacePath: workingDir,
		RepoOrigin:    repoOrigin,
		Role:          strings.TrimSpace(opts.Role),
		HumanName:     resolveHumanNameValue(strings.TrimSpace(opts.HumanName)),
		AgentType:     resolveAgentTypeValue(strings.TrimSpace(opts.AgentType)),
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	resp, err := postConnect(ctx, awebURL, signingKey, cert, reqBody)
	if err != nil {
		return connectOutput{}, err
	}

	// Write workspace.yaml
	workspacePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if _, existingErr := awconfig.LoadWorktreeWorkspaceFrom(workspacePath); existingErr != nil && !os.IsNotExist(existingErr) {
		return connectOutput{}, existingErr
	}
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, &awconfig.WorktreeWorkspace{
		AwebURL:         awebURL,
		TeamID:          resp.TeamID,
		Alias:           resp.Alias,
		WorkspaceID:     resp.WorkspaceID,
		RepoID:          resp.RepoID,
		CanonicalOrigin: canonicalizeGitOrigin(repoOrigin),
		HumanName:       reqBody.HumanName,
		AgentType:       reqBody.AgentType,
		RoleName:        strings.TrimSpace(opts.Role),
		Hostname:        hostname,
		WorkspacePath:   workingDir,
		UpdatedAt:       time.Now().UTC().Format(time.RFC3339),
	}); err != nil {
		return connectOutput{}, err
	}

	// Ensure .aw/context exists
	if err := ensureWorktreeContextAt(workingDir); err != nil {
		return connectOutput{}, err
	}

	return connectOutput{
		Status:      "connected",
		TeamID:      resp.TeamID,
		Alias:       resp.Alias,
		AwebURL:     awebURL,
		WorkspaceID: resp.WorkspaceID,
	}, nil
}

// postConnect sends POST /v1/connect with DIDKey auth + team certificate.
func postConnect(ctx context.Context, awebURL string, signingKey ed25519.PrivateKey, cert *awid.TeamCertificate, body connectRequest) (*connectResponse, error) {
	bodyJSON, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}

	url := strings.TrimRight(awebURL, "/") + "/v1/connect"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(bodyJSON))
	if err != nil {
		return nil, err
	}

	// DIDKey signature over {body_sha256, team_id, timestamp}
	timestamp := time.Now().UTC().Format(time.RFC3339)
	did := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	bodyHash := sha256.Sum256(bodyJSON)
	bodyHashHex := hex.EncodeToString(bodyHash[:])
	sigPayload := fmt.Sprintf(`{"body_sha256":%q,"team_id":%q,"timestamp":%q}`, bodyHashHex, cert.Team, timestamp)
	sig := ed25519.Sign(signingKey, []byte(sigPayload))
	req.Header.Set("Authorization", fmt.Sprintf("DIDKey %s %s", did, base64.RawStdEncoding.EncodeToString(sig)))
	req.Header.Set("X-AWEB-Timestamp", timestamp)

	// Team certificate header
	certEncoded, err := awid.EncodeTeamCertificateHeader(cert)
	if err != nil {
		return nil, fmt.Errorf("encode certificate header: %w", err)
	}
	req.Header.Set("X-AWID-Team-Certificate", certEncoded)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		respBody, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("POST /v1/connect returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result connectResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decode connect response: %w", err)
	}
	return &result, nil
}

// hasCertificateForInit checks if .aw/team-cert.pem exists in the working directory.
func hasCertificateForInit(workingDir string) bool {
	_, err := os.Stat(filepath.Join(workingDir, ".aw", "team-cert.pem"))
	return err == nil
}

// discoverRepoOrigin attempts to find the git remote origin URL.
func discoverRepoOrigin(workingDir string) string {
	cmd := exec.Command("git", "-C", workingDir, "remote", "get-url", "origin")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// canonicalizeGitOrigin strips .git suffix and normalizes git URLs to domain/path form.
func canonicalizeGitOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}
	// Strip trailing .git
	origin = strings.TrimSuffix(origin, ".git")
	// Convert SSH URLs: git@github.com:org/repo → github.com/org/repo
	if strings.HasPrefix(origin, "git@") {
		origin = strings.TrimPrefix(origin, "git@")
		origin = strings.Replace(origin, ":", "/", 1)
	}
	// Strip https:// or http://
	for _, prefix := range []string{"https://", "http://"} {
		if strings.HasPrefix(origin, prefix) {
			origin = strings.TrimPrefix(origin, prefix)
		}
	}
	return origin
}

func formatConnect(v any) string {
	out := v.(connectOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Alias:       %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Aweb URL:    %s\n", out.AwebURL))
	return sb.String()
}
