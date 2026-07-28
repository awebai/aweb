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
	"net/http"
	"net/url"
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
	Status        string `json:"status"`
	TeamID        string `json:"team_id"`
	Alias         string `json:"alias"`
	AwebURL       string `json:"aweb_url"`
	AgentID       string `json:"-"`
	WorkspaceID   string `json:"workspace_id,omitempty"`
	StableID      string `json:"stable_id,omitempty"`
	Address       string `json:"address,omitempty"`
	IdentityScope string `json:"identity_scope,omitempty"`
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
// Identities are repo-independent: the request carries no repo_origin, and
// the CLI never sends the cwd git origin for identity/workspace init.
type connectRequest struct {
	Hostname      string `json:"hostname"`
	WorkspacePath string `json:"workspace_path"`
	Role          string `json:"role,omitempty"`
	HumanName     string `json:"human_name,omitempty"`
	AgentType     string `json:"agent_type,omitempty"`
}

type certificateConnectOptions struct {
	Role         string
	HumanName    string
	AgentType    string
	APIKey       string
	IdentityHome string
}

// initCertificateConnect implements the certificate-based init flow.
// Reads team cert + signing key, calls POST /v1/connect, writes workspace.yaml.
func initCertificateConnect(workingDir, awebURL, role string) (connectOutput, error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return connectOutput{}, err
	}
	return initCertificateConnectWithOptions(workingDir, awebURL, certificateConnectOptions{
		Role:         strings.TrimSpace(role),
		IdentityHome: home.Root,
	})
}

func initCertificateConnectWithOptions(workingDir, awebURL string, opts certificateConnectOptions) (connectOutput, error) {
	identityHome := strings.TrimSpace(opts.IdentityHome)
	if identityHome == "" {
		identityHome = filepath.Join(filepath.Clean(workingDir), ".aw")
	}
	cert, certPath, err := loadCertificateForConnectAt(workingDir, identityHome)
	if err != nil {
		return connectOutput{}, fmt.Errorf("load team certificate: %w\n(run `aw id team fetch-cert` after controller approval to install a certificate under %s)", err, filepath.Join(workingDir, ".aw", "team-certs"))
	}

	signingKeyPath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "signing.key")
	if err != nil {
		return connectOutput{}, err
	}
	signingKey, err := awid.LoadSigningKey(signingKeyPath)
	if err != nil {
		return connectOutput{}, fmt.Errorf("load signing key: %w", err)
	}

	didKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if didKey != cert.MemberDIDKey {
		return connectOutput{}, fmt.Errorf("signing key did:key %s does not match certificate member_did_key %s", didKey, cert.MemberDIDKey)
	}

	hostname, _ := os.Hostname()

	reqBody := connectRequest{
		Hostname:      hostname,
		WorkspacePath: workingDir,
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

	workspacePath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "workspace.yaml")
	if err != nil {
		return connectOutput{}, err
	}
	workspaceState, existingErr := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if existingErr != nil && !os.IsNotExist(existingErr) {
		return connectOutput{}, existingErr
	}
	if workspaceState == nil {
		workspaceState = &awconfig.WorktreeWorkspace{}
	}
	// Record the teams.yaml membership through the shared writer, which carries
	// over any registry/aweb URLs an earlier join stored. The worktree binding
	// (role, workspace id) is written separately below because it is unique to
	// the connect step.
	if err := upsertAcceptedTeamMembershipState(workingDir, &teamAcceptInviteOutput{
		TeamID:   resp.TeamID,
		Alias:    resp.Alias,
		CertPath: filepath.ToSlash(certPath),
	}, cert, "", "", true, identityHome); err != nil {
		return connectOutput{}, err
	}
	workspaceState.AwebURL = awebURL
	if strings.TrimSpace(opts.APIKey) != "" {
		workspaceState.APIKey = strings.TrimSpace(opts.APIKey)
	}
	upsertWorkspaceMembershipCache(workspaceState, awconfig.WorktreeMembership{
		TeamID:      resp.TeamID,
		Alias:       resp.Alias,
		RoleName:    strings.TrimSpace(opts.Role),
		WorkspaceID: resp.WorkspaceID,
		CertPath:    filepath.ToSlash(certPath),
		JoinedAt:    strings.TrimSpace(cert.IssuedAt),
	})
	workspaceState.RepoID = resp.RepoID
	workspaceState.CanonicalOrigin = canonicalizeGitOrigin(discoverRepoOrigin(workingDir))
	workspaceState.HumanName = reqBody.HumanName
	workspaceState.AgentType = reqBody.AgentType
	workspaceState.Hostname = hostname
	workspaceState.WorkspacePath = workingDir
	workspaceState.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspaceState); err != nil {
		return connectOutput{}, err
	}

	// Ensure .aw/context exists
	if err := ensureWorktreeContextAtIdentityHome(identityHome); err != nil {
		return connectOutput{}, err
	}
	if err := ensureLocalIdentityEncryptionKeyForDir(workingDir, explicitEncryptionKeyIdentityHome(identityHome)); err != nil {
		return connectOutput{}, fmt.Errorf("set up E2E encryption key: %w", err)
	}
	if _, err := setupOrRotateIdentityEncryptionKeyForDir(ctx, workingDir, false, explicitEncryptionKeyIdentityHome(identityHome)); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not publish E2E encryption key automatically: %v\n", err)
	}

	identityScope := awid.NormalizeIdentityScope(firstNonEmpty(cert.IdentityScope, cert.Lifetime))
	return connectOutput{
		Status:        "connected",
		TeamID:        resp.TeamID,
		Alias:         resp.Alias,
		AwebURL:       awebURL,
		AgentID:       resp.AgentID,
		WorkspaceID:   resp.WorkspaceID,
		StableID:      strings.TrimSpace(cert.MemberDIDAW),
		Address:       strings.TrimSpace(cert.MemberAddress),
		IdentityScope: identityScope,
	}, nil
}

func loadCertificateForConnect(workingDir string) (*awid.TeamCertificate, string, error) {
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return nil, "", err
	}
	return loadCertificateForConnectAt(workingDir, home.Root)
}

func loadCertificateForConnectAt(workingDir, identityHome string) (*awid.TeamCertificate, string, error) {
	if teamState, err := awconfig.LoadTeamStateFromIdentityHome(identityHome); err == nil && teamState != nil {
		activeMembership := teamState.ActiveMembership()
		if activeMembership == nil {
			return nil, "", fmt.Errorf("teams state is missing active_team membership")
		}
		certPath, err := awconfig.IdentityHomeStoredPath(awconfig.IdentityHome{Root: identityHome}, activeMembership.CertPath)
		if err != nil {
			return nil, "", err
		}
		cert, err := awid.LoadTeamCertificate(certPath)
		if err != nil {
			return nil, "", err
		}
		return cert, strings.TrimSpace(activeMembership.CertPath), nil
	}

	stored, err := awconfig.ListTeamCertificatesFromIdentityHome(identityHome)
	if err != nil {
		return nil, "", err
	}
	if len(stored) == 0 {
		return nil, "", os.ErrNotExist
	}
	if len(stored) > 1 {
		return nil, "", fmt.Errorf("multiple team certificates found under .aw/team-certs; connect one team at a time after choosing an active team")
	}
	return stored[0].Certificate, stored[0].CertPath, nil
}

// postConnect sends POST /v1/connect with DIDKey auth + team certificate.
// maxConnectResponseBytes bounds the /v1/connect response so an untrusted or
// MITM'd aweb server cannot exhaust client memory during the pre-trust connect
// handshake. Var, not const, only so tests can lower it without a multi-MiB
// fixture; production keeps the shared response cap.
var maxConnectResponseBytes int64 = awid.MaxResponseSize

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

	client := &http.Client{Timeout: 30 * time.Second, Transport: awid.NewAPITransport()}
	resp, err := awid.DoNoRedirect(client, req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := readAllBounded(resp.Body, maxConnectResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("read connect response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("POST /v1/connect returned %d: %s", resp.StatusCode, string(respBody))
	}

	var result connectResponse
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("decode connect response: %w", err)
	}
	return &result, nil
}

// hasCertificateForInit checks if at least one team certificate exists in the working directory.
func hasCertificateForInit(workingDir string) bool {
	stored, err := awconfig.ListTeamCertificates(workingDir)
	return err == nil && len(stored) > 0
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

// canonicalizeGitOrigin strips credentials, ports, and .git suffixes and
// normalizes git URLs to domain/path form.
func canonicalizeGitOrigin(origin string) string {
	origin = strings.TrimSpace(origin)
	if origin == "" {
		return ""
	}

	if parsed, err := url.Parse(origin); err == nil && parsed.Scheme != "" && parsed.Hostname() != "" {
		path := strings.TrimSuffix(strings.Trim(parsed.Path, "/"), ".git")
		if path != "" {
			return canonicalGitHost(parsed.Hostname()) + "/" + path
		}
	}

	// Convert scp-like SSH URLs: user@host:org/repo.git → host/org/repo.
	if !strings.Contains(origin, "://") {
		if colon := strings.Index(origin, ":"); colon > 0 && colon < len(origin)-1 {
			host := origin[:colon]
			if at := strings.LastIndex(host, "@"); at >= 0 {
				host = host[at+1:]
			}
			path := strings.TrimSuffix(strings.Trim(origin[colon+1:], "/"), ".git")
			if host != "" && path != "" {
				return canonicalGitHost(host) + "/" + path
			}
		}
	}

	return strings.TrimSuffix(origin, ".git")
}

func canonicalGitHost(host string) string {
	if strings.EqualFold(strings.TrimSpace(host), "ssh.github.com") {
		return "github.com"
	}
	return strings.TrimSpace(host)
}

func formatConnect(v any) string {
	out := v.(connectOutput)
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("Status:      %s\n", out.Status))
	sb.WriteString(fmt.Sprintf("Team:        %s\n", out.TeamID))
	sb.WriteString(fmt.Sprintf("Name:        %s\n", out.Alias))
	sb.WriteString(fmt.Sprintf("Aweb URL:    %s\n", out.AwebURL))
	return sb.String()
}
