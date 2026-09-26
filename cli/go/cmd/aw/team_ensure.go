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
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"
)

const (
	workspaceTeamKeyFormat       = 1
	workspaceTeamEnsurePath      = "/api/v1/teams/workspace-team/ensure"
	workspaceTeamEnrollPath      = "/api/v1/teams/workspace-team/enroll"
	workspaceTeamEnrollOperation = "workspace_team_member_enroll.v1"
	workspaceTeamPartialVersion  = 1
)

var (
	teamEnsureWorkspaceKey string
	teamEnsureLabel        string
)

var teamEnsureCmd = &cobra.Command{
	Use:   "ensure --workspace-key <canonical-key>",
	Short: "Ensure this host has a workspace's default team authority",
	Long: "Ensure this host has a workspace's default team authority.\n\n" +
		"The server receives only the format-1 workspace-key digest. Credentials are installed\n" +
		"only into the explicit --identity-home credential root, and the result is bound only\n" +
		"after a live spawn-authority proof from that installed root.\n\n" +
		"Stable diagnostics are printed to stderr and exit 2, including with --json; there is\n" +
		"no JSON error envelope. authorization-required means host CLI auth is missing,\n" +
		"invalid, expired, revoked, or not authorized. workspace-key-not-portable means a\n" +
		"local/ workspace key cannot be used for hosted default team ensure.\n" +
		"identity-home-occupied means the explicit identity home already contains\n" +
		"conflicting identity, team, workspace, or binding state. unsupported-server means\n" +
		"the aweb service is older than the workspace's default team ensure/enroll contract (Cloud 0.8.16\n" +
		"or later) and is missing one of: CLI auth status, workspace's default team ensure,\n" +
		"workspace's default team enroll, or installed-root spawn-authority proof. Non-404\n" +
		"server errors keep their existing handling.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTeamEnsure(cmd.Context(), cmd)
	},
}

type workspaceTeamEnsureRequest struct {
	WorkspaceKeyFormat int    `json:"workspace_key_format"`
	WorkspaceKeySHA256 string `json:"workspace_key_sha256"`
	Label              string `json:"label,omitempty"`
	ExpectedTeamID     string `json:"expected_team_id,omitempty"`
}

type workspaceTeamEnsureResponse struct {
	State           string         `json:"state"`
	TeamID          string         `json:"team_id"`
	CanonicalTeamID string         `json:"canonical_team_id"`
	Label           string         `json:"label,omitempty"`
	LabelSource     string         `json:"label_source,omitempty"`
	Owner           map[string]any `json:"owner,omitempty"`
	Binding         map[string]any `json:"binding,omitempty"`
}

type workspaceTeamEnrollRequest struct {
	WorkspaceKeyFormat int                         `json:"workspace_key_format"`
	WorkspaceKeySHA256 string                      `json:"workspace_key_sha256"`
	TeamID             string                      `json:"team_id"`
	CanonicalTeamID    string                      `json:"canonical_team_id"`
	Identity           workspaceTeamEnrollIdentity `json:"identity"`
	Proof              workspaceTeamEnrollProof    `json:"proof"`
}

type workspaceTeamEnrollIdentity struct {
	Alias         string `json:"alias"`
	HumanName     string `json:"human_name,omitempty"`
	AgentType     string `json:"agent_type"`
	DID           string `json:"did"`
	PublicKey     string `json:"public_key,omitempty"`
	StableID      string `json:"stable_id,omitempty"`
	IdentityScope string `json:"identity_scope"`
	Custody       string `json:"custody"`
}

type workspaceTeamEnrollProof struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type workspaceTeamEnrollResponse struct {
	State               string                      `json:"state"`
	TeamID              string                      `json:"team_id"`
	CanonicalTeamID     string                      `json:"canonical_team_id"`
	IdentityID          string                      `json:"identity_id"`
	AgentID             string                      `json:"agent_id"`
	Alias               string                      `json:"alias"`
	DID                 string                      `json:"did"`
	StableID            string                      `json:"stable_id"`
	IdentityScope       string                      `json:"identity_scope"`
	Created             bool                        `json:"created"`
	APIKey              string                      `json:"api_key,omitempty"`
	APIKeyCreated       bool                        `json:"api_key_created"`
	TeamCert            string                      `json:"team_cert"`
	SpawnAuthorityCheck *workspaceTeamSpawnAdvisory `json:"spawn_authority_check,omitempty"`
}

type workspaceTeamSpawnAdvisory struct {
	TeamID   string `json:"team_id"`
	CanSpawn bool   `json:"can_spawn"`
}

type teamEnsureOutput struct {
	Status          string `json:"status"`
	TeamID          string `json:"team_id"`
	CanonicalTeamID string `json:"canonical_team_id,omitempty"`
	IdentityHome    string `json:"identity_home"`
	IdentityScope   string `json:"identity_scope"`
	DID             string `json:"did"`
	StableID        string `json:"stable_id,omitempty"`
	Alias           string `json:"alias,omitempty"`
	Created         bool   `json:"created"`
	Reused          bool   `json:"reused"`
	CanSpawn        bool   `json:"can_spawn"`
	ActorAgentID    string `json:"actor_agent_id,omitempty"`
	AuthKind        string `json:"auth_kind,omitempty"`
}

type workspaceTeamPartialState struct {
	Version            int    `yaml:"version"`
	Issuer             string `yaml:"issuer"`
	WorkspaceKeySHA256 string `yaml:"workspace_key_sha256"`
	Alias              string `yaml:"alias"`
	DIDKey             string `yaml:"did_key"`
	StableID           string `yaml:"stable_id"`
	SigningKeyB64      string `yaml:"signing_key_b64"`
	CreatedAt          string `yaml:"created_at"`
}

type workspaceTeamBindingState struct {
	Version            int    `yaml:"version"`
	Issuer             string `yaml:"issuer"`
	WorkspaceKeySHA256 string `yaml:"workspace_key_sha256"`
	TeamID             string `yaml:"team_id"`
	CanonicalTeamID    string `yaml:"canonical_team_id,omitempty"`
	BoundAt            string `yaml:"bound_at"`
}

type workspaceTeamIdentityMaterial struct {
	PublicKey      ed25519.PublicKey
	SigningKey     ed25519.PrivateKey
	DIDKey         string
	StableID       string
	IdentityScope  string
	Alias          string
	ExistingGlobal bool
	Partial        bool
}

func init() {
	teamEnsureCmd.Flags().StringVar(&teamEnsureWorkspaceKey, "workspace-key", "", "OATS canonical format-1 workspace key")
	teamEnsureCmd.Flags().StringVar(&teamEnsureLabel, "label", "", "Optional display label for the workspace's default team")
	teamEnsureCmd.GroupID = teamGroupMembership
	teamHumanCmd.AddCommand(teamEnsureCmd)
}

func runTeamEnsure(ctx context.Context, cmd *cobra.Command) error {
	loadDotenvBestEffort()
	workingDir, err := os.Getwd()
	if err != nil {
		return err
	}
	home, err := identityHomeForDir(workingDir)
	if err != nil {
		return err
	}
	if !home.External() {
		return usageError("aw team ensure requires explicit --identity-home selecting the credential root to install")
	}
	workspaceDigest, err := workspaceTeamDigest(teamEnsureWorkspaceKey)
	if err != nil {
		return err
	}
	cfg, err := requireCLIAuthForTeamEnsure(ctx)
	if err != nil {
		return err
	}
	ensure, err := postWorkspaceTeamEnsure(ctx, cfg, workspaceTeamEnsureRequest{
		WorkspaceKeyFormat: workspaceTeamKeyFormat,
		WorkspaceKeySHA256: workspaceDigest,
		Label:              strings.TrimSpace(teamEnsureLabel),
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(ensure.TeamID) == "" {
		return fmt.Errorf("team ensure response missing team_id")
	}
	if strings.TrimSpace(ensure.CanonicalTeamID) == "" {
		return fmt.Errorf("team ensure response missing canonical_team_id")
	}
	material, err := prepareWorkspaceTeamIdentityMaterial(workingDir, home.Root, cfg.Issuer, workspaceDigest, strings.TrimSpace(teamEnsureLabel), ensure)
	if err != nil {
		return err
	}
	enroll, err := postWorkspaceTeamEnroll(ctx, cfg, ensure, workspaceDigest, material)
	if err != nil {
		return err
	}
	cert, err := decodeWorkspaceTeamTeamCert(enroll.TeamCert)
	if err != nil {
		return err
	}
	if strings.TrimSpace(enroll.TeamID) != strings.TrimSpace(ensure.TeamID) {
		return fmt.Errorf("team ensure enroll response team_id %q does not match ensured team_id %q", enroll.TeamID, ensure.TeamID)
	}
	if strings.TrimSpace(enroll.CanonicalTeamID) == "" {
		return fmt.Errorf("team ensure enroll response missing canonical_team_id")
	}
	if strings.TrimSpace(enroll.CanonicalTeamID) != strings.TrimSpace(ensure.CanonicalTeamID) {
		return fmt.Errorf("team ensure enroll response canonical_team_id %q does not match ensured canonical_team_id %q", enroll.CanonicalTeamID, ensure.CanonicalTeamID)
	}
	if strings.TrimSpace(cert.Team) != strings.TrimSpace(enroll.CanonicalTeamID) {
		return fmt.Errorf("team ensure enroll response certificate team_id %q does not match response canonical_team_id %q", cert.Team, enroll.CanonicalTeamID)
	}
	if got := strings.TrimSpace(enroll.DID); got != "" && got != material.DIDKey {
		return fmt.Errorf("team ensure enroll response did %q does not match local did %q", got, material.DIDKey)
	}
	if strings.TrimSpace(enroll.APIKey) != "" || enroll.APIKeyCreated {
		return fmt.Errorf("team ensure enroll response returned an API key; this client path requires cert-authenticated retryable enrollment")
	}
	if err := installWorkspaceTeamEnrollment(workingDir, home.Root, cfg.Issuer, material, enroll, cert); err != nil {
		return err
	}
	spawn, err := verifyWorkspaceTeamSpawnAuthority(ctx, workingDir, home.Root, enroll.TeamID)
	if err != nil {
		return err
	}
	if err := saveWorkspaceTeamBindingMarker(home.Root, workspaceTeamBindingState{Version: workspaceTeamPartialVersion, Issuer: cfg.Issuer, WorkspaceKeySHA256: workspaceDigest, TeamID: enroll.TeamID, CanonicalTeamID: enroll.CanonicalTeamID, BoundAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		return err
	}
	if err := removeWorkspaceTeamPartial(home.Root); err != nil {
		return fmt.Errorf("remove partial team ensure state: %w", err)
	}
	out := teamEnsureOutput{
		Status:          "bound",
		TeamID:          enroll.TeamID,
		CanonicalTeamID: enroll.CanonicalTeamID,
		IdentityHome:    home.Root,
		IdentityScope:   material.IdentityScope,
		DID:             material.DIDKey,
		StableID:        firstNonEmptyString(enroll.StableID, material.StableID),
		Alias:           firstNonEmptyString(enroll.Alias, material.Alias),
		Created:         enroll.Created,
		Reused:          !enroll.Created,
		CanSpawn:        spawn.CanSpawn,
		ActorAgentID:    spawn.ActorAgentID,
		AuthKind:        spawn.AuthKind,
	}
	if jsonFlag {
		return json.NewEncoder(cmd.OutOrStdout()).Encode(out)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "status: %s\nteam_id: %s\nidentity_home: %s\ndid: %s\ncan_spawn: %t\n", out.Status, out.TeamID, out.IdentityHome, out.DID, out.CanSpawn)
	return nil
}

func workspaceTeamDigest(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", usageError("--workspace-key is required")
	}
	if strings.HasPrefix(key, "local/") {
		return "", usageError("workspace-key-not-portable: local workspace keys cannot be used for hosted default team ensure")
	}
	sum := sha256.Sum256([]byte(key))
	return hex.EncodeToString(sum[:]), nil
}

func requireCLIAuthForTeamEnsure(ctx context.Context) (cliAuthConfig, error) {
	cfg, ok, err := loadCLIAuthConfig()
	if err != nil {
		return cliAuthConfig{}, err
	}
	if !ok || strings.TrimSpace(cfg.AccessToken) == "" {
		return cliAuthConfig{}, usageError("authorization-required: run `aw auth login` before `aw team ensure`")
	}
	if cfg.ClientID != cliAuthClientID || strings.TrimSpace(cfg.Issuer) == "" || strings.TrimSpace(cfg.Resource) == "" {
		return cliAuthConfig{}, usageError("authorization-required: stored CLI auth is invalid; run `aw auth login`")
	}
	if err := validateStoredCLIAuthAudience(cfg, cliAuthScope); err != nil {
		return cliAuthConfig{}, err
	}
	if time.Now().UTC().After(cfg.ExpiresAt) {
		refreshed, refreshErr := refreshCLIAuthToken(ctx, cfg)
		if refreshErr != nil {
			return cliAuthConfig{}, usageError("authorization-required: stored CLI auth is expired or revoked; run `aw auth login`")
		}
		cfg = refreshed
		if err := saveCLIAuthConfig(cfg); err != nil {
			return cliAuthConfig{}, err
		}
	}
	status, err := requestCLIAuthServerStatus(ctx, cfg)
	if err != nil {
		if diagnostic, ok := workspaceTeamUnsupportedServerDiagnostic("CLI auth status", "/api/v1/cli-auth/status", err); ok {
			return cliAuthConfig{}, diagnostic
		}
		return cliAuthConfig{}, usageError("authorization-required: stored CLI auth is not authorized; run `aw auth login`")
	}
	if strings.TrimSpace(status.Status) != "" && strings.TrimSpace(status.Status) != "authorized" {
		return cliAuthConfig{}, usageError("authorization-required: stored CLI auth status is %s; run `aw auth login`", status.Status)
	}
	return cfg, nil
}

func postWorkspaceTeamEnsure(ctx context.Context, cfg cliAuthConfig, req workspaceTeamEnsureRequest) (*workspaceTeamEnsureResponse, error) {
	var out workspaceTeamEnsureResponse
	if err := postCLIAuthJSON(ctx, cfg.Issuer, workspaceTeamEnsurePath, cfg.AccessToken, req, &out); err != nil {
		return nil, workspaceTeamEnsureEndpointError("workspace's default team ensure", workspaceTeamEnsurePath, err)
	}
	return &out, nil
}

func postWorkspaceTeamEnroll(ctx context.Context, cfg cliAuthConfig, ensure *workspaceTeamEnsureResponse, digest string, material workspaceTeamIdentityMaterial) (*workspaceTeamEnrollResponse, error) {
	timestamp := time.Now().UTC().Format(time.RFC3339)
	issuerAud, err := cliAuthIssuerAudience(cfg.Issuer)
	if err != nil {
		return nil, err
	}
	stableID := ""
	if material.IdentityScope == awid.IdentityModeGlobal {
		stableID = material.StableID
	}
	payload := map[string]any{
		"operation":            workspaceTeamEnrollOperation,
		"aud":                  issuerAud,
		"method":               http.MethodPost,
		"path":                 workspaceTeamEnrollPath,
		"workspace_key_format": workspaceTeamKeyFormat,
		"workspace_key_sha256": digest,
		"team_id":              strings.TrimSpace(ensure.TeamID),
		"canonical_team_id":    strings.TrimSpace(ensure.CanonicalTeamID),
		"did":                  material.DIDKey,
		"stable_id":            stableID,
		"identity_scope":       material.IdentityScope,
		"alias":                material.Alias,
	}
	_, signature, _, err := awid.SignArbitraryPayload(material.SigningKey, payload, timestamp)
	if err != nil {
		return nil, err
	}
	req := workspaceTeamEnrollRequest{
		WorkspaceKeyFormat: workspaceTeamKeyFormat,
		WorkspaceKeySHA256: digest,
		TeamID:             strings.TrimSpace(ensure.TeamID),
		CanonicalTeamID:    strings.TrimSpace(ensure.CanonicalTeamID),
		Identity: workspaceTeamEnrollIdentity{
			Alias:         material.Alias,
			AgentType:     "agent",
			DID:           material.DIDKey,
			StableID:      stableID,
			IdentityScope: material.IdentityScope,
			Custody:       awid.CustodySelf,
		},
		Proof: workspaceTeamEnrollProof{Type: "didkey-intent-v1", Timestamp: timestamp, Signature: signature},
	}
	var out workspaceTeamEnrollResponse
	if err := postCLIAuthJSON(ctx, cfg.Issuer, workspaceTeamEnrollPath, cfg.AccessToken, req, &out); err != nil {
		return nil, workspaceTeamEnsureEndpointError("workspace's default team enroll", workspaceTeamEnrollPath, err)
	}
	return &out, nil
}

func workspaceTeamEnsureEndpointError(feature, path string, err error) error {
	if diagnostic, ok := workspaceTeamUnsupportedServerDiagnostic(feature, path, err); ok {
		return diagnostic
	}
	return err
}

func workspaceTeamUnsupportedServerDiagnostic(feature, path string, err error) (error, bool) {
	if statusCode, ok := cliAuthHTTPStatusCode(err); ok && statusCode == http.StatusNotFound {
		return usageError("unsupported-server: aweb service does not support %s (%s); upgrade the aweb/cloud server and retry", feature, path), true
	}
	return nil, false
}

func cliAuthHTTPStatusCode(err error) (int, bool) {
	var httpErr *cliAuthHTTPStatusError
	if errors.As(err, &httpErr) {
		return httpErr.StatusCode, true
	}
	return awid.HTTPStatusCode(err)
}

func postCLIAuthJSON(ctx context.Context, issuer, path, bearer string, in any, out any) error {
	body, err := json.Marshal(in)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(issuer, "/")+path, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if strings.TrimSpace(bearer) != "" {
		req.Header.Set("Authorization", "Bearer "+strings.TrimSpace(bearer))
	}
	return doCLIAuthJSON(req, out)
}

func cliAuthIssuerAudience(issuer string) (string, error) {
	parsed, err := url.Parse(strings.TrimSpace(issuer))
	if err != nil {
		return "", err
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid auth issuer %q", issuer)
	}
	return parsed.Scheme + "://" + parsed.Host, nil
}

func prepareWorkspaceTeamIdentityMaterial(workingDir, identityHome, issuer, digest, label string, ensure *workspaceTeamEnsureResponse) (workspaceTeamIdentityMaterial, error) {
	if identity, err := awconfig.ResolveIdentityFromHome(workingDir, identityHome); err == nil {
		if awid.NormalizeIdentityScope(identity.IdentityScope) != awid.IdentityModeGlobal {
			return workspaceTeamIdentityMaterial{}, usageError("identity-home-occupied: existing identity.yaml in %s is not an explicit global identity", identityHome)
		}
		signingKey, err := awid.LoadSigningKey(identity.SigningKeyPath)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, fmt.Errorf("load global identity signing key: %w", err)
		}
		pub := signingKey.Public().(ed25519.PublicKey)
		didKey := awid.ComputeDIDKey(pub)
		if didKey != strings.TrimSpace(identity.DID) {
			return workspaceTeamIdentityMaterial{}, usageError("current signing key did:key %s does not match identity.yaml did %s", didKey, identity.DID)
		}
		stableID := strings.TrimSpace(identity.StableID)
		if stableID == "" {
			return workspaceTeamIdentityMaterial{}, usageError("explicit global identity is missing stable_id")
		}
		return workspaceTeamIdentityMaterial{PublicKey: pub, SigningKey: signingKey, DIDKey: didKey, StableID: stableID, IdentityScope: awid.IdentityModeGlobal, Alias: workspaceTeamAlias(label), ExistingGlobal: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return workspaceTeamIdentityMaterial{}, err
	}

	partialPath, partial, err := loadWorkspaceTeamPartial(identityHome)
	if err != nil {
		return workspaceTeamIdentityMaterial{}, err
	}
	if partial != nil {
		if partial.Issuer != strings.TrimSpace(issuer) || partial.WorkspaceKeySHA256 != strings.TrimSpace(digest) {
			return workspaceTeamIdentityMaterial{}, usageError("identity-home-occupied: partial team ensure state at %s belongs to another issuer or workspace", partialPath)
		}
		material, err := materialFromWorkspaceTeamPartial(partialPath, partial)
		if err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		material.Partial = true
		return material, nil
	}

	signingPath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "signing.key")
	if err != nil {
		return workspaceTeamIdentityMaterial{}, err
	}
	if signingKey, err := awid.LoadSigningKey(signingPath); err == nil {
		if err := validateWorkspaceTeamExistingLocalRoot(identityHome, issuer, digest, ensure); err != nil {
			return workspaceTeamIdentityMaterial{}, err
		}
		pub := signingKey.Public().(ed25519.PublicKey)
		return workspaceTeamIdentityMaterial{PublicKey: pub, SigningKey: signingKey, DIDKey: awid.ComputeDIDKey(pub), StableID: "", IdentityScope: awid.IdentityModeLocal, Alias: workspaceTeamAlias(label)}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return workspaceTeamIdentityMaterial{}, err
	}

	if occupied, err := identityHomeHasUnexpectedFiles(identityHome); err != nil {
		return workspaceTeamIdentityMaterial{}, err
	} else if occupied {
		return workspaceTeamIdentityMaterial{}, usageError("identity-home-occupied: %s is not empty", identityHome)
	}
	generated, err := generateAPIKeyBootstrapIdentity()
	if err != nil {
		return workspaceTeamIdentityMaterial{}, err
	}
	partial = &workspaceTeamPartialState{
		Version:            workspaceTeamPartialVersion,
		Issuer:             strings.TrimSpace(issuer),
		WorkspaceKeySHA256: strings.TrimSpace(digest),
		Alias:              workspaceTeamAlias(label),
		DIDKey:             generated.DIDKey,
		StableID:           generated.StableID,
		SigningKeyB64:      base64.StdEncoding.EncodeToString([]byte(generated.SigningKey)),
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	if err := saveWorkspaceTeamPartial(identityHome, partial); err != nil {
		return workspaceTeamIdentityMaterial{}, err
	}
	return workspaceTeamIdentityMaterial{PublicKey: generated.PublicKey, SigningKey: generated.SigningKey, DIDKey: generated.DIDKey, StableID: "", IdentityScope: awid.IdentityModeLocal, Alias: partial.Alias, Partial: true}, nil
}

func validateWorkspaceTeamExistingLocalRoot(identityHome, issuer, digest string, ensure *workspaceTeamEnsureResponse) error {
	binding, err := loadWorkspaceTeamBindingMarker(identityHome)
	if err != nil {
		return err
	}
	if binding == nil {
		return usageError("identity-home-occupied: %s already contains local identity material without workspace's default team binding state", identityHome)
	}
	if strings.TrimSpace(binding.Issuer) != strings.TrimSpace(issuer) || strings.TrimSpace(binding.WorkspaceKeySHA256) != strings.TrimSpace(digest) || strings.TrimSpace(binding.TeamID) != strings.TrimSpace(ensure.TeamID) || strings.TrimSpace(binding.CanonicalTeamID) != strings.TrimSpace(ensure.CanonicalTeamID) {
		return usageError("identity-home-occupied: %s is already bound to a different workspace's default team", identityHome)
	}
	teamState, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
	if err != nil {
		return usageError("identity-home-occupied: %s already contains local identity material without loadable team state", identityHome)
	}
	membership := teamState.Membership(strings.TrimSpace(ensure.CanonicalTeamID))
	if membership == nil {
		return usageError("identity-home-occupied: %s workspace's default team binding has no matching team membership", identityHome)
	}
	return nil
}

func workspaceTeamAlias(label string) string {
	candidate := strings.TrimSpace(label)
	if candidate == "" {
		return "workspace"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(candidate) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "workspace"
	}
	return b.String()
}

func workspaceTeamPartialPath(identityHome string) (string, error) {
	return awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "workspace-team-ensure.yaml")
}

func loadWorkspaceTeamPartial(identityHome string) (string, *workspaceTeamPartialState, error) {
	path, err := workspaceTeamPartialPath(identityHome)
	if err != nil {
		return "", nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return path, nil, nil
	}
	if err != nil {
		return path, nil, err
	}
	var state workspaceTeamPartialState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return path, nil, fmt.Errorf("read partial team ensure state %s: %w", path, err)
	}
	if state.Version != workspaceTeamPartialVersion {
		return path, nil, usageError("partial team ensure state at %s has unsupported version %d", path, state.Version)
	}
	return path, &state, nil
}

func saveWorkspaceTeamPartial(identityHome string, state *workspaceTeamPartialState) error {
	path, err := workspaceTeamPartialPath(identityHome)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, data)
}

func removeWorkspaceTeamPartial(identityHome string) error {
	path, err := workspaceTeamPartialPath(identityHome)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func workspaceTeamBindingPath(identityHome string) (string, error) {
	return awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "workspace-team-binding.yaml")
}

func loadWorkspaceTeamBindingMarker(identityHome string) (*workspaceTeamBindingState, error) {
	path, err := workspaceTeamBindingPath(identityHome)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var state workspaceTeamBindingState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read workspace's default team binding state %s: %w", path, err)
	}
	if state.Version != workspaceTeamPartialVersion {
		return nil, usageError("workspace's default team binding state at %s has unsupported version %d", path, state.Version)
	}
	return &state, nil
}

func saveWorkspaceTeamBindingMarker(identityHome string, state workspaceTeamBindingState) error {
	path, err := workspaceTeamBindingPath(identityHome)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(&state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, data)
}

func materialFromWorkspaceTeamPartial(path string, state *workspaceTeamPartialState) (workspaceTeamIdentityMaterial, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(state.SigningKeyB64))
	if err != nil {
		return workspaceTeamIdentityMaterial{}, fmt.Errorf("decode partial team ensure signing key from %s: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return workspaceTeamIdentityMaterial{}, fmt.Errorf("partial team ensure state %s has invalid signing key size %d", path, len(raw))
	}
	signingKey := ed25519.PrivateKey(raw)
	pub := signingKey.Public().(ed25519.PublicKey)
	didKey := awid.ComputeDIDKey(pub)
	if didKey != strings.TrimSpace(state.DIDKey) {
		return workspaceTeamIdentityMaterial{}, fmt.Errorf("partial team ensure state %s did_key does not match signing key", path)
	}
	return workspaceTeamIdentityMaterial{PublicKey: pub, SigningKey: signingKey, DIDKey: didKey, StableID: "", IdentityScope: awid.IdentityModeLocal, Alias: workspaceTeamAlias(state.Alias)}, nil
}

func identityHomeHasUnexpectedFiles(identityHome string) (bool, error) {
	entries, err := os.ReadDir(identityHome)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.Name() == "." || entry.Name() == ".." {
			continue
		}
		return true, nil
	}
	return false, nil
}

func decodeWorkspaceTeamTeamCert(encoded string) (*awid.TeamCertificate, error) {
	encoded = strings.TrimSpace(encoded)
	if encoded == "" {
		return nil, fmt.Errorf("team ensure enroll response missing team_cert")
	}
	cert, err := awid.DecodeTeamCertificateHeader(encoded)
	if err == nil {
		return cert, nil
	}
	var raw awid.TeamCertificate
	if jsonErr := json.Unmarshal([]byte(encoded), &raw); jsonErr == nil && strings.TrimSpace(raw.Team) != "" {
		return &raw, nil
	}
	return nil, fmt.Errorf("decode team ensure team_cert: %w", err)
}

func installWorkspaceTeamEnrollment(workingDir, identityHome, issuer string, material workspaceTeamIdentityMaterial, enroll *workspaceTeamEnrollResponse, cert *awid.TeamCertificate) error {
	if err := persistLocalSigningKeyAndCertificateAt(workingDir, identityHome, material.SigningKey, cert); err != nil {
		return err
	}
	if material.IdentityScope == awid.IdentityModeGlobal {
		identityPath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "identity.yaml")
		if err != nil {
			return err
		}
		stableID := firstNonEmptyString(enroll.StableID, material.StableID)
		if err := awconfig.SaveWorktreeIdentityTo(identityPath, &awconfig.WorktreeIdentity{DID: material.DIDKey, StableID: stableID, Address: strings.TrimSpace(cert.MemberAddress), Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryStatus: "registered", CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
			return err
		}
	}
	canonicalTeamID := strings.TrimSpace(enroll.CanonicalTeamID)
	output := &teamAcceptInviteOutput{Status: "accepted", TeamID: canonicalTeamID, Alias: firstNonEmptyString(enroll.Alias, material.Alias), CertPath: awconfig.TeamCertificateRelativePath(canonicalTeamID), AwebURL: strings.TrimRight(issuer, "/")}
	if err := recordAcceptedTeamMembership(workingDir, output, cert, "", strings.TrimRight(issuer, "/"), recordMembershipOptions{IdentityHome: explicitEncryptionKeyIdentityHome(identityHome), SetActive: true, WriteWorkspaceBinding: false}); err != nil {
		return err
	}
	return saveWorkspaceTeamBinding(identityHome, output, cert, strings.TrimRight(issuer, "/"))
}

func saveWorkspaceTeamBinding(identityHome string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, awebURL string) error {
	workspacePath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "workspace.yaml")
	if err != nil {
		return err
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(workspacePath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if workspace == nil {
		workspace = &awconfig.WorktreeWorkspace{}
	}
	workspace.AwebURL = strings.TrimSpace(awebURL)
	workspace.WorkspacePath = identityHome
	workspace.UpdatedAt = time.Now().UTC().Format(time.RFC3339)
	upsertWorkspaceMembershipCache(workspace, awconfig.WorktreeMembership{TeamID: strings.TrimSpace(output.TeamID), Alias: strings.TrimSpace(output.Alias), CertPath: filepath.ToSlash(strings.TrimSpace(output.CertPath)), JoinedAt: strings.TrimSpace(cert.IssuedAt)})
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		return err
	}
	recordMachineWorkspaceBestEffort(awconfig.MachineWorkspaceIndexEntry{
		Path:      workspace.WorkspacePath,
		TeamID:    strings.TrimSpace(output.TeamID),
		Alias:     strings.TrimSpace(output.Alias),
		ServerURL: strings.TrimSpace(awebURL),
	})
	return nil
}

func verifyWorkspaceTeamSpawnAuthority(ctx context.Context, workingDir, identityHome, teamID string) (*teamSpawnAuthorityOutput, error) {
	client, sel, err := resolveClientSelectionForDir(workingDir)
	if err != nil {
		return nil, fmt.Errorf("resolve installed identity for spawn authority: %w", err)
	}
	if sel == nil || strings.TrimSpace(sel.TeamID) == "" {
		return nil, fmt.Errorf("installed identity has no selected team for spawn authority")
	}
	path := "/api/v1/spawn/authority?team_id=" + url.QueryEscape(strings.TrimSpace(teamID))
	var out teamSpawnAuthorityOutput
	if err := client.Get(ctx, path, &out); err != nil {
		return nil, workspaceTeamEnsureEndpointError("installed-root spawn authority proof", "/api/v1/spawn/authority", err)
	}
	if strings.TrimSpace(out.TeamID) != strings.TrimSpace(teamID) {
		return nil, fmt.Errorf("spawn authority team_id %q does not match ensured team %q", out.TeamID, teamID)
	}
	if !out.CanSpawn {
		return nil, fmt.Errorf("spawn authority denied for team %s", teamID)
	}
	return &out, nil
}
