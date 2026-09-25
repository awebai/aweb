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
	personalWorkspaceKeyFormat       = 1
	personalWorkspaceEnsurePath      = "/api/v1/teams/personal-workspace/ensure"
	personalWorkspaceEnrollPath      = "/api/v1/teams/personal-workspace/enroll"
	personalWorkspaceEnrollOperation = "personal_workspace_member_enroll.v1"
	personalWorkspacePartialVersion  = 1
)

var (
	teamEnsureWorkspaceKey string
	teamEnsureLabel        string
)

var teamEnsureCmd = &cobra.Command{
	Use:   "ensure --workspace-key <canonical-key>",
	Short: "Ensure this host has a personal workspace team authority",
	Long: "Ensure this host has a personal workspace team authority.\n\n" +
		"The server receives only the format-1 workspace-key digest. Credentials are installed\n" +
		"only into the explicit --identity-home credential root, and the result is bound only\n" +
		"after a live spawn-authority proof from that installed root.\n\n" +
		"Stable diagnostics are printed to stderr and exit 2, including with --json; there is\n" +
		"no JSON error envelope. authorization-required means host CLI auth is missing,\n" +
		"invalid, expired, revoked, or not authorized. workspace-key-not-portable means a\n" +
		"local/ workspace key cannot be used for hosted personal team ensure.\n" +
		"identity-home-occupied means the explicit identity home already contains\n" +
		"conflicting identity, team, workspace, or binding state. unsupported-server means\n" +
		"the aweb service is older than the personal ensure/enroll contract (Cloud 0.8.12\n" +
		"or later) and is missing one of: CLI auth status, personal workspace ensure,\n" +
		"personal workspace enroll, or installed-root spawn-authority proof. Non-404\n" +
		"server errors keep their existing handling.",
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		return runTeamEnsure(cmd.Context(), cmd)
	},
}

type personalWorkspaceEnsureRequest struct {
	WorkspaceKeyFormat int    `json:"workspace_key_format"`
	WorkspaceKeySHA256 string `json:"workspace_key_sha256"`
	Label              string `json:"label,omitempty"`
	ExpectedTeamID     string `json:"expected_team_id,omitempty"`
}

type personalWorkspaceEnsureResponse struct {
	State           string         `json:"state"`
	TeamID          string         `json:"team_id"`
	CanonicalTeamID string         `json:"canonical_team_id"`
	Label           string         `json:"label,omitempty"`
	LabelSource     string         `json:"label_source,omitempty"`
	Owner           map[string]any `json:"owner,omitempty"`
	Binding         map[string]any `json:"binding,omitempty"`
}

type personalWorkspaceEnrollRequest struct {
	WorkspaceKeyFormat int                             `json:"workspace_key_format"`
	WorkspaceKeySHA256 string                          `json:"workspace_key_sha256"`
	TeamID             string                          `json:"team_id"`
	CanonicalTeamID    string                          `json:"canonical_team_id"`
	Identity           personalWorkspaceEnrollIdentity `json:"identity"`
	Proof              personalWorkspaceEnrollProof    `json:"proof"`
}

type personalWorkspaceEnrollIdentity struct {
	Alias         string `json:"alias"`
	HumanName     string `json:"human_name,omitempty"`
	AgentType     string `json:"agent_type"`
	DID           string `json:"did"`
	PublicKey     string `json:"public_key,omitempty"`
	StableID      string `json:"stable_id,omitempty"`
	IdentityScope string `json:"identity_scope"`
	Custody       string `json:"custody"`
}

type personalWorkspaceEnrollProof struct {
	Type      string `json:"type"`
	Timestamp string `json:"timestamp"`
	Signature string `json:"signature"`
}

type personalWorkspaceEnrollResponse struct {
	State               string                          `json:"state"`
	TeamID              string                          `json:"team_id"`
	CanonicalTeamID     string                          `json:"canonical_team_id"`
	IdentityID          string                          `json:"identity_id"`
	AgentID             string                          `json:"agent_id"`
	Alias               string                          `json:"alias"`
	DID                 string                          `json:"did"`
	StableID            string                          `json:"stable_id"`
	IdentityScope       string                          `json:"identity_scope"`
	Created             bool                            `json:"created"`
	APIKey              string                          `json:"api_key,omitempty"`
	APIKeyCreated       bool                            `json:"api_key_created"`
	TeamCert            string                          `json:"team_cert"`
	SpawnAuthorityCheck *personalWorkspaceSpawnAdvisory `json:"spawn_authority_check,omitempty"`
}

type personalWorkspaceSpawnAdvisory struct {
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

type personalWorkspacePartialState struct {
	Version            int    `yaml:"version"`
	Issuer             string `yaml:"issuer"`
	WorkspaceKeySHA256 string `yaml:"workspace_key_sha256"`
	Alias              string `yaml:"alias"`
	DIDKey             string `yaml:"did_key"`
	StableID           string `yaml:"stable_id"`
	SigningKeyB64      string `yaml:"signing_key_b64"`
	CreatedAt          string `yaml:"created_at"`
}

type personalWorkspaceBindingState struct {
	Version            int    `yaml:"version"`
	Issuer             string `yaml:"issuer"`
	WorkspaceKeySHA256 string `yaml:"workspace_key_sha256"`
	TeamID             string `yaml:"team_id"`
	CanonicalTeamID    string `yaml:"canonical_team_id,omitempty"`
	BoundAt            string `yaml:"bound_at"`
}

type personalWorkspaceIdentityMaterial struct {
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
	teamEnsureCmd.Flags().StringVar(&teamEnsureLabel, "label", "", "Optional display label for the personal workspace team")
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
	workspaceDigest, err := personalWorkspaceDigest(teamEnsureWorkspaceKey)
	if err != nil {
		return err
	}
	cfg, err := requireCLIAuthForTeamEnsure(ctx)
	if err != nil {
		return err
	}
	ensure, err := postPersonalWorkspaceEnsure(ctx, cfg, personalWorkspaceEnsureRequest{
		WorkspaceKeyFormat: personalWorkspaceKeyFormat,
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
	material, err := preparePersonalWorkspaceIdentityMaterial(workingDir, home.Root, cfg.Issuer, workspaceDigest, strings.TrimSpace(teamEnsureLabel), ensure)
	if err != nil {
		return err
	}
	enroll, err := postPersonalWorkspaceEnroll(ctx, cfg, ensure, workspaceDigest, material)
	if err != nil {
		return err
	}
	cert, err := decodePersonalWorkspaceTeamCert(enroll.TeamCert)
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
	if err := installPersonalWorkspaceEnrollment(workingDir, home.Root, cfg.Issuer, material, enroll, cert); err != nil {
		return err
	}
	spawn, err := verifyPersonalWorkspaceSpawnAuthority(ctx, workingDir, home.Root, enroll.TeamID)
	if err != nil {
		return err
	}
	if err := savePersonalWorkspaceBindingMarker(home.Root, personalWorkspaceBindingState{Version: personalWorkspacePartialVersion, Issuer: cfg.Issuer, WorkspaceKeySHA256: workspaceDigest, TeamID: enroll.TeamID, CanonicalTeamID: enroll.CanonicalTeamID, BoundAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		return err
	}
	if err := removePersonalWorkspacePartial(home.Root); err != nil {
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

func personalWorkspaceDigest(raw string) (string, error) {
	key := strings.TrimSpace(raw)
	if key == "" {
		return "", usageError("--workspace-key is required")
	}
	if strings.HasPrefix(key, "local/") {
		return "", usageError("workspace-key-not-portable: local workspace keys cannot be used for hosted personal team ensure")
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
		if diagnostic, ok := personalWorkspaceUnsupportedServerDiagnostic("CLI auth status", "/api/v1/cli-auth/status", err); ok {
			return cliAuthConfig{}, diagnostic
		}
		return cliAuthConfig{}, usageError("authorization-required: stored CLI auth is not authorized; run `aw auth login`")
	}
	if strings.TrimSpace(status.Status) != "" && strings.TrimSpace(status.Status) != "authorized" {
		return cliAuthConfig{}, usageError("authorization-required: stored CLI auth status is %s; run `aw auth login`", status.Status)
	}
	return cfg, nil
}

func postPersonalWorkspaceEnsure(ctx context.Context, cfg cliAuthConfig, req personalWorkspaceEnsureRequest) (*personalWorkspaceEnsureResponse, error) {
	var out personalWorkspaceEnsureResponse
	if err := postCLIAuthJSON(ctx, cfg.Issuer, personalWorkspaceEnsurePath, cfg.AccessToken, req, &out); err != nil {
		return nil, personalWorkspaceEnsureEndpointError("personal workspace ensure", personalWorkspaceEnsurePath, err)
	}
	return &out, nil
}

func postPersonalWorkspaceEnroll(ctx context.Context, cfg cliAuthConfig, ensure *personalWorkspaceEnsureResponse, digest string, material personalWorkspaceIdentityMaterial) (*personalWorkspaceEnrollResponse, error) {
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
		"operation":            personalWorkspaceEnrollOperation,
		"aud":                  issuerAud,
		"method":               http.MethodPost,
		"path":                 personalWorkspaceEnrollPath,
		"workspace_key_format": personalWorkspaceKeyFormat,
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
	req := personalWorkspaceEnrollRequest{
		WorkspaceKeyFormat: personalWorkspaceKeyFormat,
		WorkspaceKeySHA256: digest,
		TeamID:             strings.TrimSpace(ensure.TeamID),
		CanonicalTeamID:    strings.TrimSpace(ensure.CanonicalTeamID),
		Identity: personalWorkspaceEnrollIdentity{
			Alias:         material.Alias,
			AgentType:     "agent",
			DID:           material.DIDKey,
			StableID:      stableID,
			IdentityScope: material.IdentityScope,
			Custody:       awid.CustodySelf,
		},
		Proof: personalWorkspaceEnrollProof{Type: "didkey-intent-v1", Timestamp: timestamp, Signature: signature},
	}
	var out personalWorkspaceEnrollResponse
	if err := postCLIAuthJSON(ctx, cfg.Issuer, personalWorkspaceEnrollPath, cfg.AccessToken, req, &out); err != nil {
		return nil, personalWorkspaceEnsureEndpointError("personal workspace enroll", personalWorkspaceEnrollPath, err)
	}
	return &out, nil
}

func personalWorkspaceEnsureEndpointError(feature, path string, err error) error {
	if diagnostic, ok := personalWorkspaceUnsupportedServerDiagnostic(feature, path, err); ok {
		return diagnostic
	}
	return err
}

func personalWorkspaceUnsupportedServerDiagnostic(feature, path string, err error) (error, bool) {
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

func preparePersonalWorkspaceIdentityMaterial(workingDir, identityHome, issuer, digest, label string, ensure *personalWorkspaceEnsureResponse) (personalWorkspaceIdentityMaterial, error) {
	if identity, err := awconfig.ResolveIdentityFromHome(workingDir, identityHome); err == nil {
		if awid.NormalizeIdentityScope(identity.IdentityScope) != awid.IdentityModeGlobal {
			return personalWorkspaceIdentityMaterial{}, usageError("identity-home-occupied: existing identity.yaml in %s is not an explicit global identity", identityHome)
		}
		signingKey, err := awid.LoadSigningKey(identity.SigningKeyPath)
		if err != nil {
			return personalWorkspaceIdentityMaterial{}, fmt.Errorf("load global identity signing key: %w", err)
		}
		pub := signingKey.Public().(ed25519.PublicKey)
		didKey := awid.ComputeDIDKey(pub)
		if didKey != strings.TrimSpace(identity.DID) {
			return personalWorkspaceIdentityMaterial{}, usageError("current signing key did:key %s does not match identity.yaml did %s", didKey, identity.DID)
		}
		stableID := strings.TrimSpace(identity.StableID)
		if stableID == "" {
			return personalWorkspaceIdentityMaterial{}, usageError("explicit global identity is missing stable_id")
		}
		return personalWorkspaceIdentityMaterial{PublicKey: pub, SigningKey: signingKey, DIDKey: didKey, StableID: stableID, IdentityScope: awid.IdentityModeGlobal, Alias: personalWorkspaceAlias(label), ExistingGlobal: true}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return personalWorkspaceIdentityMaterial{}, err
	}

	partialPath, partial, err := loadPersonalWorkspacePartial(identityHome)
	if err != nil {
		return personalWorkspaceIdentityMaterial{}, err
	}
	if partial != nil {
		if partial.Issuer != strings.TrimSpace(issuer) || partial.WorkspaceKeySHA256 != strings.TrimSpace(digest) {
			return personalWorkspaceIdentityMaterial{}, usageError("identity-home-occupied: partial team ensure state at %s belongs to another issuer or workspace", partialPath)
		}
		material, err := materialFromPersonalWorkspacePartial(partialPath, partial)
		if err != nil {
			return personalWorkspaceIdentityMaterial{}, err
		}
		material.Partial = true
		return material, nil
	}

	signingPath, err := awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "signing.key")
	if err != nil {
		return personalWorkspaceIdentityMaterial{}, err
	}
	if signingKey, err := awid.LoadSigningKey(signingPath); err == nil {
		if err := validatePersonalWorkspaceExistingLocalRoot(identityHome, issuer, digest, ensure); err != nil {
			return personalWorkspaceIdentityMaterial{}, err
		}
		pub := signingKey.Public().(ed25519.PublicKey)
		return personalWorkspaceIdentityMaterial{PublicKey: pub, SigningKey: signingKey, DIDKey: awid.ComputeDIDKey(pub), StableID: "", IdentityScope: awid.IdentityModeLocal, Alias: personalWorkspaceAlias(label)}, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return personalWorkspaceIdentityMaterial{}, err
	}

	if occupied, err := identityHomeHasUnexpectedFiles(identityHome); err != nil {
		return personalWorkspaceIdentityMaterial{}, err
	} else if occupied {
		return personalWorkspaceIdentityMaterial{}, usageError("identity-home-occupied: %s is not empty", identityHome)
	}
	generated, err := generateAPIKeyBootstrapIdentity()
	if err != nil {
		return personalWorkspaceIdentityMaterial{}, err
	}
	partial = &personalWorkspacePartialState{
		Version:            personalWorkspacePartialVersion,
		Issuer:             strings.TrimSpace(issuer),
		WorkspaceKeySHA256: strings.TrimSpace(digest),
		Alias:              personalWorkspaceAlias(label),
		DIDKey:             generated.DIDKey,
		StableID:           generated.StableID,
		SigningKeyB64:      base64.StdEncoding.EncodeToString([]byte(generated.SigningKey)),
		CreatedAt:          time.Now().UTC().Format(time.RFC3339),
	}
	if err := savePersonalWorkspacePartial(identityHome, partial); err != nil {
		return personalWorkspaceIdentityMaterial{}, err
	}
	return personalWorkspaceIdentityMaterial{PublicKey: generated.PublicKey, SigningKey: generated.SigningKey, DIDKey: generated.DIDKey, StableID: "", IdentityScope: awid.IdentityModeLocal, Alias: partial.Alias, Partial: true}, nil
}

func validatePersonalWorkspaceExistingLocalRoot(identityHome, issuer, digest string, ensure *personalWorkspaceEnsureResponse) error {
	binding, err := loadPersonalWorkspaceBindingMarker(identityHome)
	if err != nil {
		return err
	}
	if binding == nil {
		return usageError("identity-home-occupied: %s already contains local identity material without personal workspace binding state", identityHome)
	}
	if strings.TrimSpace(binding.Issuer) != strings.TrimSpace(issuer) || strings.TrimSpace(binding.WorkspaceKeySHA256) != strings.TrimSpace(digest) || strings.TrimSpace(binding.TeamID) != strings.TrimSpace(ensure.TeamID) || strings.TrimSpace(binding.CanonicalTeamID) != strings.TrimSpace(ensure.CanonicalTeamID) {
		return usageError("identity-home-occupied: %s is already bound to a different personal workspace", identityHome)
	}
	teamState, err := awconfig.LoadTeamStateFromIdentityHome(identityHome)
	if err != nil {
		return usageError("identity-home-occupied: %s already contains local identity material without loadable team state", identityHome)
	}
	membership := teamState.Membership(strings.TrimSpace(ensure.CanonicalTeamID))
	if membership == nil {
		return usageError("identity-home-occupied: %s personal workspace binding has no matching team membership", identityHome)
	}
	return nil
}

func personalWorkspaceAlias(label string) string {
	candidate := strings.TrimSpace(label)
	if candidate == "" {
		return "personal"
	}
	var b strings.Builder
	for _, r := range strings.ToLower(candidate) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "personal"
	}
	return b.String()
}

func personalWorkspacePartialPath(identityHome string) (string, error) {
	return awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "personal-workspace-ensure.yaml")
}

func loadPersonalWorkspacePartial(identityHome string) (string, *personalWorkspacePartialState, error) {
	path, err := personalWorkspacePartialPath(identityHome)
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
	var state personalWorkspacePartialState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return path, nil, fmt.Errorf("read partial team ensure state %s: %w", path, err)
	}
	if state.Version != personalWorkspacePartialVersion {
		return path, nil, usageError("partial team ensure state at %s has unsupported version %d", path, state.Version)
	}
	return path, &state, nil
}

func savePersonalWorkspacePartial(identityHome string, state *personalWorkspacePartialState) error {
	path, err := personalWorkspacePartialPath(identityHome)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, data)
}

func removePersonalWorkspacePartial(identityHome string) error {
	path, err := personalWorkspacePartialPath(identityHome)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func personalWorkspaceBindingPath(identityHome string) (string, error) {
	return awconfig.IdentityHomePath(awconfig.IdentityHome{Root: identityHome}, "personal-workspace-binding.yaml")
}

func loadPersonalWorkspaceBindingMarker(identityHome string) (*personalWorkspaceBindingState, error) {
	path, err := personalWorkspaceBindingPath(identityHome)
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
	var state personalWorkspaceBindingState
	if err := yaml.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("read personal workspace binding state %s: %w", path, err)
	}
	if state.Version != personalWorkspacePartialVersion {
		return nil, usageError("personal workspace binding state at %s has unsupported version %d", path, state.Version)
	}
	return &state, nil
}

func savePersonalWorkspaceBindingMarker(identityHome string, state personalWorkspaceBindingState) error {
	path, err := personalWorkspaceBindingPath(identityHome)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(&state)
	if err != nil {
		return err
	}
	return awid.AtomicWriteFile(path, data)
}

func materialFromPersonalWorkspacePartial(path string, state *personalWorkspacePartialState) (personalWorkspaceIdentityMaterial, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(state.SigningKeyB64))
	if err != nil {
		return personalWorkspaceIdentityMaterial{}, fmt.Errorf("decode partial team ensure signing key from %s: %w", path, err)
	}
	if len(raw) != ed25519.PrivateKeySize {
		return personalWorkspaceIdentityMaterial{}, fmt.Errorf("partial team ensure state %s has invalid signing key size %d", path, len(raw))
	}
	signingKey := ed25519.PrivateKey(raw)
	pub := signingKey.Public().(ed25519.PublicKey)
	didKey := awid.ComputeDIDKey(pub)
	if didKey != strings.TrimSpace(state.DIDKey) {
		return personalWorkspaceIdentityMaterial{}, fmt.Errorf("partial team ensure state %s did_key does not match signing key", path)
	}
	return personalWorkspaceIdentityMaterial{PublicKey: pub, SigningKey: signingKey, DIDKey: didKey, StableID: "", IdentityScope: awid.IdentityModeLocal, Alias: personalWorkspaceAlias(state.Alias)}, nil
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

func decodePersonalWorkspaceTeamCert(encoded string) (*awid.TeamCertificate, error) {
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

func installPersonalWorkspaceEnrollment(workingDir, identityHome, issuer string, material personalWorkspaceIdentityMaterial, enroll *personalWorkspaceEnrollResponse, cert *awid.TeamCertificate) error {
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
	return savePersonalWorkspaceBinding(identityHome, output, cert, strings.TrimRight(issuer, "/"))
}

func savePersonalWorkspaceBinding(identityHome string, output *teamAcceptInviteOutput, cert *awid.TeamCertificate, awebURL string) error {
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
	return awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace)
}

func verifyPersonalWorkspaceSpawnAuthority(ctx context.Context, workingDir, identityHome, teamID string) (*teamSpawnAuthorityOutput, error) {
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
		return nil, personalWorkspaceEnsureEndpointError("installed-root spawn authority proof", "/api/v1/spawn/authority", err)
	}
	if strings.TrimSpace(out.TeamID) != strings.TrimSpace(teamID) {
		return nil, fmt.Errorf("spawn authority team_id %q does not match ensured team %q", out.TeamID, teamID)
	}
	if !out.CanSpawn {
		return nil, fmt.Errorf("spawn authority denied for team %s", teamID)
	}
	return &out, nil
}
