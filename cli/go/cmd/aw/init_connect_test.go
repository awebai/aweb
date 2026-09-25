package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestInitWithCertificateConnectsToServer(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := awid.ComputeDIDKey(memberPub)
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	// Sign a certificate for the member
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  memberDIDKey,
		Alias:         "alice",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotConnectPayload map[string]any
	var gotAuthHeader string
	var gotCertHeader string
	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": serverURL,
				"aweb_url":       serverURL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			gotAuthHeader = r.Header.Get("Authorization")
			gotCertHeader = r.Header.Get("X-AWID-Team-Certificate")
			if err := json.NewDecoder(r.Body).Decode(&gotConnectPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "backend:acme.com",
				"alias":        "alice",
				"agent_id":     "agent-uuid-1",
				"workspace_id": "ws-uuid-1",
				"repo_id":      "",
				"team_did_key": teamDIDKey,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			_ = json.NewEncoder(w).Encode(awid.PublishAgentEncryptionKeyResponse{
				AgentID: "agent-uuid-1",
				TeamID:  "backend:acme.com",
				Alias:   "alice",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Write identity
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           memberDIDKey,
		StableID:      awid.ComputeStableID(memberPub),
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-06T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}

	// Write team certificate
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, cert.Team, cert); err != nil {
		t.Fatal(err)
	}

	// Exercise the port-443 SSH form used when GitHub's port 22 is blocked.
	initGitRepoWithOrigin(t, tmp, "ssh://git@ssh.github.com:443/acme/backend.git")

	run := exec.CommandContext(ctx, bin, "init", "--url", server.URL, "--role", "developer", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if got["status"] != "connected" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["team_id"] != "backend:acme.com" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if got["alias"] != "alice" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if got["aweb_url"] != server.URL {
		t.Fatalf("aweb_url=%v", got["aweb_url"])
	}
	if _, ok := got["server_url"]; ok {
		t.Fatalf("unexpected legacy server_url in output: %v", got["server_url"])
	}
	if _, ok := got["lifetime"]; ok {
		t.Fatalf("unexpected legacy lifetime in output: %v", got["lifetime"])
	}
	if got["identity_scope"] != awid.IdentityModeGlobal {
		t.Fatalf("identity_scope=%v", got["identity_scope"])
	}

	// Verify DIDKey auth was used
	if !strings.HasPrefix(gotAuthHeader, "DIDKey ") {
		t.Fatalf("expected DIDKey auth, got %q", gotAuthHeader)
	}

	// Verify certificate was sent
	if gotCertHeader == "" {
		t.Fatal("X-AWID-Team-Certificate header missing")
	}
	decodedCert, err := awid.DecodeTeamCertificateHeader(gotCertHeader)
	if err != nil {
		t.Fatalf("decode cert header: %v", err)
	}
	if decodedCert.CertificateID != cert.CertificateID {
		t.Fatalf("cert id=%q want %q", decodedCert.CertificateID, cert.CertificateID)
	}

	// Verify workspace.yaml was written with team_id
	ws, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	activeMembership := activeMembershipForTest(t, ws)
	if activeMembership.TeamID != "backend:acme.com" {
		t.Fatalf("workspace team_id=%q", activeMembership.TeamID)
	}
	if activeMembership.Alias != "alice" {
		t.Fatalf("workspace alias=%q", activeMembership.Alias)
	}
	if ws.AwebURL != server.URL {
		t.Fatalf("workspace aweb_url=%q want %q", ws.AwebURL, server.URL)
	}
	if ws.CanonicalOrigin != "github.com/acme/backend" {
		t.Fatalf("workspace canonical_origin=%q want %q", ws.CanonicalOrigin, "github.com/acme/backend")
	}
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load teams state: %v", err)
	}
	if teamState.ActiveTeam != "backend:acme.com" {
		t.Fatalf("teams active_team=%q", teamState.ActiveTeam)
	}
	if membership := teamState.Membership("backend:acme.com"); membership == nil {
		t.Fatal("expected backend membership in teams.yaml")
	}
	requireWorktreeEncryptionKeyForTest(t, tmp)

	// Verify connect payload had expected fields
	if gotConnectPayload["hostname"] == nil || gotConnectPayload["hostname"] == "" {
		t.Fatal("connect payload missing hostname")
	}
	if _, ok := gotConnectPayload["repo_origin"]; ok {
		t.Fatalf("identity connect must remain repo-independent: %#v", gotConnectPayload)
	}
	// macOS /tmp → /private/tmp symlink; check suffix instead of exact match
	wsPath, _ := gotConnectPayload["workspace_path"].(string)
	if !strings.HasSuffix(wsPath, filepath.Base(tmp)) {
		t.Fatalf("connect payload workspace_path=%v", gotConnectPayload["workspace_path"])
	}
}

func TestWorkspaceConnectExternalIdentityHomeRecoversAcceptedRoot(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	instanceHome := filepath.Join(root, "instance")
	if err := os.MkdirAll(instanceHome, 0o755); err != nil {
		t.Fatal(err)
	}
	identityHome := filepath.Join(root, "accepted.aw")
	teamID := "default:recover.aweb.ai"
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(identityHome, "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           memberDID,
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeLocal,
		CreatedAt:     "2026-04-06T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(identityHome, "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: memberDID, Alias: "alice", IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	certPath, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(identityHome, teamID, cert)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamStateToIdentityHome(identityHome, &awconfig.TeamState{ActiveTeam: teamID, Memberships: []awconfig.TeamMembership{{
		TeamID:   teamID,
		Alias:    "alice",
		CertPath: filepath.ToSlash(certPath),
		AwebURL:  "https://old.example.invalid/api",
	}}}); err != nil {
		t.Fatal(err)
	}

	var gotConnectPayload connectRequest
	server := newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": serverURL,
				"aweb_url":       serverURL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			if err := json.NewDecoder(r.Body).Decode(&gotConnectPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      teamID,
				"alias":        "alice",
				"agent_id":     "agent-alice",
				"workspace_id": "workspace-recovered",
				"repo_id":      "repo-ignored",
				"team_did_key": awid.ComputeDIDKey(teamPub),
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-alice", teamID, "alice")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	run := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "workspace", "connect", "--service", server.URL, "--json")
	run.Env = testCommandEnv(filepath.Join(root, "home"))
	run.Dir = instanceHome
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("workspace connect failed: %v\n%s", err, out)
	}
	if gotConnectPayload.WorkspacePath != identityHome {
		t.Fatalf("workspace_path=%q want external root %q", gotConnectPayload.WorkspacePath, identityHome)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(identityHome, "workspace.yaml"))
	if err != nil {
		t.Fatalf("load external workspace: %v", err)
	}
	if workspace.AwebURL != server.URL || workspace.WorkspacePath != identityHome || workspace.CanonicalOrigin != "" {
		t.Fatalf("workspace=%#v", workspace)
	}
	if membership := workspace.Membership(teamID); membership == nil || membership.WorkspaceID != "workspace-recovered" {
		t.Fatalf("workspace membership=%#v", membership)
	}
	if _, err := os.Stat(filepath.Join(instanceHome, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("workspace connect mutated caller cwd identity home: %v", err)
	}

	gotConnectPayload = connectRequest{}
	serviceInit := exec.CommandContext(ctx, bin, "--identity-home", identityHome, "service", "init", "--service", server.URL, "--json")
	serviceInit.Env = testCommandEnv(filepath.Join(root, "home"))
	serviceInit.Dir = instanceHome
	serviceOut, err := serviceInit.CombinedOutput()
	if err != nil {
		t.Fatalf("service init failed: %v\n%s", err, serviceOut)
	}
	if gotConnectPayload.WorkspacePath != identityHome {
		t.Fatalf("service init workspace_path=%q want external root %q", gotConnectPayload.WorkspacePath, identityHome)
	}
	if _, err := os.Stat(filepath.Join(instanceHome, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("service init mutated caller cwd identity home: %v", err)
	}
}

func TestWorkspaceConnectRejectsGrantIdentityHomeBeforeMutation(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	instanceHome := filepath.Join(root, "instance")
	if err := os.MkdirAll(instanceHome, 0o755); err != nil {
		t.Fatal(err)
	}
	grantHome := filepath.Join(root, "grant.aw")
	if err := os.MkdirAll(grantHome, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(grantHome, "grant.yaml"), []byte("version: 1\ngrant_id: grant-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	called := false
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		t.Fatalf("workspace connect with grant home reached network: %s %s", r.Method, r.URL.Path)
	}))

	for _, tc := range []struct {
		name string
		args []string
	}{
		{name: "workspace-connect", args: []string{"workspace", "connect", "--service", server.URL, "--json"}},
		{name: "service-init", args: []string{"service", "init", "--service", server.URL, "--json"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			called = false
			run := exec.CommandContext(ctx, bin, append([]string{"--identity-home", grantHome}, tc.args...)...)
			run.Env = testCommandEnv(filepath.Join(root, "home"))
			run.Dir = instanceHome
			out, err := run.CombinedOutput()
			if err == nil {
				t.Fatalf("expected grant home refusal, got success:\n%s", out)
			}
			if !strings.Contains(string(out), "this is a grant home") {
				t.Fatalf("unexpected grant refusal:\n%s", out)
			}
			if called {
				t.Fatal("grant-home connect should fail before network")
			}
			if _, err := os.Stat(filepath.Join(grantHome, "workspace.yaml")); !os.IsNotExist(err) {
				t.Fatalf("grant home mutated workspace.yaml: %v", err)
			}
			if _, err := os.Stat(filepath.Join(instanceHome, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("grant home connect mutated caller cwd: %v", err)
			}
		})
	}
}

func TestCanonicalizeGitOriginSSHWithPort(t *testing.T) {
	t.Parallel()

	tests := map[string]string{
		"ssh://git@ssh.github.com:443/acme/backend.git":  "github.com/acme/backend",
		"ssh://git@ssh.github.com:443/acme/backend":      "github.com/acme/backend",
		"ssh://deploy@git.example.com:2222/acme/backend": "git.example.com/acme/backend",
	}
	for origin, want := range tests {
		if got := canonicalizeGitOrigin(origin); got != want {
			t.Errorf("canonicalizeGitOrigin(%q)=%q want %q", origin, got, want)
		}
	}
}

func TestInitWithCertificatePreservesExplicitAPIPath(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := awid.ComputeDIDKey(memberPub)
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  memberDIDKey,
		Alias:         "alice",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotConnectPath string
	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": serverURL + "/api",
				"aweb_url":       serverURL + "/api",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/connect":
			gotConnectPath = r.URL.Path
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "backend:acme.com",
				"alias":        "alice",
				"agent_id":     "agent-uuid-1",
				"workspace_id": "ws-uuid-1",
				"repo_id":      "",
				"team_did_key": teamDIDKey,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/agents/me/encryption-key":
			_ = json.NewEncoder(w).Encode(awid.PublishAgentEncryptionKeyResponse{
				AgentID: "agent-uuid-1",
				TeamID:  "backend:acme.com",
				Alias:   "alice",
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:           memberDIDKey,
		StableID:      awid.ComputeStableID(memberPub),
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-06T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, cert.Team, cert); err != nil {
		t.Fatal(err)
	}

	initGitRepoWithOrigin(t, tmp, "https://github.com/acme/backend.git")

	run := exec.CommandContext(ctx, bin, "init", "--url", server.URL+"/api", "--role", "developer", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}
	if gotConnectPath != "/api/v1/connect" {
		t.Fatalf("connect path=%q", gotConnectPath)
	}
}

func TestInitWithCertificateNotTriggeredWithoutCert(t *testing.T) {
	t.Parallel()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// With no cert at all, the certificate connect flow should not trigger.
	// The old flow runs instead — which requires a TTY.
	// We just verify the command doesn't claim "connected".
	run := exec.CommandContext(ctx, bin, "init", "--url", "http://localhost:9999", "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, _ := run.CombinedOutput()
	// Should NOT say "connected" (certificate flow)
	if strings.Contains(string(out), `"connected"`) {
		t.Fatalf("certificate flow should not trigger without cert:\n%s", string(out))
	}
}

func TestConnectResponseWritesWorkspaceYAML(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = teamPub

	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  awid.ComputeDIDKey(memberPub),
		Alias:         "bob",
		IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": serverURL,
				"aweb_url":       serverURL,
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "backend:acme.com",
				"alias":        "bob",
				"agent_id":     "agent-uuid-2",
				"workspace_id": "ws-uuid-2",
				"repo_id":      "repo-uuid-1",
			})
		}
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Write signing key only for local mode (no identity.yaml)
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, cert.Team, cert); err != nil {
		t.Fatal(err)
	}

	run := exec.CommandContext(ctx, bin, "init", "--url", server.URL, "--json")
	run.Env = idCreateCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	ws, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	activeMembership := activeMembershipForTest(t, ws)
	if activeMembership.TeamID != "backend:acme.com" {
		t.Fatalf("team_id=%q", activeMembership.TeamID)
	}
	if activeMembership.Alias != "bob" {
		t.Fatalf("alias=%q", activeMembership.Alias)
	}
	if ws.RepoID != "repo-uuid-1" {
		t.Fatalf("repo_id=%q", ws.RepoID)
	}
	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, string(out))
	}
	if _, ok := got["lifetime"]; ok {
		t.Fatalf("unexpected legacy lifetime in output: %v", got["lifetime"])
	}
	if got["identity_scope"] != awid.IdentityModeLocal {
		t.Fatalf("identity_scope=%v", got["identity_scope"])
	}
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load teams state: %v", err)
	}
	if teamState.ActiveTeam != "backend:acme.com" {
		t.Fatalf("teams active_team=%q", teamState.ActiveTeam)
	}
	if membership := teamState.Membership("backend:acme.com"); membership == nil {
		t.Fatal("expected backend membership in teams.yaml")
	}
}

// The /v1/connect handshake happens before the server is trusted, so an
// untrusted or MITM'd server must not be able to exhaust client memory with an
// unbounded response body.
func TestPostConnectRejectsOversizeResponse(t *testing.T) {
	prev := maxConnectResponseBytes
	maxConnectResponseBytes = 1024
	t.Cleanup(func() { maxConnectResponseBytes = prev })

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          "backend:acme.com",
		MemberDIDKey:  awid.ComputeDIDKey(memberPub),
		Alias:         "alice",
		IdentityScope: awid.IdentityModeGlobal,
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = teamPub

	oversize := strings.Repeat("a", int(maxConnectResponseBytes)+4096)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// A JSON envelope padded past the cap: the bounded read must reject it
		// before buffering the whole body.
		_, _ = w.Write([]byte(`{"team_id":"backend:acme.com","junk":"` + oversize + `"}`))
	}))
	t.Cleanup(server.Close)

	_, err = postConnect(context.Background(), server.URL, memberKey, cert, connectRequest{})
	if err == nil {
		t.Fatal("expected oversize connect response to be rejected")
	}
	if !strings.Contains(err.Error(), "exceeds maximum size") {
		t.Fatalf("expected a size-limit rejection before the body was buffered, got: %v", err)
	}
}
