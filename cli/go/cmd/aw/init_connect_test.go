package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
		Team:         "acme.com/backend",
		MemberDIDKey: memberDIDKey,
		Alias:        "alice",
		Lifetime:     awid.LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	var gotConnectPayload map[string]any
	var gotAuthHeader string
	var gotCertHeader string
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			gotAuthHeader = r.Header.Get("Authorization")
			gotCertHeader = r.Header.Get("X-AWID-Team-Certificate")
			if err := json.NewDecoder(r.Body).Decode(&gotConnectPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_address": "acme.com/backend",
				"alias":        "alice",
				"agent_id":     "agent-uuid-1",
				"workspace_id": "ws-uuid-1",
				"repo_id":      "",
				"team_did_key": teamDIDKey,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Write identity
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{
		DID:       memberDIDKey,
		StableID:  awid.ComputeStableID(memberPub),
		Address:   "acme.com/alice",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-06T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}

	// Write team certificate
	if err := awid.SaveTeamCertificate(filepath.Join(tmp, ".aw", "team-cert.pem"), cert); err != nil {
		t.Fatal(err)
	}

	// Initialize a git repo so canonical_origin is available
	initGitRepoWithOrigin(t, tmp, "https://github.com/acme/backend.git")

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
	if got["team_address"] != "acme.com/backend" {
		t.Fatalf("team_address=%v", got["team_address"])
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

	// Verify workspace.yaml was written with team_address
	ws, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	if ws.TeamAddress != "acme.com/backend" {
		t.Fatalf("workspace team_address=%q", ws.TeamAddress)
	}
	if ws.Alias != "alice" {
		t.Fatalf("workspace alias=%q", ws.Alias)
	}
	if ws.AwebURL != server.URL {
		t.Fatalf("workspace aweb_url=%q want %q", ws.AwebURL, server.URL)
	}

	// Verify connect payload had expected fields
	if gotConnectPayload["hostname"] == nil || gotConnectPayload["hostname"] == "" {
		t.Fatal("connect payload missing hostname")
	}
	// macOS /tmp → /private/tmp symlink; check suffix instead of exact match
	wsPath, _ := gotConnectPayload["workspace_path"].(string)
	if !strings.HasSuffix(wsPath, filepath.Base(tmp)) {
		t.Fatalf("connect payload workspace_path=%v", gotConnectPayload["workspace_path"])
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
		Team:         "acme.com/backend",
		MemberDIDKey: awid.ComputeDIDKey(memberPub),
		Alias:        "bob",
		Lifetime:     awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
			})
		default:
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_address": "acme.com/backend",
				"alias":        "bob",
				"agent_id":     "agent-uuid-2",
				"workspace_id": "ws-uuid-2",
				"repo_id":      "repo-uuid-1",
			})
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	// Write signing key only (ephemeral — no identity.yaml)
	if err := awid.SaveSigningKey(filepath.Join(tmp, ".aw", "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(filepath.Join(tmp, ".aw", "team-cert.pem"), cert); err != nil {
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
	if ws.TeamAddress != "acme.com/backend" {
		t.Fatalf("team_address=%q", ws.TeamAddress)
	}
	if ws.Alias != "bob" {
		t.Fatalf("alias=%q", ws.Alias)
	}
	if ws.RepoID != "repo-uuid-1" {
		t.Fatalf("repo_id=%q", ws.RepoID)
	}
}
