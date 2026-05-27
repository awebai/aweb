package main

import (
	"context"
	"encoding/json"
	"io"
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

func TestInitGlobalCreatesSelfCustodialGlobalCLIIdentityAndSignsCloudRequest(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		didRegisterPath  string
		didFullPath      string
		registeredDIDAW  string
		registeredDIDKey string
		signupBodyBytes  []byte
		signupBody       map[string]any
		signupAuth       string
		signupTimestamp  string
	)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL + "/api",
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["username"] != "juanre" {
				t.Fatalf("username=%v", payload["username"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"available": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			didRegisterPath = r.URL.Path
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"did_key", "server", "address", "handle"} {
				if _, ok := payload[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			registeredDIDAW, _ = payload["did_aw"].(string)
			registeredDIDKey, _ = payload["new_did_key"].(string)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"registered"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			didFullPath = r.URL.Path
			didAW := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			if didAW != registeredDIDAW {
				t.Fatalf("did full did_aw=%q want %q", didAW, registeredDIDAW)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          didAW,
				"current_did_key": registeredDIDKey,
				"created_at":      "2026-04-08T00:00:00Z",
				"updated_at":      "2026-04-08T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			signupAuth = strings.TrimSpace(r.Header.Get("Authorization"))
			signupTimestamp = strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
			var err error
			signupBodyBytes, err = io.ReadAll(r.Body)
			if err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(signupBodyBytes, &signupBody); err != nil {
				t.Fatal(err)
			}

			didKey, _ := signupBody["did_key"].(string)
			didAW, _ := signupBody["did_aw"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:juanre.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   didAW,
				MemberAddress: "juanre.aweb.ai/laptop",
				Alias:         "laptop",
				Lifetime:      awid.LifetimePersistent,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-1",
				"username":         "juanre",
				"org_id":           "org-1",
				"namespace_domain": "juanre.aweb.ai",
				"team_id":          "default:juanre.aweb.ai",
				"api_key":          "aw_sk_cli_signup_workspace",
				"certificate":      encoded,
				"did_aw":           didAW,
				"member_address":   "juanre.aweb.ai/laptop",
				"alias":            "laptop",
				"team_did_key":     teamDIDKey,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/connect":
			if strings.TrimSpace(r.Header.Get("Authorization")) == "" {
				t.Fatal("connect missing Authorization")
			}
			if strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")) == "" {
				t.Fatal("connect missing team certificate")
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			if payload["workspace_path"] == "" {
				t.Fatalf("connect workspace_path=%v", payload["workspace_path"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:juanre.aweb.ai",
				"alias":        "laptop",
				"agent_id":     "agent-1",
				"workspace_id": "workspace-hosted",
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "default:juanre.aweb.ai", "laptop")
		case r.Method == http.MethodPut && r.URL.Path == "/api/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "default:juanre.aweb.ai", "laptop")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(
		ctx,
		bin,
		"--json",
		"init",
		"--persistent",
		"--username", "juanre",
		"--name", "laptop",
		"--url", server.URL,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	if signupBody["username"] != "juanre" {
		t.Fatalf("username=%v", signupBody["username"])
	}
	if didRegisterPath != "/v1/did" {
		t.Fatalf("did register path=%q", didRegisterPath)
	}
	if signupBody["alias"] != "laptop" {
		t.Fatalf("alias=%v", signupBody["alias"])
	}

	didKey, _ := signupBody["did_key"].(string)
	didAW, _ := signupBody["did_aw"].(string)
	if didFullPath != "/v1/did/"+didAW+"/full" {
		t.Fatalf("did full path=%q", didFullPath)
	}
	parts := strings.Fields(signupAuth)
	if len(parts) != 3 || parts[0] != "DIDKey" || parts[1] != didKey {
		t.Fatalf("Authorization=%q", signupAuth)
	}
	if !verifyCloudDIDPayload(t, mustExtractPublicKey(t, didKey), http.MethodPost, "/api/v1/onboarding/cli-signup", signupTimestamp, signupBodyBytes, parts[2]) {
		t.Fatal("cli-signup signed payload did not verify")
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got["status"] != "connected" {
		t.Fatalf("status=%v", got["status"])
	}
	if got["team_id"] != "default:juanre.aweb.ai" {
		t.Fatalf("team_id=%v", got["team_id"])
	}
	if got["alias"] != "laptop" {
		t.Fatalf("alias=%v", got["alias"])
	}
	if _, ok := got["api_key"]; ok {
		t.Fatalf("init output leaked api_key")
	}

	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("identity.yaml missing: %v", err)
	}
	if identity.DID != didKey {
		t.Fatalf("did=%q want %q", identity.DID, didKey)
	}
	if identity.StableID != didAW {
		t.Fatalf("stable_id=%q want %q", identity.StableID, didAW)
	}
	if identity.Address != "juanre.aweb.ai/laptop" {
		t.Fatalf("address=%q", identity.Address)
	}

	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:juanre.aweb.ai"))
	if err != nil {
		t.Fatalf("team certificate missing: %v", err)
	}
	if cert.MemberDIDKey != didKey {
		t.Fatalf("cert did_key=%q want %q", cert.MemberDIDKey, didKey)
	}
	if cert.MemberDIDAW != didAW {
		t.Fatalf("cert did_aw=%q want %q", cert.MemberDIDAW, didAW)
	}
	if cert.MemberAddress != "juanre.aweb.ai/laptop" {
		t.Fatalf("cert member_address=%q", cert.MemberAddress)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("workspace.yaml missing: %v", err)
	}
	if workspace.AwebURL != server.URL+"/api" {
		t.Fatalf("workspace aweb_url=%q", workspace.AwebURL)
	}
	if workspace.APIKey != "aw_sk_cli_signup_workspace" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}
	membership := workspace.Membership("default:juanre.aweb.ai")
	if membership == nil {
		t.Fatalf("workspace missing aweb-managed team membership: %+v", workspace.Memberships)
	}
	if membership.WorkspaceID != "workspace-hosted" {
		t.Fatalf("membership workspace_id=%q", membership.WorkspaceID)
	}
}

func TestInitSelfCustodialGlobalCLIThenAddWorktreeTwiceUsesStoredWorkspaceAPIKey(t *testing.T) {
	t.Parallel()

	const (
		teamID       = "default:hostedchain.aweb.ai"
		parentAPIKey = "aw_sk_cli_signup_workspace"
	)

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		registeredDIDAW  string
		registeredDIDKey string
		workspaceInits   []map[string]any
		connectAliases   []string
	)

	signCert := func(fields awid.TeamCertificateFields) string {
		t.Helper()
		cert, err := awid.SignTeamCertificate(teamKey, fields)
		if err != nil {
			t.Fatalf("sign cert: %v", err)
		}
		encoded, err := awid.EncodeTeamCertificateHeader(cert)
		if err != nil {
			t.Fatalf("encode cert: %v", err)
		}
		return encoded
	}

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			_ = json.NewEncoder(w).Encode(map[string]any{"available": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			registeredDIDAW, _ = payload["did_aw"].(string)
			registeredDIDKey, _ = payload["new_did_key"].(string)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(`{"status":"registered"}`))
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			didAW := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			if didAW != registeredDIDAW {
				t.Fatalf("did full did_aw=%q want %q", didAW, registeredDIDAW)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          didAW,
				"current_did_key": registeredDIDKey,
				"created_at":      "2026-05-09T00:00:00Z",
				"updated_at":      "2026-05-09T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			didKey, _ := payload["did_key"].(string)
			didAW, _ := payload["did_aw"].(string)
			encoded := signCert(awid.TeamCertificateFields{
				Team:          teamID,
				MemberDIDKey:  didKey,
				MemberDIDAW:   didAW,
				MemberAddress: "hostedchain.aweb.ai/laptop",
				Alias:         "laptop",
				Lifetime:      awid.LifetimePersistent,
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-1",
				"username":         "hostedchain",
				"org_id":           "org-1",
				"namespace_domain": "hostedchain.aweb.ai",
				"team_id":          teamID,
				"api_key":          parentAPIKey,
				"certificate":      encoded,
				"did_aw":           didAW,
				"member_address":   "hostedchain.aweb.ai/laptop",
				"alias":            "laptop",
				"team_did_key":     teamDIDKey,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			if got := strings.TrimSpace(r.Header.Get("Authorization")); got != "Bearer "+parentAPIKey {
				t.Fatalf("workspace init Authorization=%q", got)
			}
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			workspaceInits = append(workspaceInits, payload)
			didKey, _ := payload["did"].(string)
			alias, _ := payload["alias"].(string)
			encoded := signCert(awid.TeamCertificateFields{
				Team:         teamID,
				MemberDIDKey: didKey,
				Alias:        alias,
				Lifetime:     awid.LifetimeEphemeral,
			})
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          alias,
				"team_id":        teamID,
				"workspace_id":   "ws-" + alias,
				"did":            didKey,
				"stable_id":      "",
				"identity_scope": awid.IdentityModeLocal,
				"custody":        awid.CustodySelf,
				"api_key":        "aw_sk_child_" + alias,
				"team_did_key":   teamDIDKey,
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/roles/active":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_roles_id": "roles-1",
				"roles": map[string]any{
					"developer": map[string]any{"title": "Developer"},
				},
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/workspaces/team":
			workspaces := make([]map[string]any, 0, len(connectAliases))
			for _, alias := range connectAliases {
				workspaces = append(workspaces, map[string]any{
					"workspace_id": "ws-" + alias,
					"alias":        alias,
					"role":         "developer",
					"status":       "active",
				})
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"workspaces": workspaces})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			cert, err := awid.DecodeTeamCertificateHeader(strings.TrimSpace(r.Header.Get("X-AWID-Team-Certificate")))
			if err != nil {
				t.Fatalf("decode connect cert: %v", err)
			}
			alias := strings.TrimSpace(cert.Alias)
			if alias == "" {
				t.Fatal("connect certificate missing alias")
			}
			connectAliases = append(connectAliases, alias)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      teamID,
				"alias":        alias,
				"agent_id":     "agent-" + alias,
				"workspace_id": "ws-" + alias,
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-laptop", teamID, "laptop")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	repo := filepath.Join(tmp, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, "https://github.com/acme/hosted-chain.git")
	buildAwBinary(t, ctx, bin)

	initCmd := exec.CommandContext(ctx, bin, "--json", "init", "--persistent", "--username", "hostedchain", "--name", "laptop", "--url", server.URL)
	initCmd.Env = testCommandEnv(tmp)
	initCmd.Dir = repo
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	parentWorkspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(repo, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load parent workspace: %v", err)
	}
	if parentWorkspace.APIKey != parentAPIKey {
		t.Fatalf("parent api_key=%q", parentWorkspace.APIKey)
	}
	if parentWorkspace.Membership(teamID) == nil {
		t.Fatalf("parent missing team membership: %+v", parentWorkspace.Memberships)
	}

	for _, alias := range []string{"bob", "carol"} {
		cmd := exec.CommandContext(ctx, bin, "workspace", "add-worktree", "developer", "--alias", alias)
		cmd.Env = testCommandEnv(tmp)
		cmd.Dir = repo
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("add-worktree %s failed: %v\n%s", alias, err, string(out))
		}
		child := filepath.Join(tmp, "repo-"+alias)
		childWorkspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(child, ".aw", "workspace.yaml"))
		if err != nil {
			t.Fatalf("load child %s workspace: %v", alias, err)
		}
		if childWorkspace.APIKey != "aw_sk_child_"+alias {
			t.Fatalf("child %s api_key=%q", alias, childWorkspace.APIKey)
		}
		membership := childWorkspace.Membership(teamID)
		if membership == nil {
			t.Fatalf("child %s missing team membership: %+v", alias, childWorkspace.Memberships)
		}
		if membership.WorkspaceID != "ws-"+alias {
			t.Fatalf("child %s workspace_id=%q", alias, membership.WorkspaceID)
		}
		if _, err := os.Stat(filepath.Join(child, ".aw", "identity.yaml")); !os.IsNotExist(err) {
			t.Fatalf("child %s should be local without identity.yaml: %v", alias, err)
		}
	}

	if got := len(workspaceInits); got != 2 {
		t.Fatalf("workspace init calls=%d want 2", got)
	}
	for i, alias := range []string{"bob", "carol"} {
		if workspaceInits[i]["alias"] != alias {
			t.Fatalf("workspace init %d alias=%v want %s", i, workspaceInits[i]["alias"], alias)
		}
		if workspaceInits[i]["role_name"] != "developer" {
			t.Fatalf("workspace init %d role_name=%v", i, workspaceInits[i]["role_name"])
		}
		if _, ok := workspaceInits[i]["lifetime"]; ok {
			t.Fatalf("workspace init %d must not send lifetime: %v", i, workspaceInits[i]["lifetime"])
		}
		if workspaceInits[i]["identity_scope"] != awid.IdentityModeLocal {
			t.Fatalf("workspace init %d identity_scope=%v", i, workspaceInits[i]["identity_scope"])
		}
	}
	if strings.Join(connectAliases, ",") != "laptop,bob,carol" {
		t.Fatalf("connect aliases=%v", connectAliases)
	}
}

func TestInitSelfCustodialGlobalCLITreatsSameKeyAlreadyRegisteredAsSuccess(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		registerCalls    int
		keyLookups       int
		signupCalled     bool
		registeredDIDAW  string
		registeredDIDKey string
		signupBody       map[string]any
	)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			_ = json.NewEncoder(w).Encode(map[string]any{"available": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			registerCalls++
			var payload map[string]any
			if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
				t.Fatal(err)
			}
			registeredDIDAW, _ = payload["did_aw"].(string)
			registeredDIDKey, _ = payload["new_did_key"].(string)
			for _, field := range []string{"did_key", "server", "address", "handle"} {
				if _, ok := payload[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			http.Error(w, `{"detail":"did_aw already registered"}`, http.StatusConflict)
		case r.Method == http.MethodGet && registeredDIDAW != "" && r.URL.Path == "/v1/did/"+registeredDIDAW+"/key":
			keyLookups++
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          registeredDIDAW,
				"current_did_key": registeredDIDKey,
				"log_head":        nil,
			})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			t.Fatalf("already-registered self-custodial CLI init should not read full did state")
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			signupCalled = true
			signupBody = map[string]any{}
			if err := json.NewDecoder(r.Body).Decode(&signupBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := signupBody["did_key"].(string)
			didAW, _ := signupBody["did_aw"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:juanre.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   didAW,
				MemberAddress: "juanre.aweb.ai/laptop",
				Alias:         "laptop",
				Lifetime:      awid.LifetimePersistent,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-1",
				"username":         "juanre",
				"org_id":           "org-1",
				"namespace_domain": "juanre.aweb.ai",
				"team_id":          "default:juanre.aweb.ai",
				"api_key":          "aw_sk_cli_signup_workspace",
				"certificate":      encoded,
				"did_aw":           didAW,
				"member_address":   "juanre.aweb.ai/laptop",
				"alias":            "laptop",
				"team_did_key":     teamDIDKey,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:juanre.aweb.ai",
				"alias":        "laptop",
				"agent_id":     "agent-1",
				"workspace_id": "workspace-hosted",
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "default:juanre.aweb.ai", "laptop")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(
		ctx,
		bin,
		"--json",
		"init",
		"--persistent",
		"--username", "juanre",
		"--name", "laptop",
		"--url", server.URL,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init retry failed: %v\n%s", err, string(out))
	}

	if registerCalls != 1 {
		t.Fatalf("register calls=%d want 1", registerCalls)
	}
	if keyLookups != 1 {
		t.Fatalf("key lookups=%d want 1", keyLookups)
	}
	if !signupCalled {
		t.Fatal("cli-signup was not called after same-key registration conflict")
	}
	if signupBody["did_aw"] != registeredDIDAW {
		t.Fatalf("signup did_aw=%v want %q", signupBody["did_aw"], registeredDIDAW)
	}
	if signupBody["did_key"] != registeredDIDKey {
		t.Fatalf("signup did_key=%v want %q", signupBody["did_key"], registeredDIDKey)
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got["status"] != "connected" {
		t.Fatalf("status=%v", got["status"])
	}
}

func TestInitLocalCLIWorkspaceOmitsGlobalIdentityFile(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		didRegisterCalls int
		signupBody       map[string]any
	)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"onboarding_url": server.URL,
				"aweb_url":       server.URL,
				"registry_url":   server.URL,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/check-username":
			_ = json.NewEncoder(w).Encode(map[string]any{"available": true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			didRegisterCalls++
			t.Fatalf("local CLI workspace init should not register a did:aw")
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			t.Fatalf("local CLI workspace init should not read back did:aw state")
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/onboarding/cli-signup":
			signupBody = map[string]any{}
			if err := json.NewDecoder(r.Body).Decode(&signupBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := signupBody["did_key"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "default:juanre.aweb.ai",
				MemberDIDKey: didKey,
				Alias:        "laptop",
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"user_id":          "user-1",
				"username":         "juanre",
				"org_id":           "org-1",
				"namespace_domain": "juanre.aweb.ai",
				"team_id":          "default:juanre.aweb.ai",
				"api_key":          "aw_sk_cli_signup_workspace",
				"certificate":      encoded,
				"did_aw":           "",
				"member_address":   "",
				"alias":            "laptop",
				"team_did_key":     teamDIDKey,
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:juanre.aweb.ai",
				"alias":        "laptop",
				"agent_id":     "agent-1",
				"workspace_id": "workspace-hosted",
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "default:juanre.aweb.ai", "laptop")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)

	run := exec.CommandContext(
		ctx,
		bin,
		"--json",
		"init",
		"--username", "juanre",
		"--alias", "laptop",
		"--url", server.URL,
	)
	run.Env = testCommandEnv(tmp)
	run.Dir = tmp
	out, err := run.CombinedOutput()
	if err != nil {
		t.Fatalf("init failed: %v\n%s", err, string(out))
	}

	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should not exist for local CLI workspace init: %v", err)
	}
	if didRegisterCalls != 0 {
		t.Fatalf("did registrations=%d want 0", didRegisterCalls)
	}
	if signupBody["did_aw"] != "" {
		t.Fatalf("local signup did_aw=%v want empty string", signupBody["did_aw"])
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "signing.key")); err != nil {
		t.Fatalf("signing.key missing: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:juanre.aweb.ai"))
	if err != nil {
		t.Fatalf("team certificate missing: %v", err)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("cert member_did_aw=%q want empty", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("cert member_address=%q want empty", cert.MemberAddress)
	}
	wantLifetime := awid.LifetimeEphemeral
	if cert.Lifetime != wantLifetime {
		t.Fatalf("cert lifetime=%q want %q", cert.Lifetime, wantLifetime)
	}

	var got map[string]any
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if got["status"] != "connected" {
		t.Fatalf("status=%v", got["status"])
	}
}
