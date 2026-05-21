package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestInitAPIKeyAliasCreatesLocalSelfCustodialCLIWorkspace(t *testing.T) {
	t.Parallel()

	const apiKey = "aw_sk_test_ephemeral"

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var (
		initAuthHeader string
		initBody       map[string]any
		connectBody    map[string]any
	)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			initAuthHeader = strings.TrimSpace(r.Header.Get("Authorization"))
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			publicKeyB64, _ := initBody["public_key"].(string)
			publicKeyBytes, err := base64.StdEncoding.DecodeString(publicKeyB64)
			if err != nil {
				t.Fatalf("decode public_key: %v", err)
			}
			didKey, _ := initBody["did"].(string)
			if got := awid.ComputeDIDKey(ed25519.PublicKey(publicKeyBytes)); got != didKey {
				t.Fatalf("did=%q does not match public_key => %q", didKey, got)
			}
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "backend:acme.com",
				MemberDIDKey: didKey,
				Alias:        "alice",
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
				"server_url":     server.URL + "/api",
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "backend:acme.com",
				"workspace_id":   "ws-1",
				"did":            didKey,
				"stable_id":      "",
				"identity_scope": awid.IdentityModeLocal,
				"custody":        awid.CustodySelf,
				"api_key":        "workspace-sk-ephemeral",
			})
		case "/api/v1/connect":
			requireCertificateAuthForTest(t, r)
			if err := json.NewDecoder(r.Body).Decode(&connectBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "backend:acme.com",
				"alias":        "alice",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir: tmp,
		AwebURL:    externalLikeTestURL(t, server.URL),
		APIKey:     apiKey,
		Alias:      "requested-alias",
		Role:       "backend",
	})
	if err != nil {
		t.Fatalf("runAPIKeyBootstrapInit: %v", err)
	}

	if initAuthHeader != "Bearer "+apiKey {
		t.Fatalf("Authorization=%q", initAuthHeader)
	}
	if initBody["alias"] != "requested-alias" {
		t.Fatalf("init alias=%v", initBody["alias"])
	}
	if initBody["role_name"] != "backend" {
		t.Fatalf("init role_name=%v", initBody["role_name"])
	}
	if _, ok := initBody["lifetime"]; ok {
		t.Fatalf("workspace init request must not send lifetime: %v", initBody["lifetime"])
	}
	if initBody["identity_scope"] != awid.IdentityModeLocal {
		t.Fatalf("init identity_scope=%v", initBody["identity_scope"])
	}
	if initBody["custody"] != awid.CustodySelf {
		t.Fatalf("init custody=%v", initBody["custody"])
	}
	if _, ok := initBody["identity_type"]; ok {
		t.Fatalf("local CLI workspace bootstrap must not send hosted identity_type: %v", initBody["identity_type"])
	}
	if _, ok := initBody["address"]; ok {
		t.Fatalf("local CLI workspace bootstrap must not request an address: %v", initBody["address"])
	}
	if connectBody["role"] != "backend" {
		t.Fatalf("connect role=%v", connectBody["role"])
	}
	if result.TeamID != "backend:acme.com" {
		t.Fatalf("team_id=%q", result.TeamID)
	}
	if result.AwebURL != server.URL+"/api" {
		t.Fatalf("aweb_url=%q", result.AwebURL)
	}

	signingKey, err := awid.LoadSigningKey(filepath.Join(tmp, ".aw", "signing.key"))
	if err != nil {
		t.Fatalf("load signing key: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "backend:acme.com"))
	if err != nil {
		t.Fatalf("load team certificate: %v", err)
	}
	gotDidKey := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey))
	if cert.MemberDIDKey != gotDidKey {
		t.Fatalf("cert member_did_key=%q want %q", cert.MemberDIDKey, gotDidKey)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("cert member_did_aw=%q", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("cert member_address=%q", cert.MemberAddress)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should not exist for local API-key init: %v", err)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace.yaml: %v", err)
	}
	if workspace.APIKey != "workspace-sk-ephemeral" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}
	if workspace.AwebURL != server.URL+"/api" {
		t.Fatalf("workspace aweb_url=%q", workspace.AwebURL)
	}
	if containsStringUnderTree(t, filepath.Join(tmp, ".aw"), apiKey) {
		t.Fatal("AWEB_API_KEY was written to disk")
	}
}

func TestInitAPIKeyGlobalNameCreatesSelfCustodialGlobalCLIIdentity(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:1")

	const apiKey = "aw_sk_test_persistent"

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var initBody map[string]any
	var requestOrder []string
	var registeredDIDKey string
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/did":
			requestOrder = append(requestOrder, "register_identity")
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			registeredDIDKey, _ = body["new_did_key"].(string)
			for _, field := range []string{"address", "server", "handle", "did_key"} {
				if _, ok := body[field]; ok {
					t.Fatalf("register_did payload unexpectedly carried %q", field)
				}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			requestOrder = append(requestOrder, "did_full")
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": registeredDIDKey,
				"created_at":      "2026-04-18T00:00:00Z",
				"updated_at":      "2026-04-18T00:00:00Z",
			})
		case r.URL.Path == "/api/v1/workspaces/init":
			requestOrder = append(requestOrder, "workspace_init")
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := initBody["did"].(string)
			pubKeyB64, _ := initBody["public_key"].(string)
			pubKeyBytes, _ := base64.StdEncoding.DecodeString(pubKeyB64)
			stableID := awid.ComputeStableID(ed25519.PublicKey(pubKeyBytes))
			memberAddress := "alice.aweb.ai/alice"
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:alice.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   stableID,
				MemberAddress: memberAddress,
				Alias:         "alice",
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
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "default:alice.aweb.ai",
				"workspace_id":   "ws-1",
				"did":            didKey,
				"stable_id":      stableID,
				"identity_scope": awid.IdentityModeGlobal,
				"custody":        awid.CustodySelf,
				"api_key":        "workspace-sk-persistent",
			})
		case r.URL.Path == "/v1/connect":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:alice.aweb.ai",
				"alias":        "alice",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	result, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir:  tmp,
		AwebURL:     externalLikeTestURL(t, server.URL),
		RegistryURL: server.URL,
		APIKey:      apiKey,
		Name:        "alice",
		Role:        "backend",
		HumanName:   "Alice",
		AgentType:   "codex",
		Persistent:  true,
	})
	if err != nil {
		t.Fatalf("runAPIKeyBootstrapInit global: %v", err)
	}

	if got, want := strings.Join(requestOrder[:3], ","), "register_identity,did_full,workspace_init"; got != want {
		t.Fatalf("request order=%q want %q", got, want)
	}
	if _, ok := initBody["lifetime"]; ok {
		t.Fatalf("workspace init request must not send lifetime: %v", initBody["lifetime"])
	}
	if initBody["identity_scope"] != awid.IdentityModeGlobal {
		t.Fatalf("init identity_scope=%v", initBody["identity_scope"])
	}
	if initBody["name"] != "alice" {
		t.Fatalf("init name=%v", initBody["name"])
	}
	if a, ok := initBody["alias"]; ok && strings.TrimSpace(a.(string)) != "" {
		t.Fatalf("global init should not send alias, got %v", a)
	}
	if initBody["custody"] != awid.CustodySelf {
		t.Fatalf("init custody=%v", initBody["custody"])
	}
	if result.TeamID != "default:alice.aweb.ai" {
		t.Fatalf("team_id=%q", result.TeamID)
	}
	if result.Address != "alice.aweb.ai/alice" {
		t.Fatalf("address=%q", result.Address)
	}
	if result.StableID == "" {
		t.Fatal("stable_id should be included in connect output")
	}
	if result.IdentityScope != awid.IdentityModeGlobal {
		t.Fatalf("identity_scope=%q", result.IdentityScope)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(tmp, ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("load identity.yaml: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:alice.aweb.ai"))
	if err != nil {
		t.Fatalf("load team certificate: %v", err)
	}
	if identity.DID != cert.MemberDIDKey {
		t.Fatalf("identity did=%q want %q", identity.DID, cert.MemberDIDKey)
	}
	if !strings.HasPrefix(identity.StableID, "did:aw:") || identity.StableID == "" {
		t.Fatalf("stable_id=%q want did:aw:...", identity.StableID)
	}
	if identity.StableID != cert.MemberDIDAW {
		t.Fatalf("identity stable_id=%q does not match cert member_did_aw=%q", identity.StableID, cert.MemberDIDAW)
	}
	if identity.Address != "alice.aweb.ai/alice" {
		t.Fatalf("address=%q", identity.Address)
	}
	if identity.Custody != awid.CustodySelf {
		t.Fatalf("identity custody=%q", identity.Custody)
	}
	if identity.Lifetime != awid.LifetimePersistent {
		t.Fatalf("identity lifetime=%q", identity.Lifetime)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace.yaml: %v", err)
	}
	if workspace.APIKey != "workspace-sk-persistent" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}
	if _, err := os.Stat(apiKeyPartialInitPath(tmp)); !os.IsNotExist(err) {
		t.Fatalf("partial init state should be removed after success: %v", err)
	}
}

func TestRunAPIKeyBootstrapInitGlobalResumesPartialAfterWorkspaceInitFailure(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "")

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var registeredDIDKeys []string
	var workspaceInitDIDKeys []string
	var workspaceInitCalls int
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v1/did":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["new_did_key"].(string)
			registeredDIDKeys = append(registeredDIDKeys, didKey)
			if len(registeredDIDKeys) > 1 {
				http.Error(w, `{"detail":"already registered"}`, http.StatusConflict)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": registeredDIDKeys[0],
				"created_at":      "2026-04-18T00:00:00Z",
				"updated_at":      "2026-04-18T00:00:00Z",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/key"):
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/key")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"did_aw":          stableID,
				"current_did_key": registeredDIDKeys[0],
			})
		case r.URL.Path == "/api/v1/workspaces/init":
			workspaceInitCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			workspaceInitDIDKeys = append(workspaceInitDIDKeys, didKey)
			if workspaceInitCalls == 1 {
				http.Error(w, `{"detail":"temporary workspace failure"}`, http.StatusInternalServerError)
				return
			}
			pubKeyB64, _ := body["public_key"].(string)
			pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
			if err != nil {
				t.Fatalf("decode public_key: %v", err)
			}
			stableID := awid.ComputeStableID(ed25519.PublicKey(pubKeyBytes))
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:alice.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   stableID,
				MemberAddress: "alice.aweb.ai/alice",
				Alias:         "alice",
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
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "default:alice.aweb.ai",
				"workspace_id":   "ws-1",
				"did":            didKey,
				"stable_id":      stableID,
				"identity_scope": awid.IdentityModeGlobal,
				"custody":        awid.CustodySelf,
				"api_key":        "workspace-sk-persistent",
			})
		case r.URL.Path == "/v1/connect":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:alice.aweb.ai",
				"alias":        "alice",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": teamDIDKey,
			})
		case r.URL.Path == "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	req := apiKeyInitRequest{
		WorkingDir:  tmp,
		AwebURL:     externalLikeTestURL(t, server.URL),
		RegistryURL: server.URL,
		APIKey:      "aw_sk_test_persistent_resume",
		Name:        "alice",
		Role:        "backend",
		Persistent:  true,
	}

	if _, err := runAPIKeyBootstrapInit(req); err == nil || !strings.Contains(err.Error(), "POST /api/v1/workspaces/init returned 500") {
		t.Fatalf("unexpected first-run error: %v", err)
	}
	info, err := os.Stat(apiKeyPartialInitPath(tmp))
	if err != nil {
		t.Fatalf("partial init state should remain after workspace init failure: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("partial init mode=%#o want 0600", got)
	}
	if containsStringUnderTree(t, filepath.Join(tmp, ".aw"), req.APIKey) {
		t.Fatal("AWEB_API_KEY was written to partial init state")
	}

	result, err := runAPIKeyBootstrapInit(req)
	if err != nil {
		t.Fatalf("retry runAPIKeyBootstrapInit: %v", err)
	}
	if result.TeamID != "default:alice.aweb.ai" {
		t.Fatalf("team_id=%q", result.TeamID)
	}
	if len(registeredDIDKeys) != 2 {
		t.Fatalf("registered DID calls=%d", len(registeredDIDKeys))
	}
	if registeredDIDKeys[0] == "" || registeredDIDKeys[0] != registeredDIDKeys[1] {
		t.Fatalf("retry registered DID=%q want original %q", registeredDIDKeys[1], registeredDIDKeys[0])
	}
	if len(workspaceInitDIDKeys) != 2 || workspaceInitDIDKeys[0] != workspaceInitDIDKeys[1] {
		t.Fatalf("workspace init DID keys=%v", workspaceInitDIDKeys)
	}
	signingKey, err := awid.LoadSigningKey(filepath.Join(tmp, ".aw", "signing.key"))
	if err != nil {
		t.Fatalf("load signing key: %v", err)
	}
	if got := awid.ComputeDIDKey(signingKey.Public().(ed25519.PublicKey)); got != registeredDIDKeys[0] {
		t.Fatalf("persisted signing key DID=%q want %q", got, registeredDIDKeys[0])
	}
	if _, err := os.Stat(apiKeyPartialInitPath(tmp)); !os.IsNotExist(err) {
		t.Fatalf("partial init state should be removed after retry success: %v", err)
	}
}

func TestRunAPIKeyBootstrapInitGlobalRejectsPartialContextMismatch(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "")

	tmp := t.TempDir()
	req := apiKeyInitRequest{
		WorkingDir:  tmp,
		AwebURL:     "https://app-one.example",
		RegistryURL: "https://registry.example",
		APIKey:      "aw_sk_test_partial_mismatch",
		Name:        "alice",
		Role:        "backend",
		Persistent:  true,
	}
	material, err := generateAPIKeyBootstrapIdentity()
	if err != nil {
		t.Fatal(err)
	}
	state, err := newAPIKeyPartialInitState(req, "alice", "https://registry.example", material)
	if err != nil {
		t.Fatal(err)
	}
	if err := saveAPIKeyPartialInit(tmp, state); err != nil {
		t.Fatalf("save partial init: %v", err)
	}

	req.AwebURL = "https://app-two.example"
	_, err = runAPIKeyBootstrapInit(req)
	if err == nil || !strings.Contains(err.Error(), "different bootstrap context") || !strings.Contains(err.Error(), "aweb_url") {
		t.Fatalf("unexpected mismatch error: %v", err)
	}
}

func TestRunAPIKeyBootstrapInitRegisterIdentityFailureShortCircuitsWorkspaceInit(t *testing.T) {
	t.Setenv("AWID_REGISTRY_URL", "")

	registerCalls := 0
	initCalls := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/did":
			registerCalls++
			http.Error(w, `{"detail":"registry unavailable"}`, http.StatusBadGateway)
		case "/api/v1/workspaces/init":
			initCalls++
			t.Fatalf("workspace init should not be called after register identity failure")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err := runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir:  tmp,
		AwebURL:     externalLikeTestURL(t, server.URL),
		RegistryURL: server.URL,
		APIKey:      "aw_sk_test_persistent",
		Name:        "alice",
		Persistent:  true,
	})

	if err == nil || !strings.Contains(err.Error(), "before workspace init") {
		t.Fatalf("unexpected error: %v", err)
	}
	if registerCalls != 1 {
		t.Fatalf("register calls=%d", registerCalls)
	}
	if initCalls != 0 {
		t.Fatalf("workspace init calls=%d", initCalls)
	}
	if _, statErr := os.Stat(filepath.Join(tmp, ".aw", "workspace.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("workspace.yaml should not be written: %v", statErr)
	}
	info, statErr := os.Stat(apiKeyPartialInitPath(tmp))
	if statErr != nil {
		t.Fatalf("partial init state should be written before register identity: %v", statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("partial init mode=%#o want 0600", got)
	}
}

func TestResolveAPIKeyInitAwebURLStripsAPISuffix(t *testing.T) {
	oldAwebURL := initAwebURL
	oldCompatURL := initURL
	t.Cleanup(func() {
		initAwebURL = oldAwebURL
		initURL = oldCompatURL
	})

	t.Setenv("AWEB_URL", "")
	initAwebURL = "https://app.aweb.ai/api"
	initURL = ""

	awebURL, err := resolveAPIKeyInitAwebURL()
	if err != nil {
		t.Fatalf("resolveAPIKeyInitAwebURL: %v", err)
	}
	if awebURL != "https://app.aweb.ai" {
		t.Fatalf("awebURL=%q", awebURL)
	}
}

func TestInitAPIKeyRequiresExplicitAwebURL(t *testing.T) {
	// Cannot use t.Parallel() — uses cwd and globals.

	oldIsTTY := initIsTTY
	oldAwebURL := initAwebURL
	oldCompatURL := initURL
	oldInjectDocs := initInjectDocs
	oldSetupHooks := initSetupHooks
	oldSetupChannel := initSetupChannel
	t.Cleanup(func() {
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initURL = oldCompatURL
		initInjectDocs = oldInjectDocs
		initSetupHooks = oldSetupHooks
		initSetupChannel = oldSetupChannel
	})
	initIsTTY = func() bool { return false }

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	t.Setenv(initAPIKeyEnvVar, "aw_sk_missing_url")
	t.Setenv("AWEB_URL", "")
	initAwebURL = ""
	initURL = ""
	initInjectDocs = false
	initSetupHooks = false
	initSetupChannel = false

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	if err := runInit(&cmd.Command, nil); err == nil || !strings.Contains(err.Error(), "AWEB_URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAPIKeyBootstrapInitRejectsResponseDIDMismatch(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = awid.ComputeDIDKey(teamPub)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "backend:acme.com",
				MemberDIDKey: didKey,
				Alias:        "alice",
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
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "backend:acme.com",
				"workspace_id":   "ws-1",
				"did":            "did:key:z6MkrWrongResponseDid11111111111111111111111",
				"stable_id":      "",
				"identity_scope": awid.IdentityModeLocal,
				"custody":        awid.CustodySelf,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir: tmp,
		AwebURL:    externalLikeTestURL(t, server.URL),
		APIKey:     "aw_sk_test",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match generated did:key") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAPIKeyBootstrapInitRejectsResponseIdentityScopeMismatch(t *testing.T) {
	t.Parallel()

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_ = awid.ComputeDIDKey(teamPub)

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:          "default:alice.aweb.ai",
				MemberDIDKey:  didKey,
				MemberDIDAW:   "did:aw:alice",
				MemberAddress: "alice.aweb.ai/alice",
				Alias:         "alice",
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
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "default:alice.aweb.ai",
				"workspace_id":   "ws-1",
				"did":            didKey,
				"stable_id":      "did:aw:alice",
				"identity_scope": awid.IdentityModeGlobal,
				"custody":        awid.CustodySelf,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir: tmp,
		AwebURL:    externalLikeTestURL(t, server.URL),
		APIKey:     "aw_sk_test",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match requested identity_scope") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAPIKeyBootstrapInitRejectsTamperedTeamCertificate(t *testing.T) {
	t.Parallel()

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "backend:acme.com",
				MemberDIDKey: didKey,
				Alias:        "alice",
				Lifetime:     awid.LifetimeEphemeral,
			})
			if err != nil {
				t.Fatal(err)
			}
			tampered := *cert
			tampered.Alias = "mallory"
			encoded, err := awid.EncodeTeamCertificateHeader(&tampered)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "backend:acme.com",
				"workspace_id":   "ws-1",
				"did":            didKey,
				"stable_id":      "",
				"identity_scope": awid.IdentityModeLocal,
				"custody":        awid.CustodySelf,
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir: tmp,
		AwebURL:    externalLikeTestURL(t, server.URL),
		APIKey:     "aw_sk_test",
	})
	if err == nil || !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestRunAPIKeyBootstrapInitRejectsMissingOrNonSelfCustody(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name         string
		custody      string
		wantFragment string
	}{
		{name: "missing", custody: "", wantFragment: "missing custody"},
		{name: "non-self", custody: "hosted", wantFragment: `custody "hosted" is not self-custodial`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}

			var server *httptest.Server
			server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/workspaces/init":
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					didKey, _ := body["did"].(string)
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
						Team:         "backend:acme.com",
						MemberDIDKey: didKey,
						Alias:        "alice",
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
						"server_url":     server.URL,
						"team_cert":      encoded,
						"alias":          "alice",
						"team_id":        "backend:acme.com",
						"workspace_id":   "ws-1",
						"did":            didKey,
						"stable_id":      "",
						"identity_scope": awid.IdentityModeLocal,
						"custody":        tc.custody,
					})
				default:
					t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
				}
			}))

			tmp := t.TempDir()
			_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
				WorkingDir: tmp,
				AwebURL:    externalLikeTestURL(t, server.URL),
				APIKey:     "aw_sk_test",
			})
			if err == nil || !strings.Contains(err.Error(), tc.wantFragment) {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestRunAPIKeyBootstrapInitRejectsOverlongWorkspaceAPIKey(t *testing.T) {
	t.Parallel()

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
				Team:         "backend:acme.com",
				MemberDIDKey: didKey,
				Alias:        "alice",
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
				"server_url":     server.URL,
				"team_cert":      encoded,
				"alias":          "alice",
				"team_id":        "backend:acme.com",
				"workspace_id":   "ws-1",
				"did":            didKey,
				"stable_id":      "",
				"identity_scope": awid.IdentityModeLocal,
				"custody":        awid.CustodySelf,
				"api_key":        strings.Repeat("k", maxWorkspaceAPIKeyLength+1),
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	_, err = runAPIKeyBootstrapInit(apiKeyInitRequest{
		WorkingDir: tmp,
		AwebURL:    externalLikeTestURL(t, server.URL),
		APIKey:     "aw_sk_test",
	})
	if err == nil || !strings.Contains(err.Error(), fmt.Sprintf("api_key exceeds %d bytes", maxWorkspaceAPIKeyLength)) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func containsStringUnderTree(t *testing.T, root, needle string) bool {
	t.Helper()

	found := false
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil || info.IsDir() {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		if strings.Contains(string(data), needle) {
			found = true
		}
		return nil
	})
	return found
}

func externalLikeTestURL(t *testing.T, raw string) string {
	t.Helper()

	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse url %q: %v", raw, err)
	}
	host := u.Hostname()
	port := u.Port()
	switch host {
	case "127.0.0.1":
		host = "127.0.0.1.nip.io"
	case "::1":
		host = "ip6-localhost.invalid"
	case "localhost":
		host = "localhost.nip.io"
	}
	if port != "" {
		u.Host = host + ":" + port
	} else {
		u.Host = host
	}
	return u.String()
}
