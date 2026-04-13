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

func TestInitBootstrapsFromAPIKeyEphemeral(t *testing.T) {
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
				"server_url":   server.URL,
				"team_cert":    encoded,
				"alias":        "alice",
				"team_id":      "backend:acme.com",
				"workspace_id": "ws-1",
				"did":          didKey,
				"stable_id":    "",
				"lifetime":     awid.LifetimeEphemeral,
				"custody":      awid.CustodySelf,
				"api_key":      "workspace-sk-ephemeral",
			})
		case "/v1/connect":
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
		Role:       "backend",
	})
	if err != nil {
		t.Fatalf("runAPIKeyBootstrapInit: %v", err)
	}

	if initAuthHeader != "Bearer "+apiKey {
		t.Fatalf("Authorization=%q", initAuthHeader)
	}
	if initBody["role_name"] != "backend" {
		t.Fatalf("init role_name=%v", initBody["role_name"])
	}
	if initBody["lifetime"] != awid.LifetimeEphemeral {
		t.Fatalf("init lifetime=%v", initBody["lifetime"])
	}
	if connectBody["role"] != "backend" {
		t.Fatalf("connect role=%v", connectBody["role"])
	}
	if result.TeamID != "backend:acme.com" {
		t.Fatalf("team_id=%q", result.TeamID)
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
		t.Fatalf("identity.yaml should not exist for ephemeral API-key init: %v", err)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace.yaml: %v", err)
	}
	if workspace.APIKey != "workspace-sk-ephemeral" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
	}
	if containsStringUnderTree(t, filepath.Join(tmp, ".aw"), apiKey) {
		t.Fatal("AWEB_API_KEY was written to disk")
	}
}

func TestInitBootstrapsFromAPIKeyPersistentWritesIdentity(t *testing.T) {
	t.Parallel()

	const apiKey = "aw_sk_test_persistent"

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)

	var initBody map[string]any
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := initBody["did"].(string)
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
				"server_url":   server.URL,
				"team_cert":    encoded,
				"alias":        "alice",
				"team_id":      "default:alice.aweb.ai",
				"workspace_id": "ws-1",
				"did":          didKey,
				"stable_id":    "did:aw:alice",
				"lifetime":     awid.LifetimePersistent,
				"custody":      awid.CustodySelf,
				"api_key":      "workspace-sk-persistent",
			})
		case "/v1/connect":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:alice.aweb.ai",
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
		WorkingDir:  tmp,
		AwebURL:     externalLikeTestURL(t, server.URL),
		RegistryURL: "https://api.awid.ai",
		APIKey:      apiKey,
		Role:        "backend",
		Persistent:  true,
	})
	if err != nil {
		t.Fatalf("runAPIKeyBootstrapInit persistent: %v", err)
	}

	if initBody["lifetime"] != awid.LifetimePersistent {
		t.Fatalf("init lifetime=%v", initBody["lifetime"])
	}
	if result.TeamID != "default:alice.aweb.ai" {
		t.Fatalf("team_id=%q", result.TeamID)
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
	if identity.StableID != "did:aw:alice" {
		t.Fatalf("stable_id=%q", identity.StableID)
	}
	if identity.Address != "alice.aweb.ai/alice" {
		t.Fatalf("address=%q", identity.Address)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load workspace.yaml: %v", err)
	}
	if workspace.APIKey != "workspace-sk-persistent" {
		t.Fatalf("workspace api_key=%q", workspace.APIKey)
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
				"server_url":   server.URL,
				"team_cert":    encoded,
				"alias":        "alice",
				"team_id":      "backend:acme.com",
				"workspace_id": "ws-1",
				"did":          "did:key:z6MkrWrongResponseDid11111111111111111111111",
				"stable_id":    "",
				"lifetime":     awid.LifetimeEphemeral,
				"custody":      awid.CustodySelf,
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

func TestRunAPIKeyBootstrapInitRejectsResponseLifetimeMismatch(t *testing.T) {
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
				"server_url":   server.URL,
				"team_cert":    encoded,
				"alias":        "alice",
				"team_id":      "default:alice.aweb.ai",
				"workspace_id": "ws-1",
				"did":          didKey,
				"stable_id":    "did:aw:alice",
				"lifetime":     awid.LifetimePersistent,
				"custody":      awid.CustodySelf,
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
	if err == nil || !strings.Contains(err.Error(), "does not match requested lifetime") {
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
				"server_url":   server.URL,
				"team_cert":    encoded,
				"alias":        "alice",
				"team_id":      "backend:acme.com",
				"workspace_id": "ws-1",
				"did":          didKey,
				"stable_id":    "",
				"lifetime":     awid.LifetimeEphemeral,
				"custody":      awid.CustodySelf,
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
						"server_url":   server.URL,
						"team_cert":    encoded,
						"alias":        "alice",
						"team_id":      "backend:acme.com",
						"workspace_id": "ws-1",
						"did":          didKey,
						"stable_id":    "",
						"lifetime":     awid.LifetimeEphemeral,
						"custody":      tc.custody,
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
				"server_url":   server.URL,
				"team_cert":    encoded,
				"alias":        "alice",
				"team_id":      "backend:acme.com",
				"workspace_id": "ws-1",
				"did":          didKey,
				"stable_id":    "",
				"lifetime":     awid.LifetimeEphemeral,
				"custody":      awid.CustodySelf,
				"api_key":      strings.Repeat("k", maxWorkspaceAPIKeyLength+1),
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
