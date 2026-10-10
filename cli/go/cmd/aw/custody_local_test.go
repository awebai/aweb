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

func TestCustodyStartupLocalWorkspaceWithoutIdentityFile(t *testing.T) {
	resetGrantCommandGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	setGrantTestEnv(t, root)
	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/agents/heartbeat" {
			w.WriteHeader(http.StatusOK)
			return
		}
		calls++
		if r.Method != http.MethodGet || r.URL.Path != "/v1/identity-grants/00000000-0000-0000-0000-000000000000/status" {
			t.Errorf("unexpected request: %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]string{"code": "grant_not_found", "contract": "identity-grant-status.v1"})
	}))
	defer server.Close()
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	did := awid.ComputeDIDKey(pub)
	writeLocalTeamSignedRequestWorkspaceForTest(t, root, server.URL, "backend:demo", "resident", did, key)
	if _, err := os.Stat(filepath.Join(root, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("fixture must omit identity.yaml: %v", err)
	}
	home, err := awconfig.ResolveIdentityHome(root, "")
	if err != nil {
		t.Fatal(err)
	}
	svc, err := newCustodyService(home)
	if err != nil {
		t.Fatalf("local custody startup: %v", err)
	}
	if svc.identity.DID != did || svc.identity.StableID != "" || svc.identity.IdentityScope != awid.IdentityModeLocal {
		t.Fatalf("wrong resident identity: %+v", svc.identity)
	}
	status := svc.status(context.Background(), "running", nil)
	if status.Keys["signing_ready"] != true || calls != 1 {
		t.Fatalf("local readiness=%+v, probe calls=%d", status, calls)
	}
	if _, err := os.Stat(filepath.Join(root, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("startup must not create identity.yaml: %v", err)
	}
}

func TestCustodyServeAfterAPIKeyLocalInit(t *testing.T) {
	root := t.TempDir()
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			did, _ := req["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:demo", MemberDIDKey: did, Alias: "resident", IdentityScope: awid.IdentityModeLocal})
			if err != nil {
				t.Error(err)
				return
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Error(err)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": "http://" + r.Host, "team_cert": encoded, "alias": "resident", "team_id": "backend:demo", "workspace_id": "workspace-test", "did": did, "identity_scope": "local", "custody": "self", "api_key": "aw_sk_workspace_fixture"})
		case "/v1/connect":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:demo", "alias": "resident", "agent_id": "resident-agent", "workspace_id": "workspace-test", "repo_id": "repo-test"})
		case "/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "resident-agent", "backend:demo", "resident")
		case "/v1/identity-grants/00000000-0000-0000-0000-000000000000/status":
			requireCertificateAuthForTest(t, r)
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(map[string]string{"code": "grant_not_found", "contract": "identity-grant-status.v1"})
		default:
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	bin := filepath.Join(root, "aw")
	buildAwBinary(t, ctx, bin)
	env := []string{}
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "AW") && !strings.HasPrefix(entry, "HOME=") && !strings.HasPrefix(entry, "XDG_CONFIG_HOME=") {
			env = append(env, entry)
		}
	}
	env = append(env, "HOME="+root, "XDG_CONFIG_HOME="+root, "AWEB_URL="+server.URL, "AWEB_API_KEY=aw_sk_disposable_fixture", "AW_NO_UPDATE_CHECK=1")
	initCmd := exec.CommandContext(ctx, bin, "init", "--alias", "resident", "--json")
	initCmd.Dir = root
	initCmd.Env = env
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("public local init: %v\n%s", err, out)
	}
	identityPath := filepath.Join(root, ".aw", "identity.yaml")
	if _, err := os.Stat(identityPath); !os.IsNotExist(err) {
		t.Fatalf("local init should omit identity.yaml: %v", err)
	}
	serveCtx, stop := context.WithCancel(ctx)
	defer stop()
	serve := exec.CommandContext(serveCtx, bin, "custody", "serve")
	serve.Dir = root
	serve.Env = env
	logPath := filepath.Join(root, "serve.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	serve.Stdout = log
	serve.Stderr = log
	if err := serve.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- serve.Wait() }()
	defer func() {
		stop()
		select {
		case <-done:
		case <-time.After(time.Second):
		}
	}()
	socket := awconfig.CustodySocketPath(filepath.Join(root, ".aw"))
	for {
		var report custodyStatusReport
		if err := custodyHTTP(ctx, socket, http.MethodGet, "/status", nil, &report); err == nil && report.Keys["signing_ready"] == true && report.Keys["encryption_ready"] == true {
			break
		}
		select {
		case err := <-done:
			data, _ := os.ReadFile(logPath)
			t.Fatalf("custody serve exited: %v\n%s", err, data)
		case <-ctx.Done():
			data, _ := os.ReadFile(logPath)
			t.Fatalf("custody readiness timeout: %s", data)
		case <-time.After(20 * time.Millisecond):
		}
	}
	if _, err := os.Stat(identityPath); !os.IsNotExist(err) {
		t.Fatalf("custody must not manufacture identity.yaml: %v", err)
	}
}

func TestCustodyLocalFallbackRefusals(t *testing.T) {
	for _, scenario := range []string{"malformed-identity", "external-home", "global-certificate", "key-mismatch", "missing-certificate"} {
		t.Run(scenario, func(t *testing.T) {
			resetGrantCommandGlobals(t)
			root := t.TempDir()
			t.Chdir(root)
			setGrantTestEnv(t, root)
			pub, key, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			did := awid.ComputeDIDKey(pub)
			writeLocalTeamSignedRequestWorkspaceForTest(t, root, "http://127.0.0.1:1", "backend:demo", "resident", did, key)
			home, err := awconfig.ResolveIdentityHome(root, "")
			if err != nil {
				t.Fatal(err)
			}
			switch scenario {
			case "malformed-identity":
				if err := os.WriteFile(filepath.Join(home.Root, "identity.yaml"), []byte("[invalid yaml"), 0600); err != nil {
					t.Fatal(err)
				}
			case "external-home":
				home = awconfig.IdentityHome{Root: t.TempDir(), Source: awconfig.IdentityHomeFlag}
			case "global-certificate":
				writeGlobalTeamSignedRequestWorkspaceForTest(t, root, "http://127.0.0.1:1", "backend:demo", "resident", did, awid.ComputeStableID(pub), "demo/resident", key)
				if err := os.Remove(filepath.Join(home.Root, "identity.yaml")); err != nil {
					t.Fatal(err)
				}
			case "key-mismatch":
				_, other, err := awid.GenerateKeypair()
				if err != nil {
					t.Fatal(err)
				}
				if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), other); err != nil {
					t.Fatal(err)
				}
			case "missing-certificate":
				if err := os.Remove(awconfig.TeamCertificatePath(root, "backend:demo")); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := newCustodyService(home); err == nil {
				t.Fatalf("accepted %s", scenario)
			}
		})
	}
}
