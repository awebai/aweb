package main

import (
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestTeamExtendCleanDirWithoutAuthorityErrorsClearly(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv(initAPIKeyEnvVar, "")

	err := runTeamHumanExtend(nil, []string{"developer"})
	if err == nil {
		t.Fatal("expected error")
	}
	text := err.Error()
	for _, want := range []string{"--api-key", initAPIKeyEnvVar, "agents/instances", "aw team create"} {
		if !strings.Contains(text, want) {
			t.Fatalf("error missing %q: %v", want, err)
		}
	}
	if strings.Contains(strings.ToLower(text), "eof") {
		t.Fatalf("error should not mention EOF: %v", err)
	}
}

func TestTeamExtendDiscoveryCurrentWorkspaceBeatsSiblingAmbiguity(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "agents", "instances", "other", ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{ActiveTeam: "current:acme.com", Memberships: []awconfig.TeamMembership{{TeamID: "current:acme.com", Alias: "captain", CertPath: ".aw/team-certs/current.pem"}}}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(filepath.Join(root, "agents", "instances", "other"), &awconfig.TeamState{ActiveTeam: "other:acme.com", Memberships: []awconfig.TeamMembership{{TeamID: "other:acme.com", Alias: "other", CertPath: ".aw/team-certs/other.pem"}}}); err != nil {
		t.Fatal(err)
	}
	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != "current-workspace" || authority.TeamID != "current:acme.com" || authority.AnchorDir != root {
		t.Fatalf("authority=%+v", authority)
	}
}

func TestTeamExtendDiscoveryScanAmbiguityAndTeamIDFilter(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	agentsRoot := filepath.Join(root, "agents", "instances")
	for _, tc := range []struct{ name, teamID string }{{"b", "beta:acme.com"}, {"a", "alpha:acme.com"}} {
		home := filepath.Join(agentsRoot, tc.name)
		if err := os.MkdirAll(filepath.Join(home, ".aw"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := awconfig.SaveTeamState(home, &awconfig.TeamState{ActiveTeam: tc.teamID, Memberships: []awconfig.TeamMembership{{TeamID: tc.teamID, Alias: tc.name, CertPath: ".aw/team-certs/" + tc.name + ".pem"}}}); err != nil {
			t.Fatal(err)
		}
	}
	_, err := resolveTeamExtendAuthority(root)
	if err == nil || !strings.Contains(err.Error(), "multiple teams found") || !strings.Contains(err.Error(), "alpha:acme.com") || !strings.Contains(err.Error(), "beta:acme.com") {
		t.Fatalf("ambiguity error=%v", err)
	}
	teamHumanExtendTeamID = "beta:acme.com"
	authority, err := resolveTeamExtendAuthority(root)
	if err != nil {
		t.Fatal(err)
	}
	if authority.Tier != "discovered-agent" || authority.TeamID != "beta:acme.com" || filepath.Base(authority.AnchorDir) != "b" {
		t.Fatalf("authority=%+v", authority)
	}
}

func TestTeamExtendAPIKeyTeamIDMismatchRollsBackWithExplicitAuth(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv(initAPIKeyEnvVar, "")
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(root)

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	const explicitKey = "aw_sk_explicit_extend"
	const returnedKey = "aw_sk_returned_member"
	const actualTeamID = "default:keyteam.aweb.ai"
	var initCalls, connectCalls, removeCalls int
	var removeAuth string
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			initCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer "+explicitKey {
				t.Fatalf("workspace init Authorization=%q", got)
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			didKey, _ := body["did"].(string)
			alias, _ := body["alias"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: actualTeamID, MemberDIDKey: didKey, Alias: alias, Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": server.URL, "team_cert": encoded, "alias": alias, "team_id": actualTeamID, "workspace_id": "ws-rollback", "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": returnedKey})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			connectCalls++
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": actualTeamID, "alias": "rollback", "agent_id": "agent-rollback", "workspace_id": "ws-rollback", "repo_id": "repo-1", "team_did_key": teamDIDKey})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-rollback", actualTeamID, "rollback")
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/agents/remove-member"):
			removeCalls++
			removeAuth = r.Header.Get("Authorization")
			if removeAuth != "Bearer "+explicitKey {
				t.Fatalf("remove Authorization=%q want explicit key", removeAuth)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": actualTeamID, "certificate_id": "removed"})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	teamHumanExtendAPIKey = explicitKey
	teamHumanExtendTeamID = "default:other.aweb.ai"
	initAwebURL = server.URL

	err = runTeamHumanExtend(nil, []string{"rollback", "should-not-run"})
	if err == nil {
		t.Fatal("expected mismatch error")
	}
	if !strings.Contains(err.Error(), "does not match API key team") || !strings.Contains(err.Error(), actualTeamID) || !strings.Contains(err.Error(), teamHumanExtendTeamID) {
		t.Fatalf("unexpected error: %v", err)
	}
	if initCalls != 1 || connectCalls != 1 || removeCalls != 1 {
		t.Fatalf("calls init/connect/remove=%d/%d/%d", initCalls, connectCalls, removeCalls)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "rollback")); !os.IsNotExist(statErr) {
		t.Fatalf("rollback home remains: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(root, "agents", "instances", "should-not-run")); !os.IsNotExist(statErr) {
		t.Fatalf("second member attempted despite mismatch: %v", statErr)
	}
}

func TestTeamExtendAgentHomePlacesSibling(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), memberKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: memberDID, Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	if err := awconfig.SaveControllerKey("acme.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	var certAliases []string
	server := newBYOTRegistryTestServer(t, "acme.com", "ops", controllerKey, func(alias string) { certAliases = append(certAliases, alias) })
	defer server.Close()
	if err := awconfig.SaveControllerMeta("acme.com", &awconfig.ControllerMeta{Domain: "acme.com", ControllerDID: controllerDID, RegistryURL: server.URL, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	teamHumanCreateBYOT = true
	teamHumanCreateNamespace = "acme.com"
	teamHumanCreateRegistryURL = server.URL
	if err := runTeamHumanCreate(nil, []string{"Ops"}); err != nil {
		t.Fatalf("create: %v", err)
	}
	captainHome := filepath.Join(root, "agents", "instances", "captain")
	if err := copyTestTree(filepath.Join(root, ".aw"), filepath.Join(captainHome, ".aw")); err != nil {
		t.Fatalf("seed captain home: %v", err)
	}
	if err := os.Chdir(captainHome); err != nil {
		t.Fatal(err)
	}
	if err := runTeamHumanExtend(nil, []string{"crew"}); err != nil {
		t.Fatalf("extend: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "agents", "instances", "crew", ".aw", "teams.yaml")); err != nil {
		t.Fatalf("crew sibling missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "agents", "instances", "captain", "agents")); !os.IsNotExist(err) {
		t.Fatalf("extend nested agents under caller home: %v", err)
	}
	if strings.Join(certAliases, ",") != "ops,crew" {
		t.Fatalf("cert aliases=%v", certAliases)
	}
}

func copyTestTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		return os.WriteFile(target, data, info.Mode().Perm())
	})
}

func newBYOTRegistryTestServer(t *testing.T, domain, team string, controllerKey ed25519.PrivateKey, onCert func(alias string)) *httptest.Server {
	t.Helper()
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	namespaceCreated := false
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/"+domain:
			if !namespaceCreated {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain, "controller_did": controllerDID, "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			namespaceCreated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": domain, "controller_did": controllerDID, "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/"+domain+"/teams":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": team + ":" + domain, "domain": domain, "name": team, "team_did_key": body["team_did_key"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && strings.HasPrefix(r.URL.Path, "/v1/namespaces/"+domain+"/teams/") && strings.HasSuffix(r.URL.Path, "/certificates"):
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			alias, _ := body["alias"].(string)
			onCert(strings.TrimSpace(alias))
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
}
