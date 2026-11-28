package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// serveProvisionedConnectForTest extends creator-focused HTTP fixtures with
// admission before publication (docs/identity.md:514-519). Server authority is
// exercised by the real-command world; this response preserves these fixtures'
// certificate subject while their placement and recovery assertions run.
func serveProvisionedConnectForTest(t *testing.T, w http.ResponseWriter, r *http.Request) bool {
	t.Helper()
	if r.Method != http.MethodPost || (r.URL.Path != "/v1/connect" && r.URL.Path != "/api/v1/connect") {
		return false
	}
	certificate := requireCertificateAuthForTest(t, r)
	var request connectRequest
	if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
		t.Fatal(err)
	}
	if request.WorkspacePath == "" {
		t.Fatal("provisioned connect must identify its workspace")
	}
	if err := json.NewEncoder(w).Encode(connectResponse{
		TeamID: certificate.Team, Alias: certificate.Alias,
		AgentID: "agent-" + certificate.Alias, WorkspaceID: "workspace-" + certificate.Alias,
		TeamDIDKey: certificate.TeamDIDKey,
	}); err != nil {
		t.Fatal(err)
	}
	return true
}

func resetTeamHumanCreateGlobals(t *testing.T) {
	t.Helper()
	// Team creation's guided onboarding runs aw init's setup, which sets up the
	// Claude Code channel plugin. Both halves of that are host dependencies: the runner
	// execs claude and installs at user scope, and LookPath decides the outcome
	// from whatever is on PATH. Supply both here rather than in each caller -
	// the callers are testing team creation, not plugin setup, and one of them
	// forgetting is a write to the plugin cache the host's live agents read.
	withFakeClaudeOnPath(t)
	withFakeClaudePluginRunner(t, nil)
	oldRunImplicit := initRunImplicitLocalFlow
	oldWizard := guidedOnboardingWizard
	oldPrintReady := initPrintGuidedOnboardingReady
	oldIsTTY := initIsTTY
	oldInitAwebURL := initAwebURL
	oldInitURL := initURL
	oldInitAWIDRegistry := initAWIDRegistry
	oldServerFlag := serverFlag
	oldJSON := jsonFlag
	oldBYOT := teamHumanCreateBYOT
	oldName := teamHumanCreateName
	oldNamespace := teamHumanCreateNamespace
	oldDisplayName := teamHumanCreateDisplayName
	oldServiceURL := teamHumanCreateServiceURL
	oldRegistryURL := teamHumanCreateRegistryURL
	oldAlias := teamHumanCreateAlias
	oldCreateUsername := teamHumanCreateUsername
	oldFirstLocal := teamHumanCreateFirstLocal
	oldFirstGlobal := teamHumanCreateFirstGlobal
	oldRemoveAPIKey := teamHumanRemoveAPIKey
	oldReplaceTeamID := teamHumanReplaceKeyTeamID
	oldReplaceOldDID := teamHumanReplaceKeyOldDID
	oldReplaceNewDID := teamHumanReplaceKeyNewDID
	oldReplaceOldCertID := teamHumanReplaceKeyOldCertID
	oldReplaceHome := teamHumanReplaceKeyHome
	oldReplaceGenerateNewKey := teamHumanReplaceKeyGenerateNewKey
	oldReplaceAwebURL := teamHumanReplaceKeyAwebURL
	oldReplaceRegistryURL := teamHumanReplaceKeyRegistryURL
	teamHumanReplaceKeyTeamID = ""
	teamHumanReplaceKeyOldDID = ""
	teamHumanReplaceKeyNewDID = ""
	teamHumanReplaceKeyOldCertID = ""
	teamHumanReplaceKeyHome = ""
	teamHumanReplaceKeyGenerateNewKey = false
	teamHumanReplaceKeyAwebURL = ""
	teamHumanReplaceKeyRegistryURL = ""
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldRunImplicit
		guidedOnboardingWizard = oldWizard
		initPrintGuidedOnboardingReady = oldPrintReady
		initIsTTY = oldIsTTY
		initAwebURL = oldInitAwebURL
		initURL = oldInitURL
		initAWIDRegistry = oldInitAWIDRegistry
		serverFlag = oldServerFlag
		jsonFlag = oldJSON
		teamHumanCreateBYOT = oldBYOT
		teamHumanCreateName = oldName
		teamHumanCreateNamespace = oldNamespace
		teamHumanCreateDisplayName = oldDisplayName
		teamHumanCreateServiceURL = oldServiceURL
		teamHumanCreateRegistryURL = oldRegistryURL
		teamHumanCreateAlias = oldAlias
		teamHumanCreateUsername = oldCreateUsername
		teamHumanCreateFirstLocal = oldFirstLocal
		teamHumanCreateFirstGlobal = oldFirstGlobal
		teamHumanRemoveAPIKey = oldRemoveAPIKey
		teamHumanReplaceKeyTeamID = oldReplaceTeamID
		teamHumanReplaceKeyOldDID = oldReplaceOldDID
		teamHumanReplaceKeyNewDID = oldReplaceNewDID
		teamHumanReplaceKeyOldCertID = oldReplaceOldCertID
		teamHumanReplaceKeyHome = oldReplaceHome
		teamHumanReplaceKeyGenerateNewKey = oldReplaceGenerateNewKey
		teamHumanReplaceKeyAwebURL = oldReplaceAwebURL
		teamHumanReplaceKeyRegistryURL = oldReplaceRegistryURL
	})
	initIsTTY = func() bool { return false }
	initPrintGuidedOnboardingReady = func(result *guidedOnboardingResult) {}
	initAwebURL = ""
	initURL = ""
	initAWIDRegistry = ""
	serverFlag = ""
	jsonFlag = false
	teamHumanCreateBYOT = false
	teamHumanCreateName = ""
	teamHumanCreateNamespace = ""
	teamHumanCreateDisplayName = ""
	teamHumanCreateServiceURL = ""
	teamHumanCreateRegistryURL = ""
	teamHumanCreateAlias = ""
	teamHumanCreateUsername = ""
	teamHumanCreateFirstLocal = false
	teamHumanCreateFirstGlobal = false
	teamHumanRemoveAPIKey = ""
}

// Team creation's guided onboarding reaches EnsureClaudeChannelPlugin through
// aw init's setup (SetupChannelMCP), so every test that resets
// these globals inherits it. Unstubbed it shells out to claude and installs the
// aweb-channel plugin at USER scope on whatever host runs the suite - the same
// cache the live agents on that host read - and it reports a different outcome
// depending on whether claude is on PATH and the marketplace is reachable.
//
// PATH is emptied here before the helper runs, so this fails on a host that has
// claude installed as well as on one that does not: the assertion is that the
// helper supplies the dependency rather than borrowing the host's.
func TestResetTeamHumanCreateGlobalsNeutralizesChannelPluginSetup(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	resetTeamHumanCreateGlobals(t)

	if reflect.ValueOf(runClaudeChannelPluginCommand).Pointer() ==
		reflect.ValueOf(runClaudeChannelPluginCommandExec).Pointer() {
		t.Fatal("resetTeamHumanCreateGlobals left the real executor installed: every test using this helper writes the host's user-scope plugin cache")
	}

	result := EnsureClaudeChannelPlugin(channelPluginOptions{RequireClaude: true})
	if result.Error != nil {
		t.Fatalf("channel plugin setup still depends on the host PATH: %v", result.Error)
	}
	if !result.Created || result.Skipped {
		t.Fatalf("expected a deterministic install result, got %+v", result)
	}
}

func TestFormatTeamHumanCreatePrintsAgentHome(t *testing.T) {
	out := formatTeamHumanCreate(teamHumanCreateOutput{TeamName: "eng", TeamID: "eng:local", Alias: "eng", HomeDir: "/repo"})
	if !strings.Contains(out, "Agent home: /repo") {
		t.Fatalf("output missing home path:\n%s", out)
	}
}

func TestTeamHumanCreateUsesImplicitLocalTeamName(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	t.Chdir(t.TempDir())

	var got implicitLocalInitRequest
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		got = req
		return connectOutput{Status: "connected", TeamID: "eng:local", Alias: req.Alias, AwebURL: req.AwebURL, WorkspaceID: "ws-1"}, nil
	}

	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if got.TeamName != "eng" {
		t.Fatalf("TeamName=%q, want eng", got.TeamName)
	}
	if got.Alias != "eng" {
		t.Fatalf("Alias=%q, want eng", got.Alias)
	}
}

func TestTeamHumanCreateHostedRegistryFailsNonInteractiveWithoutUsername(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "https://app.aweb.ai")
	t.Setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
	t.Chdir(t.TempDir())

	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		t.Fatalf("guidedOnboardingWizard should not run when required non-TTY flags are missing: %+v", req)
		return nil, nil
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "missing required flag: --username") {
		t.Fatalf("error=%v", err)
	}
}

func TestTeamHumanCreateHostedRegistryUsesGuidedOnboardingWhenNoIdentity(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "https://app.aweb.ai")
	t.Setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
	root := t.TempDir()
	t.Chdir(root)
	teamHumanCreateUsername = "eng-user"

	var got guidedOnboardingRequest
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		got = req
		return &guidedOnboardingResult{}, nil
	}
	calledLocal := false
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		calledLocal = true
		return connectOutput{}, nil
	}

	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if calledLocal {
		t.Fatal("hosted registry should not use implicit local flow")
	}
	if got.WorkingDir != root || got.BaseURL == "" || got.RegistryURL == "" {
		t.Fatalf("guided request not populated: %+v", got)
	}
	if !got.NonInteractive {
		t.Fatalf("expected non-interactive request when not TTY: %+v", got)
	}
	if got.Username != "eng-user" {
		t.Fatalf("username=%q want eng-user", got.Username)
	}
	if got.Alias != "eng" {
		t.Fatalf("alias=%q want eng", got.Alias)
	}
}

func TestHeadlessTeamAdminCreateAcceptsWorkspaceKey(t *testing.T) {
	for _, tc := range []struct {
		name   string
		suffix string
	}{
		{name: "base", suffix: ""},
		{name: "apisuffixed", suffix: "/api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			const apiKey = "aw_sk_create_apikey"
			teamPub, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			teamDIDKey := awid.ComputeDIDKey(teamPub)

			var initPosts atomic.Int32
			var server *httptest.Server
			server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
				if r.Method == http.MethodGet && r.URL.Path == "/api/v1/teams/current" {
					_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "11111111-1111-4111-8111-111111111111", "canonical_team_id": "backend:acme.test", "api_key_kind": "workspace"})
					return
				}
				switch r.URL.Path {
				case "/api/v1/workspaces/init":
					initPosts.Add(1)
					if r.Method != http.MethodPost || r.Header.Get("Authorization") != "Bearer "+apiKey {
						t.Error("workspace init did not use the supplied workspace key")
					}
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					didKey, _ := body["did"].(string)
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
						Team:          "backend:acme.test",
						MemberDIDKey:  didKey,
						Alias:         "eng",
						IdentityScope: awid.IdentityModeLocal,
					})
					if err != nil {
						t.Fatal(err)
					}
					encoded, err := awid.EncodeTeamCertificateHeader(cert)
					if err != nil {
						t.Fatal(err)
					}
					_ = json.NewEncoder(w).Encode(map[string]any{
						"server_url":     serverURL,
						"team_cert":      encoded,
						"alias":          "eng",
						"team_id":        "backend:acme.test",
						"workspace_id":   "ws-1",
						"did":            didKey,
						"stable_id":      "",
						"identity_scope": awid.IdentityModeLocal,
						"custody":        awid.CustodySelf,
						"api_key":        "workspace-sk-ephemeral",
					})
				case "/api/v1/connect", "/v1/connect":
					requireCertificateAuthForTest(t, r)
					_ = json.NewEncoder(w).Encode(map[string]any{
						"team_id":      "backend:acme.test",
						"alias":        "eng",
						"agent_id":     "agent-1",
						"workspace_id": "ws-1",
						"repo_id":      "",
						"team_did_key": teamDIDKey,
					})
				case "/v1/agents/heartbeat", "/api/v1/agents/heartbeat":
					w.WriteHeader(http.StatusOK)
				case "/v1/agents/me/encryption-key", "/api/v1/agents/me/encryption-key":
					writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "backend:acme.test", "eng")
				default:
					t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
				}
			})

			dir := t.TempDir()
			bin := filepath.Join(t.TempDir(), "aw")
			buildAwBinary(t, t.Context(), bin)
			cmd := exec.CommandContext(t.Context(), bin, "team", "admin", "create", "eng", "--json")
			cmd.Dir = dir
			cmd.Env = append(testCommandEnv(t.TempDir()), "AWEB_API_KEY="+apiKey, "AWEB_URL="+server.URL+tc.suffix)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("headless team create: %v\n%s", err, out)
			}
			cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(dir, "backend:acme.test"))
			if err != nil || cert.Alias != "eng" || cert.Team != "backend:acme.test" {
				t.Fatalf("create did not persist the expected membership: %+v, %v", cert, err)
			}
			if count := initPosts.Load(); count != 1 {
				t.Fatalf("workspace init requests=%d, want 1", count)
			}
		})
	}
}

func TestTeamHumanCreateRootOperatorDefaultsToTeamName(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	const apiKey = "aw_sk_create_apikey"
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	var gotInitAlias string
	var server *httptest.Server
	server = newLocalHTTPServerHandlerWithURL(t, func(serverURL string, w http.ResponseWriter, r *http.Request) {
		if serveAPIKeyCreationTeamRead(w, r, "backend:acme.com") {
			return
		}
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			gotInitAlias, _ = body["alias"].(string)
			didKey, _ := body["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:acme.com", MemberDIDKey: didKey, Alias: gotInitAlias, IdentityScope: awid.IdentityModeLocal})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": serverURL, "team_cert": encoded, "alias": gotInitAlias, "team_id": "backend:acme.com", "workspace_id": "ws-1", "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "workspace-sk-ephemeral"})
		case "/api/v1/connect", "/v1/connect":
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "backend:acme.com", "alias": gotInitAlias, "agent_id": "agent-1", "workspace_id": "ws-1", "repo_id": "", "team_did_key": teamDIDKey})
		case "/v1/agents/heartbeat", "/api/v1/agents/heartbeat":
			w.WriteHeader(http.StatusOK)
		case "/v1/agents/me/encryption-key", "/api/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "backend:acme.com", gotInitAlias)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	})

	t.Setenv("AWEB_API_KEY", apiKey)
	t.Setenv("AWEB_URL", server.URL)
	t.Chdir(t.TempDir())
	jsonFlag = true

	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if gotInitAlias != "eng" {
		t.Fatalf("workspace init alias=%q want root operator alias eng", gotInitAlias)
	}
}

func TestTeamHumanCreateExistingHostedManagedIdentityFailsClearly(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Chdir(root)
	if err := os.MkdirAll(filepath.Join(root, ".aw"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: "did:key:zHosted", StableID: "did:aw:zHosted", Address: "alice.aweb.ai/alice", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, RegistryURL: "https://api.awid.ai", CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "hosted-managed") || strings.Contains(err.Error(), "local awid registry") {
		t.Fatalf("error=%v", err)
	}
}

func TestTeamHumanCreateFirstAgentGlobalHostedBootstrapAllowed(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv(initAPIKeyEnvVar, "")
	// The hosted bootstrap is allowed when no registry is named.
	t.Setenv("AWID_REGISTRY_URL", "")
	teamHumanCreateFirstGlobal = true
	teamHumanCreateServiceURL = "https://app.example"
	teamHumanCreateUsername = "eng-user"
	var captured guidedOnboardingRequest
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		captured = req
		if err := os.MkdirAll(filepath.Join(req.WorkingDir, ".aw"), 0o755); err != nil {
			return nil, err
		}
		return &guidedOnboardingResult{}, nil
	}

	if err := runTeamHumanCreate(nil, []string{"Eng"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if !captured.Global || captured.Name != "eng" || captured.Alias != "" {
		t.Fatalf("hosted first-agent-global request = %+v", captured)
	}
}

func TestTeamHumanCreateFirstAgentGlobalLocalNoContextFailsClosed(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv(initAPIKeyEnvVar, "")
	t.Setenv("AWID_REGISTRY_URL", "http://localhost:8010")
	teamHumanCreateFirstGlobal = true
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		t.Fatal("implicit local bootstrap should not run for --first-agent-global")
		return connectOutput{}, nil
	}

	err := runTeamHumanCreate(nil, []string{"Eng"})
	if err == nil || !strings.Contains(err.Error(), "--first-agent-global requires an existing global identity or namespace/hosted context") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(root, ".aw")); !os.IsNotExist(statErr) {
		t.Fatalf("local state created despite fail-closed first-agent-global: %v", statErr)
	}
}

func TestTeamHumanCreateLocalExistingMembershipFailsBeforeRegistry(t *testing.T) {
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
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{ActiveTeam: "old:acme.com", Memberships: []awconfig.TeamMembership{{TeamID: "old:acme.com", Alias: "alice", CertPath: ".aw/team-certs/old_acme_com.json", JoinedAt: "2026-01-01T00:00:00Z"}}}); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("acme.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	var calledRegistry bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledRegistry = true
		t.Fatalf("registry should not be called when local workspace already has a team: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	teamHumanCreateBYOT = true
	teamHumanCreateNamespace = "acme.com"
	teamHumanCreateRegistryURL = server.URL

	err = runTeamHumanCreate(nil, []string{"Ops"})
	if err == nil || !strings.Contains(err.Error(), "local identities can only enroll in one team") {
		t.Fatalf("error=%v", err)
	}
	if calledRegistry {
		t.Fatal("registry called despite local one-team guard")
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".awid", "team-keys", "acme.com", "ops.key")); !os.IsNotExist(statErr) {
		t.Fatalf("team key created despite local one-team guard: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(root, ".aw", "team-certs", "ops_acme_com.json")); !os.IsNotExist(statErr) {
		t.Fatalf("team cert created despite local one-team guard: %v", statErr)
	}
}

func TestTeamHumanCreateExistingSelfCustodialIdentityCreatesTeam(t *testing.T) {
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
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: memberDID, StableID: "did:aw:zSelf", Address: "acme.com/alice", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("acme.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	var gotTeam map[string]any
	var gotCert map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		if serveProvisionedConnectForTest(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			certificate := requireCertificateAuthForTest(t, r)
			if err := json.NewEncoder(w).Encode(connectResponse{TeamID: certificate.Team, Alias: certificate.Alias, AgentID: certificate.CertificateID, WorkspaceID: "fixture-" + certificate.CertificateID, TeamDIDKey: certificate.TeamDIDKey}); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "controller_did": body["controller_did"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "name": "alice", "did_aw": "did:aw:zSelf", "current_did_key": memberDID})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			if err := json.NewDecoder(r.Body).Decode(&gotTeam); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:acme.com", "domain": "acme.com", "name": gotTeam["name"], "team_did_key": gotTeam["team_did_key"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/eng/certificates":
			if err := json.NewDecoder(r.Body).Decode(&gotCert); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		case strings.HasSuffix(r.URL.Path, "/encryption-key") && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			// aweb-abfd: creating/enrolling a member now publishes the E2E
			// encryption-key assertion (POST to the registry for global
			// identities, PUT to the aweb service where a binding exists).
			_, _ = w.Write([]byte("{}"))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	teamHumanCreateFirstGlobal = true
	// Keep admission and encryption publication on this fixture service.
	initAwebURL = server.URL

	if err := runTeamHumanCreate(nil, []string{"Eng"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if gotTeam["name"] != "eng" {
		t.Fatalf("team name=%v", gotTeam["name"])
	}
	if _, err := os.Stat(filepath.Join(home, ".awid", "team-keys", "acme.com", "eng.key")); err != nil {
		t.Fatalf("team key missing: %v", err)
	}
	if gotCert["certificate"] == "" || gotCert["certificate"] == nil {
		t.Fatalf("certificate registration payload missing certificate: %#v", gotCert)
	}
	cert, err := awconfig.LoadTeamCertificateForTeam(root, "eng:acme.com")
	if err != nil {
		t.Fatalf("team certificate missing: %v", err)
	}
	if cert.Alias != "eng" || cert.MemberDIDKey != memberDID || cert.MemberAddress != "acme.com/alice" {
		t.Fatalf("certificate fields: alias=%q did=%q address=%q", cert.Alias, cert.MemberDIDKey, cert.MemberAddress)
	}
	teamState, err := awconfig.LoadTeamState(root)
	if err != nil {
		t.Fatalf("team state missing: %v", err)
	}
	if teamState.ActiveTeam != "eng:acme.com" || teamState.Membership("eng:acme.com") == nil {
		t.Fatalf("team state active=%q memberships=%v", teamState.ActiveTeam, teamState.Memberships)
	}
	if _, err := resolveSelectionForDir(root); err != nil {
		t.Fatalf("active team should resolve after create: %v", err)
	}
	// The creator self-enrolls as the first member; without an encryption key it
	// could not do E2E messaging, so the create flow must ensure one.
	requireWorktreeEncryptionKeyForTest(t, root)
}

func TestTeamHumanCreateBYOTFirstAgentGlobalWithoutAuthorityFailsBeforeRegister(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Chdir(root)
	var calledRegistry bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calledRegistry = true
		t.Fatalf("registry should not be called for --byot --first-agent-global without namespace authority: %s %s", r.Method, r.URL.Path)
	}))
	defer server.Close()
	teamHumanCreateBYOT = true
	teamHumanCreateNamespace = "acme.com"
	teamHumanCreateRegistryURL = server.URL
	teamHumanCreateFirstGlobal = true

	err := runTeamHumanCreate(nil, []string{"Ops"})
	if err == nil || !strings.Contains(err.Error(), "--first-agent-global with --byot requires namespace controller authority") || !strings.Contains(err.Error(), "aw id create") {
		t.Fatalf("create-specific authority error=%v", err)
	}
	if calledRegistry {
		t.Fatal("registry called despite fail-closed --byot without namespace authority")
	}
	if _, statErr := os.Lstat(filepath.Join(home, ".awid", "team-keys", "acme.com", "ops.key")); !os.IsNotExist(statErr) {
		t.Fatalf("team key created despite fail-closed --byot without namespace authority: %v", statErr)
	}
	if _, statErr := os.Lstat(filepath.Join(root, ".aw", "teams.yaml")); !os.IsNotExist(statErr) {
		t.Fatalf("team state created despite fail-closed --byot without namespace authority: %v", statErr)
	}
}

func TestTeamHumanCreateBYOTFirstAgentGlobalMintsWithNamespaceAuthority(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	// Exercise the founding command's recorded registry in publication.
	t.Setenv("AWID_REGISTRY_URL", "")
	t.Chdir(root)
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	controllerDID := awid.ComputeDIDKey(controllerKey.Public().(ed25519.PublicKey))
	if err := awconfig.SaveControllerKey("acme.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	var createdDIDAW, createdDIDKey string
	var namespaceCreated bool
	var claimCalls, certCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		if serveProvisionedConnectForTest(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			certificate := requireCertificateAuthForTest(t, r)
			if err := json.NewEncoder(w).Encode(connectResponse{TeamID: certificate.Team, Alias: certificate.Alias, AgentID: certificate.CertificateID, WorkspaceID: "fixture-" + certificate.CertificateID, TeamDIDKey: certificate.TeamDIDKey}); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			if !namespaceCreated {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "controller_did": controllerDID, "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["domain"] != "acme.com" || body["controller_did"] != controllerDID {
				t.Fatalf("namespace body=%v", body)
			}
			namespaceCreated = true
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "controller_did": controllerDID, "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/addresses/claims":
			claimCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["address_name"] != "ops" {
				t.Fatalf("address_name=%v", body["address_name"])
			}
			createdDIDAW, _ = body["did_aw"].(string)
			createdDIDKey, _ = body["current_did_key"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "claimed", "domain": "acme.com", "name": "ops", "did_aw": createdDIDAW, "current_did_key": createdDIDKey, "did_status": "created", "address_status": "created"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did/"+createdDIDAW+"/encryption-key":
			writeRegistryEncryptionKeyAssertionForTest(t, w, r)
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-ops", "ops:acme.com", "ops")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/ops":
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "name": "ops", "did_aw": createdDIDAW, "current_did_key": createdDIDKey})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["name"] != "ops" {
				t.Fatalf("team name=%v", body["name"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "ops:acme.com", "domain": "acme.com", "name": "ops", "team_did_key": body["team_did_key"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/ops/certificates":
			certCalls++
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	teamHumanCreateBYOT = true
	teamHumanCreateNamespace = "acme.com"
	teamHumanCreateRegistryURL = server.URL
	teamHumanCreateFirstGlobal = true
	// Keep admission and encryption publication on this fixture service.
	initAwebURL = server.URL

	if err := runTeamHumanCreate(nil, []string{"Ops"}); err != nil {
		var publication *requiredEncryptionPublicationError
		if errors.As(err, &publication) {
			t.Fatalf("runTeamHumanCreate: %v: %v", err, publication)
		}
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if claimCalls != 1 || certCalls != 1 {
		t.Fatalf("claim calls=%d cert calls=%d", claimCalls, certCalls)
	}
	identity, _, err := awconfig.LoadWorktreeIdentityFromDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if identity.IdentityScope != awid.IdentityModeGlobal || identity.Address != "acme.com/ops" || identity.StableID != createdDIDAW || identity.RegistryURL != server.URL {
		t.Fatalf("identity=%+v created=%s", identity, createdDIDAW)
	}
	cert, err := awconfig.LoadTeamCertificateForTeam(root, "ops:acme.com")
	if err != nil {
		t.Fatalf("cert missing: %v", err)
	}
	if cert.MemberDIDAW != createdDIDAW || cert.MemberDIDKey != createdDIDKey || cert.MemberAddress != "acme.com/ops" || cert.IdentityScope != awid.IdentityModeGlobal {
		t.Fatalf("cert fields did_aw=%q did_key=%q address=%q lifetime=%q", cert.MemberDIDAW, cert.MemberDIDKey, cert.MemberAddress, cert.IdentityScope)
	}
}

func TestTeamHumanCreateBYOTEnrollsCreatorAndPreservesExistingMembership(t *testing.T) {
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
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: memberDID, StableID: "did:aw:zSelf", Address: "acme.com/alice", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(root, &awconfig.TeamState{ActiveTeam: "old:acme.com", Memberships: []awconfig.TeamMembership{{TeamID: "old:acme.com", Alias: "alice", CertPath: ".aw/team-certs/old_acme_com.json", JoinedAt: "2026-01-01T00:00:00Z"}}}); err != nil {
		t.Fatal(err)
	}
	_, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("acme.com", controllerKey); err != nil {
		t.Fatal(err)
	}
	var certCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveUnadvertisedHealth(w, r) {
			return
		}
		if serveProvisionedConnectForTest(t, w, r) {
			return
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			certificate := requireCertificateAuthForTest(t, r)
			if err := json.NewEncoder(w).Encode(connectResponse{TeamID: certificate.Team, Alias: certificate.Alias, AgentID: certificate.CertificateID, WorkspaceID: "fixture-" + certificate.CertificateID, TeamDIDKey: certificate.TeamDIDKey}); err != nil {
				t.Error(err)
			}
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "controller_did": body["controller_did"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/acme.com/addresses/alice":
			_ = json.NewEncoder(w).Encode(map[string]any{"domain": "acme.com", "name": "alice", "did_aw": "did:aw:zSelf", "current_did_key": memberDID})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if body["name"] != "ops" {
				t.Fatalf("team name=%v", body["name"])
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "ops:acme.com", "domain": "acme.com", "name": "ops", "team_did_key": body["team_did_key"], "created_at": "2026-06-20T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/acme.com/teams/ops/certificates":
			certCalls++
			w.WriteHeader(http.StatusCreated)
		case strings.HasSuffix(r.URL.Path, "/encryption-key") && (r.Method == http.MethodPost || r.Method == http.MethodPut):
			// aweb-abfd: creating/enrolling a member now publishes the E2E
			// encryption-key assertion (POST to the registry for global
			// identities, PUT to the aweb service where a binding exists).
			_, _ = w.Write([]byte("{}"))
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", server.URL)
	teamHumanCreateBYOT = true
	teamHumanCreateNamespace = "acme.com"
	teamHumanCreateRegistryURL = server.URL
	teamHumanCreateAlias = "captain"
	teamHumanCreateFirstGlobal = true
	// Keep admission and encryption publication on this fixture service.
	initAwebURL = server.URL

	if err := runTeamHumanCreate(nil, []string{"Ops"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if certCalls != 1 {
		t.Fatalf("cert calls=%d", certCalls)
	}
	state, err := awconfig.LoadTeamState(root)
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveTeam != "ops:acme.com" || state.Membership("ops:acme.com") == nil || state.Membership("old:acme.com") == nil {
		t.Fatalf("team state active=%q memberships=%v", state.ActiveTeam, state.Memberships)
	}
	cert, err := awconfig.LoadTeamCertificateForTeam(root, "ops:acme.com")
	if err != nil {
		t.Fatalf("cert missing: %v", err)
	}
	if cert.Alias != "captain" || cert.MemberDIDKey != memberDID || cert.MemberAddress != "acme.com/alice" {
		t.Fatalf("cert fields alias=%q did=%q address=%q", cert.Alias, cert.MemberDIDKey, cert.MemberAddress)
	}
}
