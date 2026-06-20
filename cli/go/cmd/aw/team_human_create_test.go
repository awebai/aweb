package main

import (
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

func resetTeamHumanCreateGlobals(t *testing.T) {
	t.Helper()
	oldRunImplicit := initRunImplicitLocalFlow
	oldWizard := guidedOnboardingWizard
	oldPrintReady := initPrintGuidedOnboardingReady
	oldIsTTY := initIsTTY
	oldJSON := jsonFlag
	oldBYOT := teamHumanCreateBYOT
	oldName := teamHumanCreateName
	oldNamespace := teamHumanCreateNamespace
	oldDisplayName := teamHumanCreateDisplayName
	oldServiceURL := teamHumanCreateServiceURL
	oldRegistryURL := teamHumanCreateRegistryURL
	oldAlias := teamHumanCreateAlias
	oldProfiles := teamHumanCreateProfiles
	oldAddLocal := teamHumanAddLocal
	oldAddGlobal := teamHumanAddGlobal
	oldAddLayoutOnly := teamHumanAddLayoutOnly
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldRunImplicit
		guidedOnboardingWizard = oldWizard
		initPrintGuidedOnboardingReady = oldPrintReady
		initIsTTY = oldIsTTY
		jsonFlag = oldJSON
		teamHumanCreateBYOT = oldBYOT
		teamHumanCreateName = oldName
		teamHumanCreateNamespace = oldNamespace
		teamHumanCreateDisplayName = oldDisplayName
		teamHumanCreateServiceURL = oldServiceURL
		teamHumanCreateRegistryURL = oldRegistryURL
		teamHumanCreateAlias = oldAlias
		teamHumanCreateProfiles = oldProfiles
		teamHumanAddLocal = oldAddLocal
		teamHumanAddGlobal = oldAddGlobal
		teamHumanAddLayoutOnly = oldAddLayoutOnly
	})
	initIsTTY = func() bool { return false }
	initPrintGuidedOnboardingReady = func(result *guidedOnboardingResult) {}
	jsonFlag = false
	teamHumanCreateBYOT = false
	teamHumanCreateName = ""
	teamHumanCreateNamespace = ""
	teamHumanCreateDisplayName = ""
	teamHumanCreateServiceURL = ""
	teamHumanCreateRegistryURL = ""
	teamHumanCreateAlias = ""
	teamHumanCreateProfiles = nil
	teamHumanAddLocal = false
	teamHumanAddGlobal = false
	teamHumanAddLayoutOnly = false
}

func TestFormatTeamHumanCreatePrintsAgentHome(t *testing.T) {
	out := formatTeamHumanCreate(teamHumanCreateOutput{TeamName: "eng", TeamID: "eng:local", Alias: "eng", HomeDir: "/repo", ProfileMode: "library"})
	if !strings.Contains(out, "Agent home: /repo") {
		t.Fatalf("output missing home path:\n%s", out)
	}
}

func TestFormatTeamHumanAddPrintsEachAgentHome(t *testing.T) {
	out := formatTeamHumanAdd(teamHumanAddOutput{AgentsRoot: "/repo/agents/instances", Agents: []teamHumanAddedAgent{{Name: "reviewer", HomeDir: "/repo/agents/instances/reviewer"}}, NoLibrary: false})
	if !strings.Contains(out, "- reviewer: /repo/agents/instances/reviewer") {
		t.Fatalf("output missing agent path:\n%s", out)
	}
}

func TestTeamHumanCreateEmptyProfileUsesImplicitLocalTeamNameAndNoLibrary(t *testing.T) {
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

func TestTeamHumanAddLayoutOnlyCreatesEmptyIdentityOnlyHomes(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	teamHumanAddLayoutOnly = true

	if err := runTeamHumanAdd(nil, []string{"developer", "reviewer"}); err != nil {
		t.Fatalf("runTeamHumanAdd: %v", err)
	}
	for _, name := range []string{"developer", "reviewer"} {
		home := root + "/agents/instances/" + name
		for _, rel := range []string{"AGENTS.md", ".aw/profile", "skills", "artifacts"} {
			if _, err := os.Stat(home + "/" + rel); !os.IsNotExist(err) {
				t.Fatalf("empty-profile layout-only home %s unexpectedly has %s (err=%v)", home, rel, err)
			}
		}
	}
}

func TestTeamHumanAddRejectsExistingHomeThroughSymlinkedParent(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	outside := t.TempDir()
	if err := os.MkdirAll(outside+"/developer", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(root+"/agents", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, root+"/agents/instances"); err != nil {
		t.Fatal(err)
	}

	err := runTeamHumanAdd(nil, []string{"developer"})
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(outside + "/developer/.aw"); !os.IsNotExist(statErr) {
		t.Fatalf("identity path wrote through symlinked parent, stat err=%v", statErr)
	}
}

func TestTeamHumanAddRejectsExistingAwSymlinkState(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	home := root + "/agents/instances/developer"
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(root+"/missing-aw-target", home+"/.aw"); err != nil {
		t.Fatal(err)
	}
	teamHumanAddLayoutOnly = true

	err := runTeamHumanAdd(nil, []string{"developer"})
	if err == nil || !strings.Contains(err.Error(), "already has identity state") {
		t.Fatalf("error=%v", err)
	}
}

func TestTeamHumanAddRejectsLayoutOnlyWithLibraryProfile(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Chdir(t.TempDir())
	teamHumanAddLayoutOnly = true

	err := runTeamHumanAdd(nil, []string{"developer@aweb.engineering-pack/developer"})
	if err == nil || !strings.Contains(err.Error(), "--layout-only") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat("agents/instances/developer"); !os.IsNotExist(statErr) {
		t.Fatalf("profile-bound add must not create layout-only home, stat err=%v", statErr)
	}
}

func TestTeamHumanCreateHostedRegistryUsesGuidedOnboardingWhenNoIdentity(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "https://app.aweb.ai")
	t.Setenv("AWID_REGISTRY_URL", "https://api.awid.ai")
	root := t.TempDir()
	t.Chdir(root)

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
	if got.Alias != "eng" {
		t.Fatalf("alias=%q want eng", got.Alias)
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
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: "did:key:zHosted", StableID: "did:aw:zHosted", Address: "alice.aweb.ai/alice", Custody: awid.CustodySelf, Lifetime: awid.LifetimePersistent, RegistryURL: "https://api.awid.ai", CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
		t.Fatal(err)
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "hosted-managed") || strings.Contains(err.Error(), "local awid registry") {
		t.Fatalf("error=%v", err)
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
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: memberDID, StableID: "did:aw:zSelf", Address: "acme.com/alice", Custody: awid.CustodySelf, Lifetime: awid.LifetimePersistent, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
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
		switch {
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
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", server.URL)

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
	if err := awconfig.SaveWorktreeIdentityTo(filepath.Join(root, ".aw", "identity.yaml"), &awconfig.WorktreeIdentity{DID: memberDID, StableID: "did:aw:zSelf", Address: "acme.com/alice", Custody: awid.CustodySelf, Lifetime: awid.LifetimePersistent, CreatedAt: time.Now().UTC().Format(time.RFC3339)}); err != nil {
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
		switch {
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
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	teamHumanCreateBYOT = true
	teamHumanCreateNamespace = "acme.com"
	teamHumanCreateRegistryURL = server.URL
	teamHumanCreateAlias = "captain"

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

func TestTeamHumanCreateRejectsVersionedLibraryProfileBeforeIdentity(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	root := t.TempDir()
	t.Chdir(root)
	teamHumanCreateProfiles = []string{"aweb.engineering-pack/developer@0.1.0"}
	called := false
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		called = true
		return connectOutput{}, nil
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "versioned Library profile selectors are not supported") {
		t.Fatalf("error=%v", err)
	}
	if called {
		t.Fatal("versioned selector should fail before identity creation")
	}
	if _, statErr := os.Lstat(root + "/.aw"); !os.IsNotExist(statErr) {
		t.Fatalf("identity state created despite unsupported selector, stat err=%v", statErr)
	}
}

func TestTeamHumanAddRejectsVersionedLibraryProfileBeforeHomeCreate(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)

	err := runTeamHumanAdd(nil, []string{"developer@aweb.engineering-pack/developer@0.1.0"})
	if err == nil || !strings.Contains(err.Error(), "versioned Library profile selectors are not supported") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(root + "/agents"); !os.IsNotExist(statErr) {
		t.Fatalf("agent home state created despite unsupported selector, stat err=%v", statErr)
	}
}

func TestTeamHumanCreateLibraryProfileRequiresPluginAfterIdentity(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Chdir(t.TempDir())
	teamHumanCreateProfiles = []string{"aweb.engineering-pack/developer"}
	called := false
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		called = true
		return connectOutput{Status: "connected", TeamID: "eng:local", Alias: req.Alias, AwebURL: req.AwebURL, WorkspaceID: "ws-1"}, nil
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "aw library plugin is not installed") {
		t.Fatalf("error=%v", err)
	}
	if !called {
		t.Fatal("profile-bound create should create identity before Library bind/materialize")
	}
}
