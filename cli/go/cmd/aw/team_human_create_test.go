package main

import (
	"crypto/ed25519"
	"encoding/base64"
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
	"github.com/awebai/aw/internal/blueprint"
)

func resetTeamHumanCreateGlobals(t *testing.T) {
	t.Helper()
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
	oldCreateHome := teamHumanCreateHome
	oldCreateRuntime := teamHumanCreateRuntime
	oldCreateLibraryURL := teamHumanCreateLibraryURL
	oldProfiles := teamHumanCreateProfiles
	oldAgents := teamHumanCreateAgents
	oldBlueprint := teamHumanCreateBlueprint
	oldFirstLocal := teamHumanCreateFirstLocal
	oldFirstGlobal := teamHumanCreateFirstGlobal
	oldAddLocal := teamHumanAddLocal
	oldAddGlobal := teamHumanAddGlobal
	oldAddLayoutOnly := teamHumanAddLayoutOnly
	oldAddHome := teamHumanAddHome
	oldAddRuntime := teamHumanAddRuntime
	oldAddLibraryURL := teamHumanAddLibraryURL
	oldAddBlueprint := teamHumanAddBlueprint
	oldAddSpecOverride := teamHumanAddSpecOverride
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
		teamHumanCreateHome = oldCreateHome
		teamHumanCreateRuntime = oldCreateRuntime
		teamHumanCreateLibraryURL = oldCreateLibraryURL
		teamHumanCreateProfiles = oldProfiles
		teamHumanCreateAgents = oldAgents
		teamHumanCreateBlueprint = oldBlueprint
		teamHumanCreateFirstLocal = oldFirstLocal
		teamHumanCreateFirstGlobal = oldFirstGlobal
		teamHumanAddLocal = oldAddLocal
		teamHumanAddGlobal = oldAddGlobal
		teamHumanAddLayoutOnly = oldAddLayoutOnly
		teamHumanAddHome = oldAddHome
		teamHumanAddRuntime = oldAddRuntime
		teamHumanAddLibraryURL = oldAddLibraryURL
		teamHumanAddBlueprint = oldAddBlueprint
		teamHumanAddSpecOverride = oldAddSpecOverride
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
	teamHumanCreateHome = ""
	teamHumanCreateRuntime = ""
	teamHumanCreateLibraryURL = ""
	teamHumanCreateProfiles = nil
	teamHumanCreateAgents = nil
	teamHumanCreateBlueprint = ""
	teamHumanCreateFirstLocal = false
	teamHumanCreateFirstGlobal = false
	teamHumanAddLocal = false
	teamHumanAddGlobal = false
	teamHumanAddLayoutOnly = false
	teamHumanAddHome = ""
	teamHumanAddRuntime = ""
	teamHumanAddLibraryURL = ""
	teamHumanAddBlueprint = ""
	teamHumanAddSpecOverride = nil
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

func TestFormatTeamHumanAddDistinguishesProfileBoundAgent(t *testing.T) {
	selector := &libraryProfileSelector{SourceBlueprintRef: "aweb.engineering", ProfileRef: "developer"}
	out := formatTeamHumanAdd(teamHumanAddOutput{
		AgentsRoot: "/repo/agents/instances",
		Agents:     []teamHumanAddedAgent{{Name: "dev", HomeDir: "/repo/agents/instances/dev", ProfileMode: "library", Profile: selector}},
		NoLibrary:  false,
		NoProfile:  false,
	})
	if !strings.Contains(out, "Added 1 agent from blueprint profile aweb.engineering/developer under /repo/agents/instances") {
		t.Fatalf("profile-bound output missing profile wording:\n%s", out)
	}
	if strings.Contains(out, "Added 1 empty-profile agent") {
		t.Fatalf("profile-bound output used empty-profile wording:\n%s", out)
	}
}

func TestFormatTeamHumanAddKeepsBareAgentEmptyProfileWording(t *testing.T) {
	out := formatTeamHumanAdd(teamHumanAddOutput{
		AgentsRoot: "/repo/agents/instances",
		Agents:     []teamHumanAddedAgent{{Name: "worker", HomeDir: "/repo/agents/instances/worker", ProfileMode: "empty"}},
		NoLibrary:  true,
		NoProfile:  true,
	})
	if !strings.Contains(out, "Added 1 empty-profile agent(s) under /repo/agents/instances") {
		t.Fatalf("bare output missing empty-profile wording:\n%s", out)
	}
}

func TestTeamHumanCreateAgentSpecsUseListedAgentAsFirstMember(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	teamHumanCreateAgents = []string{"developer@aweb.engineering/developer:local"}
	specs, err := teamHumanCreateAgentSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].Raw != "developer@aweb.engineering/developer:local" {
		t.Fatalf("specs=%+v", specs)
	}
	roster, err := teamHumanCreateRosterSpecs(specs)
	if err != nil {
		t.Fatal(err)
	}
	if len(roster) != 0 {
		t.Fatalf("single listed create agent should be the first member, roster=%v specs=%+v", roster, specs)
	}
}

func TestTeamHumanCreateFirstAgentNameConflictsWithListedAgent(t *testing.T) {
	for _, tc := range []struct {
		name     string
		agents   []string
		profiles []string
	}{
		{name: "agent", agents: []string{"developer@aweb.engineering/developer"}},
		{name: "profile compat synthesized name", profiles: []string{"aweb.engineering/developer"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTeamHumanCreateGlobals(t)
			root := t.TempDir()
			t.Chdir(root)
			teamHumanCreateAlias = "owner"
			teamHumanCreateAgents = tc.agents
			teamHumanCreateProfiles = tc.profiles

			err := runTeamHumanCreate(nil, []string{"eng"})
			if err == nil || !strings.Contains(err.Error(), "the first listed --agent is the first team member") {
				t.Fatalf("error=%v", err)
			}
			if _, statErr := os.Stat(filepath.Join(root, ".aw")); !os.IsNotExist(statErr) {
				t.Fatalf(".aw created despite prevalidation failure, stat err=%v", statErr)
			}
		})
	}
}

func TestTeamHumanCreateBlueprintSpecsCarryLocalSource(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	fixture := filepath.Join(engineeringBlueprintFixtureRoot(t), "source")
	teamHumanCreateBlueprint = fixture

	specs, err := teamHumanCreateAgentSpecs()
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) == 0 {
		t.Fatalf("specs=%+v", specs)
	}
	for _, spec := range specs {
		if spec.Profile == nil {
			t.Fatalf("missing profile in spec %+v", spec)
		}
		if spec.LocalBlueprintDir != fixture {
			t.Fatalf("LocalBlueprintDir=%q want %q", spec.LocalBlueprintDir, fixture)
		}
	}
}

func TestParseTeamAgentSpecSupportsNameScopeAndRejectsVersion(t *testing.T) {
	spec, err := parseTeamAgentSpec("ada@aweb.engineering/coordinator:global=pi")
	if err != nil {
		t.Fatal(err)
	}
	if spec.Name != "ada" || spec.Profile == nil || spec.Profile.SourceBlueprintRef != "aweb.engineering" || spec.Profile.ProfileRef != "coordinator" || spec.Scope != awid.IdentityModeGlobal || spec.RuntimeKind != "pi" {
		t.Fatalf("spec=%+v profile=%+v", spec, spec.Profile)
	}
	empty, err := parseTeamAgentSpec("bob:local")
	if err != nil {
		t.Fatal(err)
	}
	if empty.Name != "bob" || empty.Profile != nil || empty.Scope != awid.IdentityModeLocal {
		t.Fatalf("empty=%+v", empty)
	}
	if _, err := parseTeamAgentSpec("aweb.engineering/coordinator@0.2.0"); err == nil || !strings.Contains(err.Error(), "@ now separates NAME") {
		t.Fatalf("version error=%v", err)
	}
	if _, err := parseTeamAgentSpec("bob=pi"); err == nil || !strings.Contains(err.Error(), "=RUNTIME is only valid") {
		t.Fatalf("empty runtime error=%v", err)
	}
	if _, err := parseTeamAgentSpec("bob:global=pi"); err == nil || !strings.Contains(err.Error(), "=RUNTIME is only valid") {
		t.Fatalf("empty scoped runtime error=%v", err)
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

func TestTeamHumanAddHomeOverrideLayoutOnlyUsesExactPath(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	explicitHome := filepath.Join(root, "custom-home")
	teamHumanAddLayoutOnly = true
	teamHumanAddHome = explicitHome

	if err := runTeamHumanAdd(nil, []string{"developer"}); err != nil {
		t.Fatalf("runTeamHumanAdd: %v", err)
	}
	if info, err := os.Stat(explicitHome); err != nil || !info.IsDir() {
		t.Fatalf("explicit home missing: info=%v err=%v", info, err)
	}
	if _, err := os.Stat(filepath.Join(root, "agents", "instances", "developer")); !os.IsNotExist(err) {
		t.Fatalf("default agent home created despite --home, err=%v", err)
	}
}

func TestTeamHumanAddHomeOverrideRejectsRoster(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	teamHumanAddLayoutOnly = true
	teamHumanAddHome = filepath.Join(root, "custom-home")

	err := runTeamHumanAdd(nil, []string{"developer", "reviewer"})
	if err == nil || !strings.Contains(err.Error(), "--home") || !strings.Contains(err.Error(), "single") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "custom-home")); !os.IsNotExist(statErr) {
		t.Fatalf("custom home created despite roster rejection, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "agents", "instances")); !os.IsNotExist(statErr) {
		t.Fatalf("default homes created despite roster rejection, stat err=%v", statErr)
	}
}

func TestTeamHumanCreateHomeRequiresProfile(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Chdir(t.TempDir())
	teamHumanCreateHome = "."

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "--home requires --profile") {
		t.Fatalf("error=%v", err)
	}
}

func TestTeamHumanCreateHomeRejectsRoster(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	teamHumanCreateHome = filepath.Join(root, "custom-home")
	teamHumanCreateProfiles = []string{"aweb.engineering/developer", "aweb.engineering/coordinator"}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "--home") || !strings.Contains(err.Error(), "single") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat(filepath.Join(root, "custom-home")); !os.IsNotExist(statErr) {
		t.Fatalf("custom home created despite roster rejection, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "agents", "instances")); !os.IsNotExist(statErr) {
		t.Fatalf("default homes created despite roster rejection, stat err=%v", statErr)
	}
}

func TestTeamHumanCreateRosterSpecsCarryPerProfileRuntime(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	specs, err := teamHumanCreateRosterSpecs([]teamAgentSpec{
		{Raw: "aweb.engineering/coordinator=claude-code", Profile: &libraryProfileSelector{SourceBlueprintRef: "aweb.engineering", ProfileRef: "coordinator", RuntimeKind: "claude-code"}},
		{Raw: "aweb.engineering/reviewer=pi", Profile: &libraryProfileSelector{SourceBlueprintRef: "aweb.engineering", ProfileRef: "reviewer", RuntimeKind: "pi"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"aweb.engineering/reviewer=pi"}
	got := make([]string, 0, len(specs))
	for _, spec := range specs {
		got = append(got, spec.Raw)
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("specs=%v want %v", got, want)
	}
}

func TestTeamHumanCreateRosterRejectsDuplicateDerivedAgentNames(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	_, err := teamHumanCreateRosterSpecs([]teamAgentSpec{
		{Raw: "blueprint.one/alice", Profile: &libraryProfileSelector{SourceBlueprintRef: "blueprint.one", ProfileRef: "alice"}},
		{Raw: "blueprint.two/Alice", Profile: &libraryProfileSelector{SourceBlueprintRef: "blueprint.two", ProfileRef: "Alice"}},
	})
	if err != nil {
		t.Fatalf("error=%v", err)
	}
}

func TestTeamHumanCreateRosterDuplicateNamesFailBeforeInit(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	root := t.TempDir()
	t.Chdir(root)
	teamHumanCreateProfiles = []string{"alice@aweb.engineering/coordinator", "Alice@other-blueprint/reviewer"}
	initCalled := false
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		initCalled = true
		return connectOutput{}, nil
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "duplicate roster agent name") {
		t.Fatalf("error=%v", err)
	}
	if initCalled {
		t.Fatal("init/create called despite duplicate roster names")
	}
	if _, statErr := os.Stat(filepath.Join(root, ".aw")); !os.IsNotExist(statErr) {
		t.Fatalf(".aw created despite prevalidation failure, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "agents", "instances")); !os.IsNotExist(statErr) {
		t.Fatalf("default homes created despite prevalidation failure, stat err=%v", statErr)
	}
}

func TestTeamHumanCreateRosterInvalidNameFailsBeforeInit(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	root := t.TempDir()
	t.Chdir(root)
	teamHumanCreateProfiles = []string{"bad name@aweb.engineering/coordinator", "aweb.engineering/alice"}
	initCalled := false
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		initCalled = true
		return connectOutput{}, nil
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "invalid agent name") {
		t.Fatalf("error=%v", err)
	}
	if initCalled {
		t.Fatal("init/create called despite invalid roster name")
	}
	if _, statErr := os.Stat(filepath.Join(root, ".aw")); !os.IsNotExist(statErr) {
		t.Fatalf(".aw created despite prevalidation failure, stat err=%v", statErr)
	}
	if _, statErr := os.Stat(filepath.Join(root, "agents", "instances")); !os.IsNotExist(statErr) {
		t.Fatalf("default homes created despite prevalidation failure, stat err=%v", statErr)
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

	err := runTeamHumanAdd(nil, []string{"developer@aweb.engineering/developer:local"})
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

func TestTeamHumanCreateAPIKeyToleratesAPISuffixedAwebURL(t *testing.T) {
	for _, tc := range []struct {
		name   string
		suffix string
	}{
		{name: "base", suffix: ""},
		{name: "apisuffixed", suffix: "/api"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetTeamHumanCreateGlobals(t)

			const apiKey = "aw_sk_create_apikey"
			teamPub, teamKey, err := awid.GenerateKeypair()
			if err != nil {
				t.Fatal(err)
			}
			teamDIDKey := awid.ComputeDIDKey(teamPub)

			var initPaths []string
			var server *httptest.Server
			server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/api/v1/workspaces/init":
					initPaths = append(initPaths, r.URL.Path)
					var body map[string]any
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Fatal(err)
					}
					didKey, _ := body["did"].(string)
					cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
						Team:         "backend:acme.com",
						MemberDIDKey: didKey,
						Alias:        "eng",
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
						"alias":          "eng",
						"team_id":        "backend:acme.com",
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
						"team_id":      "backend:acme.com",
						"alias":        "eng",
						"agent_id":     "agent-1",
						"workspace_id": "ws-1",
						"repo_id":      "",
						"team_did_key": teamDIDKey,
					})
				case "/v1/agents/heartbeat", "/api/v1/agents/heartbeat":
					w.WriteHeader(http.StatusOK)
				case "/v1/agents/me/encryption-key", "/api/v1/agents/me/encryption-key":
					writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "backend:acme.com", "eng")
				default:
					t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
				}
			}))

			t.Setenv("AWEB_API_KEY", apiKey)
			t.Setenv("AWEB_URL", server.URL+tc.suffix)
			t.Setenv("AWID_REGISTRY_URL", "")
			t.Chdir(t.TempDir())
			jsonFlag = true

			if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
				t.Fatalf("runTeamHumanCreate with AWEB_URL=%q: %v", server.URL+tc.suffix, err)
			}
			if len(initPaths) != 1 || initPaths[0] != "/api/v1/workspaces/init" {
				t.Fatalf("workspace init paths=%v want [/api/v1/workspaces/init]", initPaths)
			}
		})
	}
}

func TestTeamHumanCreateAgentUsesListedFirstAgentName(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	const apiKey = "aw_sk_create_apikey"
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	var gotInitAlias string
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/workspaces/init":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			gotInitAlias, _ = body["alias"].(string)
			didKey, _ := body["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "backend:acme.com", MemberDIDKey: didKey, Alias: gotInitAlias, Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": server.URL, "team_cert": encoded, "alias": gotInitAlias, "team_id": "backend:acme.com", "workspace_id": "ws-1", "did": didKey, "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "workspace-sk-ephemeral"})
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
	}))

	t.Setenv("AWEB_API_KEY", apiKey)
	t.Setenv("AWEB_URL", server.URL)
	t.Chdir(t.TempDir())
	teamHumanCreateAgents = []string{"developer"}
	jsonFlag = true

	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if gotInitAlias != "developer" {
		t.Fatalf("workspace init alias=%q want listed first agent name developer", gotInitAlias)
	}
}

func TestTeamHumanAddOmittedScopeComesFromPublicProfile(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	files := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: developer\nname: Developer\nversion: 0.1.0\nscope: global\nmission: Build.\naccepted_work: [development]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Build.\n"},
	})
	digest := testLibraryProfilePayloadDigestForProfile(t, "developer", files)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/developer" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "developer", "version": "0.1.0", "digest": digest, "files": files})
	}))
	defer server.Close()
	t.Setenv(libraryURLEnvVar, server.URL)

	specs, err := resolveTeamHumanAddAgentSpecs(t.TempDir(), []string{"dev@aweb.engineering/developer"})
	if err != nil {
		t.Fatal(err)
	}
	if len(specs) != 1 || specs[0].Scope != awid.IdentityModeGlobal {
		t.Fatalf("specs=%+v", specs)
	}
}

func TestTeamHumanAddWithoutTeamContextGuidesToConnectNotInviteFlags(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", filepath.Join(root, "home"))
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "https://app.aweb.ai")
	t.Chdir(root)

	err := runTeamHumanAdd(nil, []string{"alice@aweb.engineering/developer:local=pi"})
	if err == nil {
		t.Fatal("expected failure without team context")
	}
	if strings.Contains(err.Error(), "--team") || strings.Contains(err.Error(), "--namespace") {
		t.Fatalf("error should not reference invite-only flags: %v", err)
	}
	if !strings.Contains(err.Error(), "aw team create") {
		t.Fatalf("error should guide the user to establish team context: %v", err)
	}
}

func TestTeamHumanAddAPIKeyNoActiveTeamBootstrapsAndMaterializesProfile(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWEB_API_KEY", "aw_sk_owner")
	t.Chdir(root)
	jsonFlag = true

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	files := testLibraryProfilePayloadFiles()
	digest := testLibraryProfilePayloadDigest(t, files)

	var initCalls, connectCalls int
	var initBody map[string]any
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			initCalls++
			if got := r.Header.Get("Authorization"); got != "Bearer aw_sk_owner" {
				t.Fatalf("workspace init Authorization=%q", got)
			}
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := initBody["did"].(string)
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "default:launch.aweb.ai", MemberDIDKey: didKey, Alias: "developer", Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": server.URL, "team_cert": encoded, "alias": "developer", "team_id": "default:launch.aweb.ai", "workspace_id": "ws-dev", "did": didKey, "stable_id": "", "identity_scope": awid.IdentityModeLocal, "custody": awid.CustodySelf, "api_key": "workspace-sk-dev"})
		case r.Method == http.MethodPost && (r.URL.Path == "/api/v1/connect" || r.URL.Path == "/v1/connect"):
			connectCalls++
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "default:launch.aweb.ai", "alias": "developer", "agent_id": "developer", "workspace_id": "ws-dev", "repo_id": "repo-1", "team_did_key": teamDIDKey})
		case r.Method == http.MethodGet && (r.URL.Path == "/api/v1/agents/heartbeat" || r.URL.Path == "/v1/agents/heartbeat"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && (r.URL.Path == "/api/v1/instructions/active" || r.URL.Path == "/v1/instructions/active"):
			_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "active_team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Use aw."}})
		case r.Method == http.MethodPut && (r.URL.Path == "/api/v1/agents/me/encryption-key" || r.URL.Path == "/v1/agents/me/encryption-key"):
			writePublishEncryptionKeyResponseForTest(t, w, "developer", "default:launch.aweb.ai", "developer")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/blueprints/aweb.engineering/profiles/coordinator":
			_ = json.NewEncoder(w).Encode(libraryProfileDetailResponse{BlueprintRef: "aweb.engineering", BlueprintVersion: "0.1.0", ProfileRef: "coordinator", Version: "0.1.0", Digest: digest, Files: files})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/shelf/import":
			_ = json.NewEncoder(w).Encode(libraryImportToShelfResponse{ProfileRef: "coordinator", Version: "0.1.0", Digest: digest, SourceBlueprintRef: "aweb.engineering", SourceBlueprintVersion: "0.1.0", SourceBlueprintDigest: "sha256:test-blueprint", Created: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/developer/profile-binding":
			t.Fatalf("public profile materialization must not bind via Library plugin")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Setenv("AWEB_URL", server.URL+"/api")
	t.Setenv(libraryURLEnvVar, server.URL)

	if err := runTeamHumanAdd(nil, []string{"developer@aweb.engineering/coordinator=pi"}); err != nil {
		t.Fatalf("runTeamHumanAdd: %v", err)
	}
	if initCalls != 1 || connectCalls != 1 {
		t.Fatalf("calls init/connect=%d/%d", initCalls, connectCalls)
	}
	if initBody["alias"] != "developer" || initBody["identity_scope"] != awid.IdentityModeLocal {
		t.Fatalf("workspace init body=%v", initBody)
	}
	agentHome := filepath.Join(root, "agents", "instances", "developer")
	if _, err := os.Stat(filepath.Join(agentHome, ".aw", "profile", "ref.json")); err != nil {
		t.Fatalf("profile ref not materialized: %v", err)
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(agentHome, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("load agent workspace: %v", err)
	}
	if workspace.APIKey != "workspace-sk-dev" {
		t.Fatalf("workspace api key=%q", workspace.APIKey)
	}
}

func TestTeamHumanAddAPIKeyNoActiveTeamBootstrapsGlobalThroughWorkspaceInit(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := filepath.Join(root, "home")
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv("AWEB_API_KEY", "aw_sk_owner")
	t.Chdir(root)
	jsonFlag = true

	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := awid.ComputeDIDKey(teamPub)
	files := testLibraryProfilePayloadFiles()
	digest := testLibraryProfilePayloadDigest(t, files)

	var requestOrder []string
	var initBody map[string]any
	var registeredDIDKey string
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			requestOrder = append(requestOrder, "register_identity")
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			registeredDIDKey, _ = body["new_did_key"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"registered": true})
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			requestOrder = append(requestOrder, "did_full")
			stableID := strings.TrimSuffix(strings.TrimPrefix(r.URL.Path, "/v1/did/"), "/full")
			_ = json.NewEncoder(w).Encode(map[string]any{"did_aw": stableID, "current_did_key": registeredDIDKey, "created_at": "2026-04-18T00:00:00Z", "updated_at": "2026-04-18T00:00:00Z"})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/workspaces/init":
			requestOrder = append(requestOrder, "workspace_init")
			if err := json.NewDecoder(r.Body).Decode(&initBody); err != nil {
				t.Fatal(err)
			}
			didKey, _ := initBody["did"].(string)
			pubKeyB64, _ := initBody["public_key"].(string)
			pubKeyBytes, err := base64.StdEncoding.DecodeString(pubKeyB64)
			if err != nil {
				t.Fatal(err)
			}
			stableID := awid.ComputeStableID(ed25519.PublicKey(pubKeyBytes))
			cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{Team: "default:launch.aweb.ai", MemberDIDKey: didKey, MemberDIDAW: stableID, MemberAddress: "launch.aweb.ai/global-dev", Alias: "global-dev", Lifetime: awid.LifetimePersistent})
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"server_url": server.URL, "team_cert": encoded, "alias": "global-dev", "team_id": "default:launch.aweb.ai", "workspace_id": "ws-global", "did": didKey, "stable_id": stableID, "identity_scope": awid.IdentityModeGlobal, "custody": awid.CustodySelf, "api_key": "workspace-sk-global"})
		case r.Method == http.MethodPost && (r.URL.Path == "/api/v1/connect" || r.URL.Path == "/v1/connect"):
			requireCertificateAuthForTest(t, r)
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "default:launch.aweb.ai", "alias": "global-dev", "agent_id": "global-dev", "workspace_id": "ws-global", "repo_id": "repo-1", "team_did_key": teamDIDKey})
		case r.Method == http.MethodGet && (r.URL.Path == "/api/v1/agents/heartbeat" || r.URL.Path == "/v1/agents/heartbeat"):
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && (r.URL.Path == "/api/v1/instructions/active" || r.URL.Path == "/v1/instructions/active"):
			_ = json.NewEncoder(w).Encode(map[string]any{"team_instructions_id": "instructions-1", "active_team_instructions_id": "instructions-1", "version": 1, "document": map[string]any{"body_md": "Use aw."}})
		case strings.HasSuffix(r.URL.Path, "/encryption-key"):
			writePublishEncryptionKeyResponseForTest(t, w, "global-dev", "default:launch.aweb.ai", "global-dev")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/blueprints/aweb.engineering/profiles/coordinator":
			_ = json.NewEncoder(w).Encode(libraryProfileDetailResponse{BlueprintRef: "aweb.engineering", BlueprintVersion: "0.1.0", ProfileRef: "coordinator", Version: "0.1.0", Digest: digest, Files: files})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/shelf/import":
			_ = json.NewEncoder(w).Encode(libraryImportToShelfResponse{ProfileRef: "coordinator", Version: "0.1.0", Digest: digest, SourceBlueprintRef: "aweb.engineering", SourceBlueprintVersion: "0.1.0", SourceBlueprintDigest: "sha256:test-blueprint", Created: true})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/agents/global-dev/profile-binding":
			t.Fatalf("public profile materialization must not bind via Library plugin")
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv(libraryURLEnvVar, server.URL)
	t.Setenv("AWID_REGISTRY_URL", server.URL)

	if err := runTeamHumanAdd(nil, []string{"global-dev@aweb.engineering/coordinator:global=pi"}); err != nil {
		t.Fatalf("runTeamHumanAdd global: %v", err)
	}
	if got := strings.Join(requestOrder[:3], ","); got != "register_identity,did_full,workspace_init" {
		t.Fatalf("request order=%q", got)
	}
	if initBody["identity_scope"] != awid.IdentityModeGlobal || initBody["name"] != "global-dev" {
		t.Fatalf("global workspace init body=%v", initBody)
	}
	if alias, ok := initBody["alias"].(string); ok && strings.TrimSpace(alias) != "" {
		t.Fatalf("global workspace init should not send alias: %v", initBody)
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(root, "agents", "instances", "global-dev", ".aw", "identity.yaml"))
	if err != nil {
		t.Fatalf("load global identity: %v", err)
	}
	if identity.IdentityScope != awid.IdentityModeGlobal || identity.Address != "launch.aweb.ai/global-dev" {
		t.Fatalf("identity=%+v", identity)
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

func TestTeamHumanCreateFirstAgentGlobalHostedBootstrapAllowed(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	t.Setenv(initAPIKeyEnvVar, "")
	teamHumanCreateFirstGlobal = true
	teamHumanCreateServiceURL = "https://app.example"
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
	if !captured.Persistent || captured.Name != "eng" || captured.Alias != "" {
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
	teamHumanCreateFirstGlobal = true

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
	if err == nil || !strings.Contains(err.Error(), "requires namespace controller authority") || !strings.Contains(err.Error(), "aw id create") {
		t.Fatalf("error=%v", err)
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
		switch {
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
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "published"})
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

	if err := runTeamHumanCreate(nil, []string{"Ops"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if claimCalls != 1 || certCalls != 1 {
		t.Fatalf("claim calls=%d cert calls=%d", claimCalls, certCalls)
	}
	identity, _, err := awconfig.LoadWorktreeIdentityFromDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if identity.IdentityScope != awid.IdentityModeGlobal || identity.Address != "acme.com/ops" || identity.StableID != createdDIDAW {
		t.Fatalf("identity=%+v created=%s", identity, createdDIDAW)
	}
	cert, err := awconfig.LoadTeamCertificateForTeam(root, "ops:acme.com")
	if err != nil {
		t.Fatalf("cert missing: %v", err)
	}
	if cert.MemberDIDAW != createdDIDAW || cert.MemberDIDKey != createdDIDKey || cert.MemberAddress != "acme.com/ops" || cert.Lifetime != awid.LifetimePersistent {
		t.Fatalf("cert fields did_aw=%q did_key=%q address=%q lifetime=%q", cert.MemberDIDAW, cert.MemberDIDKey, cert.MemberAddress, cert.Lifetime)
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
	teamHumanCreateFirstGlobal = true

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
	teamHumanCreateProfiles = []string{"aweb.engineering/developer@0.1.0"}
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

func TestTeamHumanAddProfileMaterializeFailureRollsBackCreatedHome(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Chdir(root)
	memberPub, memberPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDID := awid.ComputeDIDKey(teamPub)
	var certCalls int
	var registeredCertID string
	var revokedCertID string
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"aweb_url": server.URL, "registry_url": server.URL})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local/teams/eng":
			_ = json.NewEncoder(w).Encode(map[string]any{"team_id": "eng:local", "domain": "local", "name": "eng", "team_did_key": teamDID})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams/eng/certificates":
			certCalls++
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			registeredCertID, _ = body["certificate_id"].(string)
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams/eng/certificates/revoke":
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			revokedCertID, _ = body["certificate_id"].(string)
			_ = json.NewEncoder(w).Encode(map[string]any{"certificate_id": revokedCertID})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "developer", "eng:local", "developer")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/blueprints/aweb.engineering/profiles/developer":
			http.Error(w, `{"detail":"catalog unavailable"}`, http.StatusServiceUnavailable)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv(libraryURLEnvVar, server.URL)
	writeLocalTeamSignedRequestWorkspaceForTest(t, root, server.URL, "eng:local", "eng", memberDID, memberPriv)
	if err := awconfig.SaveTeamKey("local", "eng", teamKey); err != nil {
		t.Fatal(err)
	}

	err = runTeamHumanAdd(nil, []string{"developer@aweb.engineering/developer:local"})
	if err == nil || !strings.Contains(err.Error(), "library public get-profile") {
		t.Fatalf("error=%v", err)
	}
	if certCalls != 1 {
		t.Fatalf("cert calls=%d want 1 to prove identity was created before materialize failure", certCalls)
	}
	if registeredCertID == "" {
		t.Fatal("registered certificate id was not captured")
	}
	if revokedCertID != registeredCertID {
		t.Fatalf("revoked certificate_id=%q want just-created %q", revokedCertID, registeredCertID)
	}
	agentHome := filepath.Join(root, "agents", "instances", "developer")
	if _, statErr := os.Lstat(agentHome); !os.IsNotExist(statErr) {
		t.Fatalf("failed profile add left agent home state at %s: %v", agentHome, statErr)
	}
}

func TestTeamHumanAddHostedProfileMaterializeFailureRollsBackJustCreatedCert(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Chdir(root)

	teamID := "default:rollback.aweb.ai"
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	justCreatedCertID := ""
	preExistingCertID := "cert-pre-existing-do-not-touch"
	removeCertID := ""
	removeAuth := ""
	removeCalls := 0
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"aweb_url": server.URL, "registry_url": server.URL})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/create-invite":
			cert := requireCertificateAuthForTest(t, r)
			if cert.Team != teamID {
				t.Fatalf("create-invite cert team=%q want %q", cert.Team, teamID)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"invite_id": "invite-1", "token": "aw_inv_hosted_rollback_token", "server_url": server.URL})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/accept-invite":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			didKey, _ := req["did"].(string)
			cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: didKey, Alias: "developer", Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			justCreatedCertID = cert.CertificateID
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "server-team-id", "team_slug": "default", "namespace": "rollback.aweb.ai",
				"identity_id": "agent-developer", "alias": "developer", "server_url": server.URL,
				"did": didKey, "custody": "self", "lifetime": "ephemeral", "access_mode": "open", "created": true,
				"team_cert": encoded,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-developer", teamID, "developer")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/blueprints/aweb.engineering/profiles/developer":
			http.Error(w, `{"detail":"catalog unavailable"}`, http.StatusServiceUnavailable)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/teams/default:rollback.aweb.ai/agents/remove-member":
			removeCalls++
			removeAuth = r.Header.Get("Authorization")
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			removeCertID, _ = body["certificate_id"].(string)
			if removeCertID == preExistingCertID {
				t.Fatalf("rollback targeted pre-existing cert %q", preExistingCertID)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "removed", "canonical_team_id": teamID, "certificate_id": removeCertID})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv(libraryURLEnvVar, server.URL)
	oldInitAwebURL := initAwebURL
	initAwebURL = server.URL
	t.Cleanup(func() { initAwebURL = oldInitAwebURL })
	workspace := workspaceBinding(server.URL, teamID, "owner", "workspace-owner")
	workspace.APIKey = "aw_sk_owner"
	writeWorkspaceBindingForTest(t, root, workspace)

	err = runTeamHumanAdd(nil, []string{"developer@aweb.engineering/developer:local"})
	if err == nil || !strings.Contains(err.Error(), "library public get-profile") {
		t.Fatalf("error=%v", err)
	}
	if justCreatedCertID == "" {
		t.Fatal("hosted accept did not create a cert")
	}
	if removeCalls != 1 {
		t.Fatalf("remove-member calls=%d want 1", removeCalls)
	}
	if removeCertID != justCreatedCertID {
		t.Fatalf("remove certificate_id=%q want just-created %q", removeCertID, justCreatedCertID)
	}
	if removeAuth != "Bearer aw_sk_owner" {
		t.Fatalf("remove auth=%q want owner workspace bearer key", removeAuth)
	}
	agentHome := filepath.Join(root, "agents", "instances", "developer")
	if _, statErr := os.Lstat(agentHome); !os.IsNotExist(statErr) {
		t.Fatalf("failed hosted profile add left agent home state at %s: %v", agentHome, statErr)
	}
}

func TestTeamHumanAddHostedProfileRollbackFailureIsLoud(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AW_CONFIG_PATH", "")
	t.Chdir(root)

	teamID := "default:rollback-fail.aweb.ai"
	_, hostedTeamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	justCreatedCertID := ""
	var server *httptest.Server
	server = newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/discovery":
			_ = json.NewEncoder(w).Encode(map[string]any{"aweb_url": server.URL, "registry_url": server.URL})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/create-invite":
			_ = json.NewEncoder(w).Encode(map[string]any{"invite_id": "invite-1", "token": "aw_inv_hosted_rollback_fail_token", "server_url": server.URL})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/spawn/accept-invite":
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			didKey, _ := req["did"].(string)
			cert, err := awid.SignTeamCertificate(hostedTeamKey, awid.TeamCertificateFields{Team: teamID, MemberDIDKey: didKey, Alias: "developer", Lifetime: awid.LifetimeEphemeral})
			if err != nil {
				t.Fatal(err)
			}
			justCreatedCertID = cert.CertificateID
			encoded, err := awid.EncodeTeamCertificateHeader(cert)
			if err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id": "server-team-id", "team_slug": "default", "namespace": "rollback-fail.aweb.ai",
				"identity_id": "agent-developer", "alias": "developer", "server_url": server.URL,
				"did": didKey, "custody": "self", "lifetime": "ephemeral", "access_mode": "open", "created": true,
				"team_cert": encoded,
			})
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-developer", teamID, "developer")
		case r.Method == http.MethodGet && r.URL.Path == "/v1/blueprints/aweb.engineering/profiles/developer":
			http.Error(w, `{"detail":"catalog unavailable"}`, http.StatusServiceUnavailable)
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/teams/default:rollback-fail.aweb.ai/agents/remove-member":
			http.Error(w, `{"detail":"remove failed"}`, http.StatusServiceUnavailable)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))
	defer server.Close()
	t.Setenv("AWEB_URL", server.URL)
	t.Setenv(libraryURLEnvVar, server.URL)
	oldInitAwebURL := initAwebURL
	initAwebURL = server.URL
	t.Cleanup(func() { initAwebURL = oldInitAwebURL })
	workspace := workspaceBinding(server.URL, teamID, "owner", "workspace-owner")
	workspace.APIKey = "aw_sk_owner"
	writeWorkspaceBindingForTest(t, root, workspace)

	err = runTeamHumanAdd(nil, []string{"developer@aweb.engineering/developer:local"})
	if err == nil {
		t.Fatal("expected materialize + rollback failure")
	}
	text := err.Error()
	for _, want := range []string{"GET " + server.URL + "/v1/blueprints/aweb.engineering/profiles/developer returned 503", "server-side member rollback failed", "hosted remove-member returned 503", justCreatedCertID, "aw id team remove-member --team default --namespace rollback-fail.aweb.ai --cert-id"} {
		if !strings.Contains(text, want) {
			t.Fatalf("error missing %q:\n%s", want, text)
		}
	}
}

func TestTeamHumanAddRejectsVersionedLibraryProfileBeforeHomeCreate(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)

	err := runTeamHumanAdd(nil, []string{"developer@aweb.engineering/developer@0.1.0"})
	if err == nil || !strings.Contains(err.Error(), "versioned Library profile selectors are not supported") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Lstat(root + "/agents"); !os.IsNotExist(statErr) {
		t.Fatalf("agent home state created despite unsupported selector, stat err=%v", statErr)
	}
}

func TestTeamHumanCreateLibraryProfileUsesPublicCatalogAfterIdentity(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	t.Chdir(root)
	teamHumanCreateProfiles = []string{"aweb.engineering/developer"}
	files := withLibraryPayloadFileSHA([]blueprint.LibraryProfilePayloadFile{
		{Path: "profile.yaml", ContentUTF8: "id: developer\nname: Developer\nversion: 0.1.0\nmission: Build.\naccepted_work: [development]\ninstructions: instructions.md\nruntime_assumptions: [local shell]\nmemory_policy:\n  mode: reviewed-learning\n  proposal_target: library\n"},
		{Path: "instructions.md", ContentUTF8: "Build.\n"},
	})
	digest := testLibraryProfilePayloadDigestForProfile(t, "developer", files)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/blueprints/aweb.engineering/profiles/developer" {
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("X-AWID-Team-Certificate") != "" {
			t.Fatalf("public get-profile should be unsigned: %#v", r.Header)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"blueprint_ref": "aweb.engineering", "blueprint_version": "0.1.0", "profile_ref": "developer", "version": "0.1.0", "digest": digest, "files": files})
	}))
	defer server.Close()
	t.Setenv(libraryURLEnvVar, server.URL)
	called := false
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		called = true
		return connectOutput{Status: "connected", TeamID: "eng:local", Alias: req.Alias, AwebURL: req.AwebURL, WorkspaceID: "ws-1"}, nil
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "inject aw coordination docs") {
		t.Fatalf("runTeamHumanCreate error=%v", err)
	}
	if !called {
		t.Fatal("profile-bound create should create identity before public materialize")
	}
	if _, err := os.Lstat(filepath.Join(root, ".aw", "profile", "ref.json")); err != nil {
		t.Fatalf("profile ref not written: %v", err)
	}
}
