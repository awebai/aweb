package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestInitUsesGuidedOnboardingInTTY(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.

	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldPrintReady := initPrintGuidedOnboardingReady
	t.Cleanup(func() {
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initPrintGuidedOnboardingReady = oldPrintReady
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initURL = "https://app.aweb.ai"
	initRole = "reviewer"
	initPersistent = false
	initInjectDocs = false
	initSetupHooks = false
	initWriteContext = true
	initIsTTY = func() bool { return true }

	var captured guidedOnboardingRequest
	var readyCalls int
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		captured = req
		return &guidedOnboardingResult{InitialPrompt: "Download and study the agent guide at https://aweb.ai/agent-guide.txt before doing anything else."}, nil
	}
	initPrintGuidedOnboardingReady = func(result *guidedOnboardingResult) {
		readyCalls++
		if result == nil || !strings.Contains(result.InitialPrompt, "agent guide") {
			t.Fatalf("unexpected ready result: %+v", result)
		}
	}

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	if err := runInit(&cmd.Command, nil); err != nil {
		t.Fatalf("runInit returned error: %v", err)
	}
	wantDir, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("EvalSymlinks(tmp): %v", err)
	}
	gotDir, err := filepath.EvalSymlinks(captured.WorkingDir)
	if err != nil {
		t.Fatalf("EvalSymlinks(captured): %v", err)
	}
	if gotDir != wantDir {
		t.Fatalf("working_dir=%q want %q", captured.WorkingDir, tmp)
	}
	if captured.BaseURL != "https://app.aweb.ai" {
		t.Fatalf("base_url=%q", captured.BaseURL)
	}
	if captured.Role != "reviewer" {
		t.Fatalf("role=%q", captured.Role)
	}
	if !captured.AskPostCreateSetup {
		t.Fatal("expected guided onboarding to include post-create setup prompts")
	}
	if readyCalls != 1 {
		t.Fatalf("expected post-wizard ready message once, got %d", readyCalls)
	}
}

func TestInitFailsNonInteractiveWhenWorkspaceMissing(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.

	oldIsTTY := initIsTTY
	t.Cleanup(func() {
		initIsTTY = oldIsTTY
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initInjectDocs = false
	initSetupHooks = false
	initIsTTY = func() bool { return false }

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	err := runInit(&cmd.Command, nil)
	if err == nil {
		t.Fatal("expected runInit to fail")
	}
	if !strings.Contains(err.Error(), "rerun `aw init` in a TTY for guided onboarding") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveInitURLPrecedence(t *testing.T) {
	oldAwebURL := initAwebURL
	oldRegistry := initAWIDRegistry
	oldCompatURL := initURL
	t.Cleanup(func() {
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initURL = oldCompatURL
	})

	t.Setenv("AWEB_URL", "https://env-aweb.example")
	t.Setenv("AWID_REGISTRY_URL", "https://env-awid.example")

	initAwebURL = "https://flag-aweb.example"
	initAWIDRegistry = "https://flag-awid.example"
	initURL = ""

	awebURL, err := resolveInitAwebURL()
	if err != nil {
		t.Fatalf("resolveInitAwebURL: %v", err)
	}
	if awebURL != "https://flag-aweb.example" {
		t.Fatalf("awebURL=%q", awebURL)
	}
	registryURL, err := resolveInitAWIDRegistryURL()
	if err != nil {
		t.Fatalf("resolveInitAWIDRegistryURL: %v", err)
	}
	if registryURL != "https://flag-awid.example" {
		t.Fatalf("registryURL=%q", registryURL)
	}
}

func TestResolveExplicitInitAwebURLRequiresOverride(t *testing.T) {
	oldAwebURL := initAwebURL
	oldCompatURL := initURL
	t.Cleanup(func() {
		initAwebURL = oldAwebURL
		initURL = oldCompatURL
	})
	t.Setenv("AWEB_URL", "")
	initAwebURL = ""
	initURL = ""

	_, err := resolveExplicitInitAwebURL()
	if err == nil {
		t.Fatal("expected explicit aweb URL requirement error")
	}
	if !strings.Contains(err.Error(), "--aweb-url, --url, or AWEB_URL is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveExplicitInitAwebURLDefaultsForPublicAWIDTeam(t *testing.T) {
	oldAwebURL := initAwebURL
	oldCompatURL := initURL
	t.Cleanup(func() {
		initAwebURL = oldAwebURL
		initURL = oldCompatURL
	})

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWEB_URL", "")
	initAwebURL = ""
	initURL = ""

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	if err := awconfig.SaveControllerMeta("acme.com", &awconfig.ControllerMeta{
		Domain:      "acme.com",
		RegistryURL: awid.DefaultAWIDRegistryURL,
		CreatedAt:   "2026-04-13T00:00:00Z",
	}); err != nil {
		t.Fatalf("save controller meta: %v", err)
	}

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:         "backend:acme.com",
		MemberDIDKey: "did:key:z6MkpPublicTeamMember111111111111111111111111111",
		Alias:        "alice",
		Lifetime:     awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatalf("sign team certificate: %v", err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "backend:acme.com", cert); err != nil {
		t.Fatalf("save team certificate: %v", err)
	}

	awebURL, err := resolveExplicitInitAwebURL()
	if err != nil {
		t.Fatalf("resolveExplicitInitAwebURL: %v", err)
	}
	if awebURL != "https://app.aweb.ai/api" {
		t.Fatalf("awebURL=%q", awebURL)
	}
}

func TestResolveExplicitInitAwebURLOverrideWinsOverDiscoveryFallback(t *testing.T) {
	oldAwebURL := initAwebURL
	oldCompatURL := initURL
	t.Cleanup(func() {
		initAwebURL = oldAwebURL
		initURL = oldCompatURL
	})

	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("AWEB_URL", "")
	initAwebURL = "https://override.example"
	initURL = ""

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	if err := awconfig.SaveControllerMeta("acme.com", &awconfig.ControllerMeta{
		Domain:      "acme.com",
		RegistryURL: awid.DefaultAWIDRegistryURL,
		CreatedAt:   "2026-04-13T00:00:00Z",
	}); err != nil {
		t.Fatalf("save controller meta: %v", err)
	}

	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:         "backend:acme.com",
		MemberDIDKey: "did:key:z6MkpPublicTeamMember111111111111111111111111111",
		Alias:        "alice",
		Lifetime:     awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatalf("sign team certificate: %v", err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeam(tmp, "backend:acme.com", cert); err != nil {
		t.Fatalf("save team certificate: %v", err)
	}

	awebURL, err := resolveExplicitInitAwebURL()
	if err != nil {
		t.Fatalf("resolveExplicitInitAwebURL: %v", err)
	}
	if awebURL != "https://override.example" {
		t.Fatalf("awebURL=%q", awebURL)
	}
}

func TestInitRegistryIsLocalhost(t *testing.T) {
	t.Parallel()

	cases := map[string]bool{
		"http://localhost:8010": true,
		"http://127.0.0.1:8010": true,
		"http://[::1]:8010":     true,
		"https://api.awid.ai":   false,
		"http://192.168.1.20":   false,
	}
	for raw, want := range cases {
		if got := initRegistryIsLocalhost(raw); got != want {
			t.Fatalf("initRegistryIsLocalhost(%q)=%v want %v", raw, got, want)
		}
	}
}

func TestNormalizeIDCreateDomainRejectsLocalByDefault(t *testing.T) {
	t.Parallel()

	_, err := normalizeIDCreateDomain("local", false)
	if err == nil {
		t.Fatal("expected local to be rejected outside the implicit local flow")
	}
}

func TestNormalizeIDCreateDomainAllowsLocalWhenRequested(t *testing.T) {
	t.Parallel()

	domain, err := normalizeIDCreateDomain("local", true)
	if err != nil {
		t.Fatalf("normalizeIDCreateDomain: %v", err)
	}
	if domain != "local" {
		t.Fatalf("domain=%q", domain)
	}
}

func TestInitUsesImplicitLocalFlowWhenRegistryIsLocalhost(t *testing.T) {
	oldLocalFlow := initRunImplicitLocalFlow
	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldAwebURL := initAwebURL
	oldRegistry := initAWIDRegistry
	oldCompatURL := initURL
	oldAlias := initAlias
	oldRole := initRole
	oldHumanName := initHumanName
	oldAgentType := initAgentType
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initURL = oldCompatURL
		initAlias = oldAlias
		initRole = oldRole
		initHumanName = oldHumanName
		initAgentType = oldAgentType
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initIsTTY = func() bool { return false }
	initAwebURL = "http://localhost:8100"
	initAWIDRegistry = "http://127.0.0.1:8010"
	initAlias = "alice"
	initRole = "developer"
	initHumanName = "Alice Operator"
	initAgentType = "codex"

	var got implicitLocalInitRequest
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		got = req
		return connectOutput{
			Status:      "connected",
			TeamID:      "default:local",
			Alias:       "alice",
			AwebURL:     req.AwebURL,
			WorkspaceID: "ws-1",
		}, nil
	}
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		t.Fatalf("guidedOnboardingWizard should not run: %+v", req)
		return nil, nil
	}

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	if err := runInit(&cmd.Command, nil); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	if got.RegistryURL != "http://127.0.0.1:8010" {
		t.Fatalf("registry=%q", got.RegistryURL)
	}
	if got.AwebURL != "http://localhost:8100" {
		t.Fatalf("aweb=%q", got.AwebURL)
	}
	if got.Alias != "alice" {
		t.Fatalf("alias=%q", got.Alias)
	}
	if got.Role != "developer" {
		t.Fatalf("role=%q", got.Role)
	}
	if got.HumanName != "Alice Operator" {
		t.Fatalf("human_name=%q", got.HumanName)
	}
	if got.AgentType != "codex" {
		t.Fatalf("agent_type=%q", got.AgentType)
	}
}

func TestInitUsesResolvedAliasForImplicitLocalFlow(t *testing.T) {
	oldLocalFlow := initRunImplicitLocalFlow
	oldIsTTY := initIsTTY
	oldAwebURL := initAwebURL
	oldRegistry := initAWIDRegistry
	oldAlias := initAlias
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initAlias = oldAlias
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	t.Setenv("AWEB_ALIAS", "env-alice")
	initIsTTY = func() bool { return false }
	initAwebURL = "http://localhost:8100"
	initAWIDRegistry = "http://127.0.0.1:8010"
	initAlias = ""

	var got implicitLocalInitRequest
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		got = req
		return connectOutput{Status: "connected", TeamID: "default:local", Alias: req.Alias}, nil
	}

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	if err := runInit(&cmd.Command, nil); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	if got.Alias != "env-alice" {
		t.Fatalf("alias=%q", got.Alias)
	}
}

func TestInitUsesGuidedOnboardingWhenRegistryIsNotLocalhost(t *testing.T) {
	oldLocalFlow := initRunImplicitLocalFlow
	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldAwebURL := initAwebURL
	oldRegistry := initAWIDRegistry
	oldAlias := initAlias
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initAlias = oldAlias
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initIsTTY = func() bool { return true }
	initAwebURL = "https://app.example.com"
	initAWIDRegistry = "https://api.example.com"
	initAlias = "alice"

	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		t.Fatalf("local flow should not run: %+v", req)
		return connectOutput{}, nil
	}

	var got guidedOnboardingRequest
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		got = req
		return &guidedOnboardingResult{}, nil
	}

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	if err := runInit(&cmd.Command, nil); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	if got.BaseURL != "https://app.example.com" {
		t.Fatalf("base_url=%q", got.BaseURL)
	}
	if got.RegistryURL != "https://api.example.com" {
		t.Fatalf("registry_url=%q", got.RegistryURL)
	}
}

func TestImplicitLocalInitProvisioningAgainstLocalServers(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	var gotNamespacePayload map[string]any
	var gotTeamPayload map[string]any
	var gotCertPayload map[string]any

	registryServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local":
			http.NotFound(w, r)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces":
			if err := json.NewDecoder(r.Body).Decode(&gotNamespacePayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id":        "ns-1",
				"domain":              "local",
				"controller_did":      gotNamespacePayload["controller_did"],
				"verification_status": "verified",
				"last_verified_at":    "2026-04-12T00:00:00Z",
				"created_at":          "2026-04-12T00:00:00Z",
			})
		case strings.HasPrefix(r.URL.Path, "/v1/namespaces/local/addresses"):
			t.Fatalf("local implicit init should not register addresses: %s %s", r.Method, r.URL.Path)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/did":
			t.Fatalf("local implicit init should not register dids: %s %s", r.Method, r.URL.Path)
		case r.Method == http.MethodGet && strings.HasPrefix(r.URL.Path, "/v1/did/") && strings.HasSuffix(r.URL.Path, "/full"):
			t.Fatalf("local implicit init should not resolve did registrations: %s %s", r.Method, r.URL.Path)
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams":
			if err := json.NewDecoder(r.Body).Decode(&gotTeamPayload); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "team-1",
				"domain":       "local",
				"name":         "default",
				"team_did_key": gotTeamPayload["team_did_key"],
				"created_at":   "2026-04-12T00:00:00Z",
			})
		case r.Method == http.MethodPost && r.URL.Path == "/v1/namespaces/local/teams/default/certificates":
			if err := json.NewDecoder(r.Body).Decode(&gotCertPayload); err != nil {
				t.Fatal(err)
			}
			w.WriteHeader(http.StatusCreated)
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	var gotConnectBody map[string]any
	awebServer := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/v1/connect":
			if err := json.NewDecoder(r.Body).Decode(&gotConnectBody); err != nil {
				t.Fatal(err)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"team_id":      "default:local",
				"alias":        "alice",
				"agent_id":     "agent-1",
				"workspace_id": "ws-1",
				"repo_id":      "repo-1",
				"team_did_key": gotTeamPayload["team_did_key"],
			})
		default:
			t.Fatalf("unexpected %s %s", r.Method, r.URL.Path)
		}
	}))

	tmp := t.TempDir()
	result, err := runImplicitLocalInit(implicitLocalInitRequest{
		WorkingDir:  tmp,
		AwebURL:     awebServer.URL,
		RegistryURL: registryServer.URL,
		Alias:       "alice",
		Role:        "developer",
		HumanName:   "Alice Operator",
		AgentType:   "codex",
	})
	if err != nil {
		t.Fatalf("runImplicitLocalInit: %v", err)
	}
	if result.TeamID != "default:local" {
		t.Fatalf("team_id=%q", result.TeamID)
	}
	if gotNamespacePayload["domain"] != "local" {
		t.Fatalf("namespace domain=%v", gotNamespacePayload["domain"])
	}
	if gotTeamPayload["name"] != "default" {
		t.Fatalf("team name=%v", gotTeamPayload["name"])
	}
	if gotCertPayload["lifetime"] != awid.LifetimeEphemeral {
		t.Fatalf("cert lifetime=%v", gotCertPayload["lifetime"])
	}
	if _, ok := gotCertPayload["member_did_aw"]; ok {
		t.Fatalf("ephemeral local cert should not include member_did_aw: %v", gotCertPayload["member_did_aw"])
	}
	if _, ok := gotCertPayload["member_address"]; ok {
		t.Fatalf("ephemeral local cert should not include member_address: %v", gotCertPayload["member_address"])
	}
	if gotConnectBody["role"] != "developer" {
		t.Fatalf("connect role=%v", gotConnectBody["role"])
	}
	if gotConnectBody["human_name"] != "Alice Operator" {
		t.Fatalf("connect human_name=%v", gotConnectBody["human_name"])
	}
	if gotConnectBody["agent_type"] != "codex" {
		t.Fatalf("connect agent_type=%v", gotConnectBody["agent_type"])
	}

	if _, err := os.Stat(filepath.Join(tmp, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("identity.yaml should not exist for implicit local init: %v", err)
	}

	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(tmp, ".aw", "workspace.yaml"))
	if err != nil {
		t.Fatalf("LoadWorktreeWorkspaceFrom: %v", err)
	}
	activeMembership := activeMembershipForTest(t, workspace)
	if workspace.ActiveTeam != "default:local" {
		t.Fatalf("active_team=%q", workspace.ActiveTeam)
	}
	if workspace.AwebURL != awebServer.URL {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
	if activeMembership.TeamID != "default:local" {
		t.Fatalf("membership team_id=%q", activeMembership.TeamID)
	}

	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, "default:local"))
	if err != nil {
		t.Fatalf("LoadTeamCertificate: %v", err)
	}
	if cert.Lifetime != awid.LifetimeEphemeral {
		t.Fatalf("loaded cert lifetime=%q", cert.Lifetime)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("loaded cert member_did_aw=%q", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("loaded cert member_address=%q", cert.MemberAddress)
	}
}

func TestRunImplicitLocalInitRequiresAlias(t *testing.T) {
	tmp := t.TempDir()
	_, err := runImplicitLocalInit(implicitLocalInitRequest{
		WorkingDir:  tmp,
		AwebURL:     "http://localhost:8100",
		RegistryURL: "http://localhost:8010",
	})
	if err == nil {
		t.Fatal("expected alias requirement error")
	}
	if !strings.Contains(err.Error(), "--alias is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
