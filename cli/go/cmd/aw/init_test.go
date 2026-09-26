package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestInitUsesGuidedOnboardingInTTY(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.

	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldPrintReady := initPrintGuidedOnboardingReady
	oldNewAccount := initNewAccount
	t.Cleanup(func() {
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initPrintGuidedOnboardingReady = oldPrintReady
		initNewAccount = oldNewAccount
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initURL = "https://app.aweb.ai"
	initRole = "reviewer"
	initGlobal = false
	initInjectDocs = false
	initSetupHooks = false
	initWriteContext = true
	initIsTTY = func() bool { return true }
	initNewAccount = true

	var captured guidedOnboardingRequest
	var readyCalls int
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		captured = req
		return &guidedOnboardingResult{InitialPrompt: "Download and study the agent guide at https://aweb.ai/docs/agent-guide.md before doing anything else."}, nil
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

func TestInitExplicitHostedArgsInTTYSkipsOptionalPostCreatePrompts(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.

	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldPrintReady := initPrintGuidedOnboardingReady
	oldUsername := initUsername
	oldAlias := initAlias
	oldName := initName
	oldDomain := initDomain
	oldBYOD := initBYOD
	oldPersistent := initGlobal
	oldURL := initURL
	oldNewAccount := initNewAccount
	t.Cleanup(func() {
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initPrintGuidedOnboardingReady = oldPrintReady
		initUsername = oldUsername
		initAlias = oldAlias
		initName = oldName
		initDomain = oldDomain
		initBYOD = oldBYOD
		initGlobal = oldPersistent
		initURL = oldURL
		initNewAccount = oldNewAccount
	})

	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	initIsTTY = func() bool { return true }
	initURL = "https://app.aweb.ai"
	initUsername = "jane"
	initAlias = ""
	initName = "alice"
	initDomain = ""
	initBYOD = false
	initGlobal = false
	initNewAccount = true

	var captured guidedOnboardingRequest
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		captured = req
		return &guidedOnboardingResult{}, nil
	}
	initPrintGuidedOnboardingReady = func(result *guidedOnboardingResult) {}

	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)

	if err := runInit(&cmd.Command, nil); err != nil {
		t.Fatalf("runInit returned error: %v", err)
	}
	if captured.Username != "jane" || captured.Alias != "alice" {
		t.Fatalf("explicit args not passed through: %+v", captured)
	}
	if captured.NonInteractive {
		t.Fatal("TTY command should still be allowed to prompt for missing required values")
	}
	if captured.AskPostCreateSetup {
		t.Fatal("explicit command-mode init must not run optional post-create prompts")
	}
}

func TestInitNoTTYHostedRequiresExplicitNewAccountBeforeWizard(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.
	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldUsername, oldName, oldURL := initUsername, initName, initURL
	oldJSON := jsonFlag
	t.Cleanup(func() {
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initUsername, initName, initURL = oldUsername, oldName, oldURL
		jsonFlag = oldJSON
	})
	tmp := t.TempDir()
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)
	initIsTTY = func() bool { return false }
	initURL = "https://app.aweb.ai"
	initUsername = "alice"
	initName = "alice"
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		t.Fatalf("guidedOnboardingWizard should not run before explicit outcome: %+v", req)
		return nil, nil
	}
	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)
	err := runInit(&cmd.Command, nil)
	if err == nil || !strings.Contains(err.Error(), "--new-account") {
		t.Fatalf("expected --new-account usage error, got %v", err)
	}

	jsonFlag = true
	err = runInit(&cmd.Command, nil)
	if err == nil || !strings.Contains(err.Error(), "--new-account") {
		t.Fatalf("expected --json to follow no-TTY --new-account usage error, got %v", err)
	}
}

func TestInitNoTTYLocalhostRequiresExplicitNewTeamBeforeLocalFlow(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.
	oldLocalFlow := initRunImplicitLocalFlow
	oldIsTTY := initIsTTY
	oldAwebURL, oldRegistry, oldName := initAwebURL, initAWIDRegistry, initName
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		initIsTTY = oldIsTTY
		initAwebURL, initAWIDRegistry, initName = oldAwebURL, oldRegistry, oldName
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
	initName = "alice"
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		t.Fatalf("implicit local flow should not run before explicit --new-team: %+v", req)
		return connectOutput{}, nil
	}
	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)
	err := runInit(&cmd.Command, nil)
	if err == nil || !strings.Contains(err.Error(), "--new-team") {
		t.Fatalf("expected --new-team usage error, got %v", err)
	}
}

func TestInitTTYMissingOutcomeUsesChooserConfirmation(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals/stdin.
	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldURL, oldUsername, oldName, oldNewAccount := initURL, initUsername, initName, initNewAccount
	oldStdin, oldStderr := os.Stdin, os.Stderr
	t.Cleanup(func() {
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initURL, initUsername, initName, initNewAccount = oldURL, oldUsername, oldName, oldNewAccount
		os.Stdin, os.Stderr = oldStdin, oldStderr
	})
	tmp := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	discovered := filepath.Join(tmp, "discovered-workspace")
	if err := os.MkdirAll(discovered, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.RecordMachineWorkspace(awconfig.MachineWorkspaceIndexEntry{Path: discovered, TeamID: "backend:acme.com", Alias: "bob", ServerURL: "https://app.aweb.ai"}); err != nil {
		t.Fatalf("record workspace discovery: %v", err)
	}
	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer outR.Close()
	os.Stdin, os.Stderr = inR, outW
	if _, err := inW.WriteString("new-account\n"); err != nil {
		t.Fatal(err)
	}
	inW.Close()
	initIsTTY = func() bool { return true }
	initURL = "https://app.aweb.ai"
	initUsername = "alice"
	initName = "alice"
	var got guidedOnboardingRequest
	guidedOnboardingWizard = func(req guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		got = req
		return &guidedOnboardingResult{}, nil
	}
	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)
	if err := runInit(&cmd.Command, nil); err != nil {
		t.Fatalf("runInit: %v", err)
	}
	outW.Close()
	promptBytes, _ := io.ReadAll(outR)
	if !strings.Contains(string(promptBytes), "Confirmed: this will create a NEW ACCOUNT") {
		t.Fatalf("missing visible confirmation: %s", promptBytes)
	}
	if !strings.Contains(string(promptBytes), "Existing workspace discovery index") || !strings.Contains(string(promptBytes), discovered) || !strings.Contains(string(promptBytes), "aw init --join-from") {
		t.Fatalf("missing discovery choices in prompt: %s", promptBytes)
	}
	if got.Username != "alice" || got.Name != "" || got.Alias != "alice" {
		t.Fatalf("guided request after chooser=%+v", got)
	}
}

func TestRequireInitOutcomeNonTTYIncludesDiscoveryGuidance(t *testing.T) {
	// Uses HOME for discovery index; do not mark parallel.
	tmp := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	discovered := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(discovered, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.RecordMachineWorkspace(awconfig.MachineWorkspaceIndexEntry{Path: discovered, TeamID: "backend:acme.com", Alias: "alice", ServerURL: "https://app.aweb.ai"}); err != nil {
		t.Fatalf("record workspace discovery: %v", err)
	}

	err := requireOrPromptInitOutcome(false, "create a new hosted account", "--new-account")
	if err == nil {
		t.Fatal("expected missing outcome error")
	}
	text := err.Error()
	for _, want := range []string{"explicit init outcome required", "Existing workspace discovery index", discovered, "aw init --join-from"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in error:\n%v", want, err)
		}
	}
}

func TestRequireInitOutcomeTTYCanSelectDiscoveryEntry(t *testing.T) {
	// Uses HOME/globals/stdin; do not mark parallel.
	oldJoinFrom, oldJoinTeam := initJoinFrom, initJoinTeam
	oldStdin, oldStderr := os.Stdin, os.Stderr
	t.Cleanup(func() {
		initJoinFrom, initJoinTeam = oldJoinFrom, oldJoinTeam
		os.Stdin, os.Stderr = oldStdin, oldStderr
	})
	tmp := t.TempDir()
	t.Setenv("HOME", filepath.Join(tmp, "home"))
	discovered := filepath.Join(tmp, "workspace")
	if err := os.MkdirAll(discovered, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.RecordMachineWorkspace(awconfig.MachineWorkspaceIndexEntry{Path: discovered, TeamID: "backend:acme.com", Alias: "alice", ServerURL: "https://app.aweb.ai"}); err != nil {
		t.Fatalf("record workspace discovery: %v", err)
	}
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer outR.Close()
	os.Stdin, os.Stderr = inR, outW
	if _, err := inW.WriteString("1\n"); err != nil {
		t.Fatal(err)
	}
	inW.Close()

	if err := requireOrPromptInitOutcome(true, "create a new hosted account", "--new-account"); err != nil {
		t.Fatalf("prompt outcome: %v", err)
	}
	outW.Close()
	promptBytes, _ := io.ReadAll(outR)
	if initJoinFrom != discovered || initJoinTeam != "backend:acme.com" {
		t.Fatalf("selected join source=%q team=%q", initJoinFrom, initJoinTeam)
	}
	if !strings.Contains(string(promptBytes), "Confirmed: this will join team backend:acme.com") {
		t.Fatalf("missing join confirmation: %s", promptBytes)
	}
}

func TestRequireInitOutcomeTTYPersonalPromptsIdentityHome(t *testing.T) {
	// Uses globals/stdin; do not mark parallel.
	oldPersonal, oldWorkspaceKey, oldHome := initPersonalWorkspace, initWorkspaceKey, activeIdentityHome
	oldStdin, oldStderr := os.Stdin, os.Stderr
	t.Cleanup(func() {
		initPersonalWorkspace, initWorkspaceKey, activeIdentityHome = oldPersonal, oldWorkspaceKey, oldHome
		os.Stdin, os.Stderr = oldStdin, oldStderr
	})
	identityHome := filepath.Join(t.TempDir(), "principal")
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer outR.Close()
	os.Stdin, os.Stderr = inR, outW
	if _, err := inW.WriteString("personal-workspace\n" + identityHome + "\noats/workspace/test\n"); err != nil {
		t.Fatal(err)
	}
	inW.Close()

	if err := requireOrPromptInitOutcome(true, "create a new hosted account", "--new-account"); err != nil {
		t.Fatalf("prompt outcome: %v", err)
	}
	outW.Close()
	promptBytes, _ := io.ReadAll(outR)
	if !initPersonalWorkspace || initWorkspaceKey != "oats/workspace/test" || activeIdentityHome.Root != identityHome || activeIdentityHome.Source != awconfig.IdentityHomeFlag {
		t.Fatalf("personal selection personal=%v key=%q home=%+v", initPersonalWorkspace, initWorkspaceKey, activeIdentityHome)
	}
	if !strings.Contains(string(promptBytes), "explicit identity home "+identityHome) {
		t.Fatalf("missing personal confirmation: %s", promptBytes)
	}
}

func TestInitGlobalJoinRequiresExistingGlobalIdentity(t *testing.T) {
	oldGlobal, oldName := initGlobal, initName
	initGlobal = true
	initName = "alice"
	t.Cleanup(func() { initGlobal, initName = oldGlobal, oldName })
	t.Setenv("HOME", t.TempDir())
	workingDir := t.TempDir()

	err := acceptInitInviteAndConnect(authTestCmd(&bytes.Buffer{}), workingDir, "aw_inv_no_identity", "https://app.aweb.ai")
	if err == nil || !strings.Contains(err.Error(), "aw id create") {
		t.Fatalf("expected existing global identity guidance, got %v", err)
	}
}

func TestInitInviteIdentityScopeDefaultsLocalAndHonorsGlobal(t *testing.T) {
	oldGlobal := initGlobal
	t.Cleanup(func() { initGlobal = oldGlobal })
	initGlobal = false
	if got := initInviteIdentityScope(); got != awid.IdentityModeLocal {
		t.Fatalf("default scope=%q", got)
	}
	initGlobal = true
	if got := initInviteIdentityScope(); got != awid.IdentityModeGlobal {
		t.Fatalf("global scope=%q", got)
	}
}

func TestEnsureTeamAdmissionAuthForInitNonTTYRunsDeviceLogin(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldIsTTY := initIsTTY
	initIsTTY = func() bool { return false }
	t.Cleanup(func() { initIsTTY = oldIsTTY })
	home := t.TempDir()
	t.Setenv("HOME", home)

	var sawDevice, sawToken bool
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device_authorization":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("scope") != cliAuthScopeTeamAdmission {
				t.Fatalf("scope=%q", r.Form.Get("scope"))
			}
			sawDevice = true
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "device-secret", "user_code": "ABCD-EFGH", "verification_uri": serverFlag + "/oauth/device", "verification_uri_complete": serverFlag + "/oauth/device?user_code=ABCD-EFGH", "expires_in": 600, "interval": 1, "resource": serverFlag + "/cli", "scope": cliAuthScopeTeamAdmission})
		case "/oauth/token":
			if err := r.ParseForm(); err != nil {
				t.Fatal(err)
			}
			if r.Form.Get("device_code") != "device-secret" {
				t.Fatalf("device_code=%q", r.Form.Get("device_code"))
			}
			sawToken = true
			_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "team-access", "token_type": "bearer", "expires_in": 3600, "refresh_token": "team-refresh", "scope": cliAuthScopeTeamAdmission, "resource": serverFlag + "/cli"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	serverFlag = server.URL

	var out bytes.Buffer
	cmd := authTestCmd(&out)
	if err := ensureTeamAdmissionAuthForInit(cmd); err != nil {
		t.Fatalf("ensure auth: %v", err)
	}
	if !sawDevice || !sawToken {
		t.Fatalf("device=%t token=%t", sawDevice, sawToken)
	}
	if !strings.Contains(out.String(), "Open this URL to approve aw CLI login") || strings.Contains(out.String(), "team-access") || strings.Contains(out.String(), "device-secret") {
		t.Fatalf("unexpected auth output: %q", out.String())
	}
	cfg, ok, err := loadCLIAuthConfigForScope(cliAuthScopeTeamAdmission)
	if err != nil || !ok {
		t.Fatalf("load team admission auth ok=%t err=%v", ok, err)
	}
	if cfg.AccessToken != "team-access" || cfg.Scope != cliAuthScopeTeamAdmission {
		t.Fatalf("unexpected cfg=%+v", cfg)
	}
}

func TestEnsureTeamAdmissionAuthForInitNonTTYReportsDeviceExpiry(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldIsTTY := initIsTTY
	initIsTTY = func() bool { return false }
	t.Cleanup(func() { initIsTTY = oldIsTTY })
	t.Setenv("HOME", t.TempDir())

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device_authorization":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "device-secret", "user_code": "ABCD-EFGH", "verification_uri": serverFlag + "/oauth/device", "expires_in": 600, "interval": 1, "resource": serverFlag + "/cli", "scope": cliAuthScopeTeamAdmission})
		case "/oauth/token":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "expired_token"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	serverFlag = server.URL
	cliAuthLoginTimeout = 2 * time.Second

	var out bytes.Buffer
	err := ensureTeamAdmissionAuthForInit(authTestCmd(&out))
	if err == nil || !strings.Contains(err.Error(), "device code expired") {
		t.Fatalf("expected expiry, got %v", err)
	}
	if !strings.Contains(out.String(), "Open this URL") {
		t.Fatalf("missing device instructions: %q", out.String())
	}
}

func TestEnsureTeamAdmissionAuthForInitNonTTYPendingTimesOut(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldIsTTY := initIsTTY
	initIsTTY = func() bool { return false }
	t.Cleanup(func() { initIsTTY = oldIsTTY })
	t.Setenv("HOME", t.TempDir())

	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/oauth/device_authorization":
			_ = json.NewEncoder(w).Encode(map[string]any{"device_code": "device-secret", "user_code": "ABCD-EFGH", "verification_uri": serverFlag + "/oauth/device", "expires_in": 600, "interval": 1, "resource": serverFlag + "/cli", "scope": cliAuthScopeTeamAdmission})
		case "/oauth/token":
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{"error": "authorization_pending"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	serverFlag = server.URL
	cliAuthLoginTimeout = 50 * time.Millisecond

	var out bytes.Buffer
	err := ensureTeamAdmissionAuthForInit(authTestCmd(&out))
	if err == nil || !strings.Contains(err.Error(), "timed out waiting for browser approval") {
		t.Fatalf("expected pending timeout, got %v", err)
	}
	if !strings.Contains(out.String(), "Open this URL") {
		t.Fatalf("missing device instructions: %q", out.String())
	}
}

func TestEnsureTeamAdmissionAuthForInitTTYDeclineGivesLoginCommand(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldIsTTY := initIsTTY
	oldStdin, oldStderr := os.Stdin, os.Stderr
	initIsTTY = func() bool { return true }
	t.Cleanup(func() {
		initIsTTY = oldIsTTY
		os.Stdin, os.Stderr = oldStdin, oldStderr
	})
	t.Setenv("HOME", t.TempDir())
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inR.Close()
	defer outR.Close()
	os.Stdin, os.Stderr = inR, outW
	if _, err := inW.WriteString("n\n"); err != nil {
		t.Fatal(err)
	}
	inW.Close()

	err = ensureTeamAdmissionAuthForInit(authTestCmd(&bytes.Buffer{}))
	outW.Close()
	promptBytes, _ := io.ReadAll(outR)
	if err == nil || !strings.Contains(err.Error(), "aw auth login --scope cli.team_admission") {
		t.Fatalf("expected login command error, got %v", err)
	}
	if !strings.Contains(string(promptBytes), "Start bounded device login now") {
		t.Fatalf("missing prompt: %s", promptBytes)
	}
}

func TestInitOutcomeFlagValidation(t *testing.T) {
	oldJoinFrom, oldJoinTeam := initJoinFrom, initJoinTeam
	oldAdmission, oldNewAccount := initAdmissionTeamID, initNewAccount
	t.Cleanup(func() {
		initJoinFrom, initJoinTeam = oldJoinFrom, oldJoinTeam
		initAdmissionTeamID, initNewAccount = oldAdmission, oldNewAccount
	})
	initJoinFrom = "../source"
	initAdmissionTeamID = "team:example.com"
	if err := validateInitOutcomeFlags(); err == nil || !strings.Contains(err.Error(), "--join-from") || !strings.Contains(err.Error(), "--admission-team-id") {
		t.Fatalf("expected mutual exclusion naming both flags, got %v", err)
	}
	initAdmissionTeamID = ""
	initJoinFrom = ""
	initJoinTeam = "team:example.com"
	if err := validateInitOutcomeFlags(); err == nil || !strings.Contains(err.Error(), "--join-team requires --join-from") {
		t.Fatalf("expected join-team dependency error, got %v", err)
	}
	initJoinTeam = ""
	initNewAccount = true
	if err := validateInitOutcomeFlags(); err != nil {
		t.Fatalf("single outcome unexpectedly failed: %v", err)
	}
}

func TestInitFailsNonInteractiveHostedWhenRequiredFlagsMissing(t *testing.T) {
	// Cannot use t.Parallel() — needs cwd and globals.

	oldIsTTY := initIsTTY
	oldNewAccount := initNewAccount
	t.Cleanup(func() {
		initIsTTY = oldIsTTY
		initNewAccount = oldNewAccount
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
	initNewAccount = true

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
	if !strings.Contains(err.Error(), "missing required flag: --username") {
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
		Team:          "backend:acme.com",
		MemberDIDKey:  "did:key:z6MkpPublicTeamMember111111111111111111111111111",
		Alias:         "alice",
		IdentityScope: awid.IdentityModeLocal,
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
		Team:          "backend:acme.com",
		MemberDIDKey:  "did:key:z6MkpPublicTeamMember111111111111111111111111111",
		Alias:         "alice",
		IdentityScope: awid.IdentityModeLocal,
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

func TestResolveExplicitInitAwebURLPreservesAPISuffix(t *testing.T) {
	oldAwebURL := initAwebURL
	oldCompatURL := initURL
	t.Cleanup(func() {
		initAwebURL = oldAwebURL
		initURL = oldCompatURL
	})

	t.Setenv("AWEB_URL", "")
	initAwebURL = "https://app.aweb.ai/api"
	initURL = ""

	awebURL, err := resolveExplicitInitAwebURL()
	if err != nil {
		t.Fatalf("resolveExplicitInitAwebURL: %v", err)
	}
	if awebURL != "https://app.aweb.ai/api" {
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
	oldNewTeam := initNewTeam
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
		initNewTeam = oldNewTeam
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
	initNewTeam = true

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

func TestInitUsesGuidedOnboardingForExplicitHostedArgsWhenRegistryIsLocalhost(t *testing.T) {
	oldLocalFlow := initRunImplicitLocalFlow
	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldAwebURL := initAwebURL
	oldRegistry := initAWIDRegistry
	oldCompatURL := initURL
	oldBYOD := initBYOD
	oldUsername := initUsername
	oldDomain := initDomain
	oldAlias := initAlias
	oldName := initName
	oldRole := initRole
	oldPersistent := initGlobal
	oldNewAccount := initNewAccount
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initURL = oldCompatURL
		initBYOD = oldBYOD
		initUsername = oldUsername
		initDomain = oldDomain
		initAlias = oldAlias
		initName = oldName
		initRole = oldRole
		initGlobal = oldPersistent
		initNewAccount = oldNewAccount
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
	initURL = ""
	initBYOD = false
	initUsername = "alice"
	initDomain = ""
	initAlias = "laptop"
	initName = ""
	initRole = "developer"
	initGlobal = true
	initNewAccount = true

	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		t.Fatalf("local flow should not run for explicit hosted args: %+v", req)
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
	if got.BaseURL != "http://localhost:8100" {
		t.Fatalf("base_url=%q", got.BaseURL)
	}
	if got.RegistryURL != "http://127.0.0.1:8010" {
		t.Fatalf("registry_url=%q", got.RegistryURL)
	}
	if got.Username != "alice" || got.Alias != "laptop" || !got.Global {
		t.Fatalf("guided request lost hosted args: %+v", got)
	}
	if !got.NonInteractive {
		t.Fatal("expected noninteractive guided request")
	}
}

func TestInitUsesGuidedOnboardingForExplicitBYODArgsWhenRegistryIsLocalhost(t *testing.T) {
	oldLocalFlow := initRunImplicitLocalFlow
	oldWizard := guidedOnboardingWizard
	oldIsTTY := initIsTTY
	oldAwebURL := initAwebURL
	oldRegistry := initAWIDRegistry
	oldCompatURL := initURL
	oldBYOD := initBYOD
	oldUsername := initUsername
	oldDomain := initDomain
	oldAlias := initAlias
	oldName := initName
	oldRole := initRole
	oldPersistent := initGlobal
	oldNewTeam := initNewTeam
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initURL = oldCompatURL
		initBYOD = oldBYOD
		initUsername = oldUsername
		initDomain = oldDomain
		initAlias = oldAlias
		initName = oldName
		initRole = oldRole
		initGlobal = oldPersistent
		initNewTeam = oldNewTeam
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
	initURL = ""
	initBYOD = true
	initUsername = ""
	initDomain = "example.com"
	initAlias = "alice"
	initName = ""
	initRole = "developer"
	initGlobal = false
	initNewTeam = true

	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		t.Fatalf("local flow should not run for explicit BYOD args: %+v", req)
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
	if got.BaseURL != "http://localhost:8100" {
		t.Fatalf("base_url=%q", got.BaseURL)
	}
	if got.RegistryURL != "http://127.0.0.1:8010" {
		t.Fatalf("registry_url=%q", got.RegistryURL)
	}
	if !got.BYOD || got.Domain != "example.com" || got.Alias != "alice" {
		t.Fatalf("guided request lost BYOD args: %+v", got)
	}
	if !got.NonInteractive {
		t.Fatal("expected noninteractive guided request")
	}
}

func TestInitUsesResolvedAliasForImplicitLocalFlow(t *testing.T) {
	oldLocalFlow := initRunImplicitLocalFlow
	oldIsTTY := initIsTTY
	oldAwebURL := initAwebURL
	oldRegistry := initAWIDRegistry
	oldAlias := initAlias
	oldNewTeam := initNewTeam
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initAlias = oldAlias
		initNewTeam = oldNewTeam
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
	initNewTeam = true

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
	oldNewAccount := initNewAccount
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldLocalFlow
		guidedOnboardingWizard = oldWizard
		initIsTTY = oldIsTTY
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldRegistry
		initAlias = oldAlias
		initNewAccount = oldNewAccount
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
	initNewAccount = true

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
		case r.Method == http.MethodPut && r.URL.Path == "/v1/agents/me/encryption-key":
			writePublishEncryptionKeyResponseForTest(t, w, "agent-1", "default:local", "alice")
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
	if gotCertPayload["identity_scope"] != awid.IdentityModeLocal {
		t.Fatalf("cert identity_scope=%v", gotCertPayload["identity_scope"])
	}
	if _, ok := gotCertPayload["member_did_aw"]; ok {
		t.Fatalf("local cert should not include member_did_aw: %v", gotCertPayload["member_did_aw"])
	}
	if _, ok := gotCertPayload["member_address"]; ok {
		t.Fatalf("local cert should not include member_address: %v", gotCertPayload["member_address"])
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
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("LoadTeamState: %v", err)
	}
	if teamState.ActiveTeam != "default:local" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
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
	if cert.IdentityScope != awid.IdentityModeLocal {
		t.Fatalf("loaded cert identity_scope=%q", cert.IdentityScope)
	}
	if cert.MemberDIDAW != "" {
		t.Fatalf("loaded cert member_did_aw=%q", cert.MemberDIDAW)
	}
	if cert.MemberAddress != "" {
		t.Fatalf("loaded cert member_address=%q", cert.MemberAddress)
	}
}

func TestRunImplicitLocalInitRequiresName(t *testing.T) {
	tmp := t.TempDir()
	_, err := runImplicitLocalInit(implicitLocalInitRequest{
		WorkingDir:  tmp,
		AwebURL:     "http://localhost:8100",
		RegistryURL: "http://localhost:8010",
	})
	if err == nil {
		t.Fatal("expected name requirement error")
	}
	if !strings.Contains(err.Error(), "--name is required") {
		t.Fatalf("unexpected error: %v", err)
	}
}
