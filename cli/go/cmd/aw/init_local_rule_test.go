package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// --new-team without --byod creates the self-hosted `local` namespace, which
// aw init creates only through a loopback registry URL. Against any other,
// init refuses before minting anything and says what to do instead.
func TestInitNewTeamAgainstARemoteRegistryStatesTheLocalRule(t *testing.T) {
	// Cannot use t.Parallel(): needs cwd and the init globals.
	oldLocalFlow, oldWizard, oldIsTTY := initRunImplicitLocalFlow, guidedOnboardingWizard, initIsTTY
	oldAwebURL, oldRegistry, oldName, oldNewTeam := initAwebURL, initAWIDRegistry, initName, initNewTeam
	t.Cleanup(func() {
		initRunImplicitLocalFlow, guidedOnboardingWizard, initIsTTY = oldLocalFlow, oldWizard, oldIsTTY
		initAwebURL, initAWIDRegistry, initName, initNewTeam = oldAwebURL, oldRegistry, oldName, oldNewTeam
	})
	home := t.TempDir()
	t.Setenv("HOME", home)
	initIsTTY = func() bool { return false }
	initAwebURL = "http://aweb.example.test:8100"
	initAWIDRegistry = "http://awid.example.test:8010"
	initName = "alice"
	initNewTeam = true
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		t.Fatalf("local flow ran against a remote registry: %+v", req)
		return connectOutput{}, nil
	}
	guidedOnboardingWizard = func(guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		t.Fatal("hosted onboarding ran for --new-team")
		return nil, nil
	}
	cmd := &cobraCommandClone{Command: *initCmd}
	cmd.ResetFlagsForTest()
	cmd.Command.SetContext(context.Background())
	cmd.Command.SetIn(strings.NewReader(""))
	cmd.Command.SetOut(io.Discard)
	cmd.Command.SetErr(io.Discard)
	var err error
	withTestWorkingDir(t, t.TempDir(), func() {
		err = runInit(&cmd.Command, nil)
	})
	if exitCode(err) != 2 {
		t.Fatalf("want a usage refusal, got %v", err)
	}
	for _, want := range []string{"http://awid.example.test:8010", "localhost", "aw team invite", "aw team join", "aw init --new-team --byod --domain <a domain you control>"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err.Error(), want)
		}
	}
	assertNoControllerKeys(t)
}

// The controller key that created `local` on a registry controls it. A home
// without that key is refused before it mints a controller key of its own,
// and told who holds the namespace and how to join a team there.
func TestImplicitLocalInitRefusesALocalNamespaceHeldByAnotherController(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	const owner = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
	registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/v1/namespaces/local" {
			t.Errorf("unexpected registry request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{
			"namespace_id": "ns-1", "domain": "local", "controller_did": owner,
			"verification_status": "verified", "created_at": "2026-04-12T00:00:00Z",
		})
	}))
	_, err := runImplicitLocalInit(implicitLocalInitRequest{
		WorkingDir:  t.TempDir(),
		AwebURL:     "http://localhost:8100",
		RegistryURL: registry.URL,
		Alias:       "bob",
	})
	if exitCode(err) != 2 {
		t.Fatalf("want a usage refusal, got %v", err)
	}
	for _, want := range []string{registry.URL, "a key this home does not hold", "aw team invite", "aw team join", "aw init --new-team --byod --domain <a domain you control>"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err.Error(), want)
		}
	}
	assertNoControllerKeys(t)
}

// A home that controls `local` and already has the requested team is told
// so, instead of being added to that team as if it were new.
func TestImplicitLocalInitRefusesATeamThatAlreadyExists(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("local", key); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		teamName, team string
		private        bool
	}{{"", "default", false}, {"Ops", "ops", false}, {"", "default", true}} {
		registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local":
				_ = json.NewEncoder(w).Encode(map[string]any{
					"namespace_id": "ns-1", "domain": "local", "controller_did": awid.ComputeDIDKey(pub),
					"verification_status": "verified", "created_at": "2026-04-12T00:00:00Z",
				})
			case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local/teams/"+tc.team && tc.private:
				// AWID answers an unsigned read of a private team with 403
				// team_private, which discloses that it exists.
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"detail": map[string]any{"code": "team_private", "message": "Team is private; reads require a same-team signed request or the trusted service token"}})
			case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local/teams/"+tc.team:
				_ = json.NewEncoder(w).Encode(map[string]any{"team_id": tc.team + ":local", "domain": "local", "name": tc.team})
			default:
				t.Errorf("unexpected registry request %s %s", r.Method, r.URL.Path)
				http.NotFound(w, r)
			}
		}))
		_, err := runImplicitLocalInit(implicitLocalInitRequest{
			WorkingDir:  t.TempDir(),
			AwebURL:     "http://localhost:8100",
			RegistryURL: registry.URL,
			Alias:       "frank",
			TeamName:    tc.teamName,
		})
		want := "Team " + tc.team + ":local already exists. To join it, ask a member for an invite. To create another team, pass --team <name>."
		if exitCode(err) != 2 || err.Error() != want {
			t.Fatalf("team %q: want usage refusal %q, got %v", tc.team, want, err)
		}
	}
}

// --team names the local team --new-team creates, and applies to no other
// path.
func TestInitTeamFlagIsForANewLocalTeamOnly(t *testing.T) {
	// Cannot use t.Parallel(): needs cwd and the init globals.
	oldLocalFlow, oldWizard, oldIsTTY := initRunImplicitLocalFlow, guidedOnboardingWizard, initIsTTY
	oldAwebURL, oldRegistry, oldName, oldNewTeam := initAwebURL, initAWIDRegistry, initName, initNewTeam
	oldTeam, oldBYOD, oldDomain := initTeam, initBYOD, initDomain
	t.Cleanup(func() {
		initRunImplicitLocalFlow, guidedOnboardingWizard, initIsTTY = oldLocalFlow, oldWizard, oldIsTTY
		initAwebURL, initAWIDRegistry, initName, initNewTeam = oldAwebURL, oldRegistry, oldName, oldNewTeam
		initTeam, initBYOD, initDomain = oldTeam, oldBYOD, oldDomain
	})
	t.Setenv("HOME", t.TempDir())
	initIsTTY = func() bool { return false }
	guidedOnboardingWizard = func(guidedOnboardingRequest) (*guidedOnboardingResult, error) {
		t.Fatal("onboarding ran")
		return nil, nil
	}
	var gotTeam string
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		gotTeam = req.TeamName
		return connectOutput{Status: "connected", TeamID: req.TeamName + ":local", Alias: req.Alias, AwebURL: req.AwebURL}, nil
	}
	runIn := func(dir string) error {
		cmd := &cobraCommandClone{Command: *initCmd}
		cmd.ResetFlagsForTest()
		cmd.Command.SetContext(context.Background())
		cmd.Command.SetIn(strings.NewReader(""))
		cmd.Command.SetOut(io.Discard)
		cmd.Command.SetErr(io.Discard)
		var err error
		withTestWorkingDir(t, dir, func() {
			_ = captureStdout(t, func() { err = runInit(&cmd.Command, nil) })
		})
		return err
	}
	run := func() error { return runIn(t.TempDir()) }
	initAwebURL, initAWIDRegistry, initName, initTeam = "http://localhost:8100", "http://127.0.0.1:8010", "frank", "ops"

	initNewTeam, initBYOD, initDomain = true, false, ""
	if err := run(); err != nil || gotTeam != "ops" {
		t.Fatalf("--new-team --team ops: err=%v team=%q", err, gotTeam)
	}
	for _, tc := range []struct {
		name          string
		newTeam, byod bool
	}{{"without --new-team", false, false}, {"with --byod", true, true}} {
		gotTeam = ""
		initNewTeam, initBYOD, initDomain = tc.newTeam, tc.byod, ""
		if tc.byod {
			initDomain = "acme.test"
		}
		err := run()
		if exitCode(err) != 2 || err.Error() != "--team only works with --new-team in a new folder on a local (localhost) registry." || gotTeam != "" {
			t.Fatalf("%s: want the --team usage error, got %v (team %q)", tc.name, err, gotTeam)
		}
	}

	// The paths init takes before the local one never see --team, so it is
	// refused before they contact or change anything.
	initNewTeam, initBYOD, initDomain = true, false, ""
	unreachable := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("--team reached the server: %s %s", r.Method, r.URL.Path)
		http.Error(w, "refused", http.StatusTeapot)
	}))
	initAwebURL = unreachable.URL
	t.Run("with AWEB_API_KEY", func(t *testing.T) {
		t.Setenv(initAPIKeyEnvVar, "aw_sk_test")
		gotTeam = ""
		err := run()
		if exitCode(err) != 2 || !strings.Contains(err.Error(), "--team") || gotTeam != "" {
			t.Fatalf("want a --team usage error before API-key init, got %v (team %q)", err, gotTeam)
		}
	})
	t.Run("in a folder with a certificate", func(t *testing.T) {
		dir := t.TempDir()
		if _, err := awconfig.SaveTeamCertificateForTeam(dir, "default:local", &awid.TeamCertificate{Team: "default:local"}); err != nil {
			t.Fatal(err)
		}
		gotTeam = ""
		err := runIn(dir)
		if exitCode(err) != 2 || !strings.Contains(err.Error(), "--team") || gotTeam != "" {
			t.Fatalf("want a --team usage error before certificate init, got %v (team %q)", err, gotTeam)
		}
	})
}

func assertNoControllerKeys(t *testing.T) {
	t.Helper()
	dir, err := awconfig.DefaultControllersDir()
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("refusal left controller files: %v", entries)
	}
}

// When this home re-creates `local` on a registry at a new URL (the stack
// moved, or was reset), its controller record follows, so its invites carry
// the registry the team uses now.
func TestImplicitLocalInitRecordsTheRegistryItUsesNow(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	pub, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveControllerKey("local", key); err != nil {
		t.Fatal(err)
	}
	const stale = "http://127.0.0.1:1"
	if err := awconfig.SaveControllerMeta("local", &awconfig.ControllerMeta{Domain: "local", ControllerDID: awid.ComputeDIDKey(pub), RegistryURL: stale, CreatedAt: "2026-04-12T00:00:00Z"}); err != nil {
		t.Fatal(err)
	}
	registry := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local":
			_ = json.NewEncoder(w).Encode(map[string]any{
				"namespace_id": "ns-1", "domain": "local", "controller_did": awid.ComputeDIDKey(pub),
				"verification_status": "verified", "created_at": "2026-04-12T00:00:00Z",
			})
		case r.Method == http.MethodGet && r.URL.Path == "/v1/namespaces/local/teams/default":
			http.NotFound(w, r)
		default:
			// Stop the flow after the namespace is established here.
			http.Error(w, "stop", http.StatusTeapot)
		}
	}))
	_, _ = runImplicitLocalInit(implicitLocalInitRequest{
		WorkingDir:  t.TempDir(),
		AwebURL:     "http://localhost:8100",
		RegistryURL: registry.URL,
		Alias:       "alice",
	})
	meta, err := awconfig.LoadControllerMeta("local")
	if err != nil {
		t.Fatal(err)
	}
	if meta.RegistryURL != registry.URL {
		t.Fatalf("controller record keeps registry %q, want %q", meta.RegistryURL, registry.URL)
	}
	if got := registryURLForTeamInvite(t.TempDir(), "local", ""); got != registry.URL {
		t.Fatalf("invites carry registry %q, want %q", got, registry.URL)
	}
}
