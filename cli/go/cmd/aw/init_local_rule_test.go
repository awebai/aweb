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
)

// --new-team without --byod creates the self-hosted `local` namespace, which
// only a registry on this machine can hold. Against any other registry, init
// refuses before minting anything and says what to do instead.
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
	for _, want := range []string{"http://awid.example.test:8010", "self-hosted", "local", "this machine", "aw team invite", "--byod --domain"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err.Error(), want)
		}
	}
	assertNoControllerKeys(t)
}

// The first machine's controller key owns `local` for the whole registry. A
// second machine is refused before it mints a controller key of its own, and
// told who holds the namespace and how to join.
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
	for _, want := range []string{owner, "another machine", "aw team invite"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("refusal %q does not say %q", err.Error(), want)
		}
	}
	assertNoControllerKeys(t)
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
