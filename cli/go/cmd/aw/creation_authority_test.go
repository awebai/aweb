package main

import (
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestTeamHumanCreateExistingFoundingPathIgnoresAmbientWorkspaceKey(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	dir := whoIdentity(t, loadWhoVectors(t), false, true)
	t.Chdir(dir)
	reads := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reads++
		http.Error(w, "API path must not replace founding authority", 500)
	}))
	t.Setenv("AWEB_API_KEY", "aw_sk_workspace")
	t.Setenv("AWEB_URL", server.URL)
	before := fileDigestsForTest(t, filepath.Join(dir, ".aw"))
	err := runTeamHumanCreate(nil, []string{"newteam"})
	if err == nil || !strings.Contains(err.Error(), "hosted-managed for namespace example.com") || reads != 0 {
		t.Fatalf("existing namespace founding replaced by API: reads=%d err=%v", reads, err)
	}
	if after := fileDigestsForTest(t, filepath.Join(dir, ".aw")); !reflect.DeepEqual(before, after) {
		t.Fatal("founding refusal changed existing identity")
	}
}

func TestInitExternalCreationRequiresExplicitJoin(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	source := t.TempDir()
	writeWorkspaceBindingForTest(t, source, workspaceBinding("http://127.0.0.1:1", "dev:example.com", "source", "workspace-source"))
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(source, ".aw", "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	old := activeIdentityHome
	t.Cleanup(func() { activeIdentityHome = old })
	activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(source, ".aw"), Source: awconfig.IdentityHomeFlag}
	t.Chdir(t.TempDir())
	err = validateInitOutcomeFlags(initInviteInput{})
	if err == nil || !strings.Contains(err.Error(), "only supported for --workspace-team or explicit fresh --join-from") {
		t.Fatalf("implicit creation did not refuse the external identity home: %v", err)
	}
}
