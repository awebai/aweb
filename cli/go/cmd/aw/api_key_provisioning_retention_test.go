package main

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestRosterKeepsAPIKeyInitMaterialAfterSubmittedTransportFailure(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	t.Setenv(initAPIKeyEnvVar, "")
	t.Chdir(root)
	var submittedDID string
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveAPIKeyCreationTeamRead(w, r, "default:recovery.aweb.ai") {
			return
		}
		if r.URL.Path != "/api/v1/workspaces/init" {
			t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
			return
		}
		var request struct {
			DID string `json:"did"`
		}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Error(err)
			return
		}
		submittedDID = request.DID
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			t.Error("HTTP fixture cannot close the submitted connection")
			return
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		if err := connection.Close(); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	teamHumanExtendAPIKey = "aw_sk_recovery_fixture"
	initAwebURL = server.URL
	err := runTeamHumanExtend(nil, []string{"retained"})
	if err == nil || submittedDID == "" {
		t.Fatalf("submission boundary was not reached: %v", err)
	}
	home := awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(filepath.Join(root, "agents", "instances", "retained"))}
	state, readErr := loadAPIKeyPartialInit(apiKeyPartialInitPath(home))
	if readErr != nil || state == nil || state.DIDKey != submittedDID || state.SigningKeyB64 == "" || state.IDTree == nil || state.IDTree.RequestID == "" {
		t.Fatalf("outer roster cleanup discarded the submitted key/request: %v", readErr)
	}
	if !retainUnfinishedProvisioningIdentity(err) {
		t.Fatalf("submitted API-key recovery was not exposed through the shared retention contract: %v", err)
	}
	if !strings.Contains(err.Error(), filepath.Dir(home.Root)) || !strings.Contains(err.Error(), "run `aw init") || !strings.Contains(err.Error(), "--alias retained") || strings.Contains(err.Error(), teamHumanExtendAPIKey) {
		t.Fatal("recovery advice lost its child target/command or exposed the setup key")
	}
}
