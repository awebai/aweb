package main

import (
	"net/http"
	"os"
	"testing"
)

func TestWorkspaceInviteAcceptanceDoesNotChangeAmbientServiceSelection(t *testing.T) {
	const ambient = "http://127.0.0.1:1"
	t.Setenv("AWEB_URL", ambient)
	t.Setenv("AWEB_IDENTITY_HOME", "")
	calls := 0
	server := newLocalHTTPServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/spawn/invite-preview" {
			http.NotFound(w, r)
			return
		}
		calls++
		if got := os.Getenv("AWEB_URL"); got != ambient {
			t.Errorf("acceptance changed ambient service selection: %q", got)
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	_, err := acceptWorkspaceTeamInvite(workspaceInviteAcceptance{SourceDir: t.TempDir(), ChildDir: t.TempDir(), Invite: workspaceTeamInvite{Token: "aw_inv_environment_fixture", AwebURL: server.URL}, Alias: "child"})
	if err == nil || calls != 1 {
		t.Fatalf("expected refusal from the explicitly selected service: calls=%d error=%v", calls, err)
	}
	if got := os.Getenv("AWEB_URL"); got != ambient {
		t.Fatalf("acceptance left ambient selection changed: %q", got)
	}
}
