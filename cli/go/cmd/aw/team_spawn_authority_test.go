package main

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestTeamSpawnAuthorityUsesSelectedIdentityTeamAuth(t *testing.T) {
	oldTeamID, oldJSON := teamSpawnAuthorityTeamID, jsonFlag
	teamSpawnAuthorityTeamID = ""
	jsonFlag = true
	t.Cleanup(func() {
		teamSpawnAuthorityTeamID = oldTeamID
		jsonFlag = oldJSON
	})

	var gotPath, gotQuery, gotAuth, gotCert string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/spawn/authority" && r.URL.Path != "/v1/spawn/authority" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		gotAuth = r.Header.Get("Authorization")
		gotCert = r.Header.Get("X-AWID-Team-Certificate")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id":        "backend:demo",
			"actor_agent_id": "agent-123",
			"auth_kind":      "team_key",
			"live_agent":     true,
			"can_spawn":      true,
		})
	}))
	defer server.Close()

	wd := t.TempDir()
	writeDefaultWorkspaceBindingForTest(t, wd, server.URL)
	t.Chdir(wd)

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&out)
	if err := runTeamSpawnAuthority(context.Background(), cmd); err != nil {
		t.Fatalf("runTeamSpawnAuthority: %v", err)
	}
	if gotPath == "" || gotQuery == "" || !strings.Contains(gotQuery, "team_id=backend%3Ademo") {
		t.Fatalf("path=%q query=%q", gotPath, gotQuery)
	}
	if !strings.HasPrefix(gotAuth, "DIDKey ") || gotCert == "" {
		t.Fatalf("auth=%q cert=%q", gotAuth, gotCert)
	}
	var decoded map[string]any
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("json output: %v\n%s", err, out.String())
	}
	if decoded["can_spawn"] != true || decoded["auth_kind"] != "team_key" {
		t.Fatalf("output=%v", decoded)
	}
}
