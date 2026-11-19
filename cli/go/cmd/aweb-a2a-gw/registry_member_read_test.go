package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestGatewayKeepsATeamStoredRegistryPinned(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		http.NotFound(w, r)
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", "")
	root := t.TempDir()
	writeGatewayWorkspace(t, root, server.URL)
	state, err := awconfig.LoadTeamState(root)
	if err != nil {
		t.Fatal(err)
	}
	state.Memberships[0].RegistryURL = server.URL
	if err := awconfig.SaveTeamState(root, state); err != nil {
		t.Fatal(err)
	}
	client, _, err := workspaceMailClient(root, "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.ResolveIdentity(context.Background(), "default:a2a.aweb.ai/worker")
	if err == nil || !strings.Contains(err.Error(), "must use https") {
		t.Fatalf("team-stored plain-http registry: err=%v, want the pinned refusal", err)
	}
	if requests != 0 {
		t.Fatalf("team-stored registry received %d requests, want 0", requests)
	}
}
