package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestGatewaySignsPrivateTeamMemberRead(t *testing.T) {
	var caller string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/a2a.aweb.ai/teams/default/members/worker" {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		parts := strings.Fields(r.Header.Get("Authorization"))
		valid := false
		if len(parts) == 3 && parts[0] == "DIDKey" && parts[1] == caller {
			pub, err := awid.ExtractPublicKey(caller)
			sig, sigErr := base64.RawStdEncoding.DecodeString(parts[2])
			timestamp := r.Header.Get("X-AWEB-Timestamp")
			valid = err == nil && sigErr == nil && timestamp != "" && ed25519.Verify(pub, []byte(timestamp+"\nGET\n"+r.URL.Path), sig)
		}
		if !valid {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"detail":{"code":"team_private"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"team_id": "default:a2a.aweb.ai", "member_did_key": caller, "alias": "worker", "identity_scope": "local"})
	}))
	defer server.Close()
	t.Setenv("AWID_REGISTRY_URL", "")
	root := t.TempDir()
	writeGatewayWorkspace(t, root, server.URL)
	client, _, err := workspaceMailClient(root, "", server.URL, "")
	if err != nil {
		t.Fatal(err)
	}
	caller = client.DID()
	identity, err := client.ResolveIdentity(context.Background(), "default:a2a.aweb.ai/worker")
	if err != nil {
		t.Fatalf("gateway private team read: %v", err)
	}
	if identity.DID != caller {
		t.Fatalf("recipient DID=%q", identity.DID)
	}
}

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
