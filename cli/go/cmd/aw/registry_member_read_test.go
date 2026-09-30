package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestConfigureResolvedClientSignsPrivateTeamReads(t *testing.T) {
	withHome(t)
	pub, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	caller := awid.ComputeDIDKey(pub)
	gate := &privateTeamRegistry{t: t}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/namespaces/acme.com/teams/backend/members/alice" {
			t.Errorf("unexpected request %s", r.URL.Path)
			http.NotFound(w, r)
			return
		}
		did, signed := gate.verifyPathSignature(r)
		if !signed || did != caller {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"detail":{"code":"team_private"}}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"team_id": "backend:acme.com", "member_did_key": caller,
			"alias": "alice", "identity_scope": "local",
		})
	}))
	defer server.Close()
	raw, err := awid.NewWithIdentity(server.URL, key, caller)
	if err != nil {
		t.Fatal(err)
	}
	client := &aweb.Client{Client: raw}
	if err := configureResolvedClient(client, &awconfig.Selection{
		RegistryURL: server.URL, Address: "acme.com/me", TeamID: "backend:acme.com",
	}, server.URL); err != nil {
		t.Fatal(err)
	}
	// Exercise the configured registry directly: current-team roster routing is
	// a separate authenticated path and must retain its existing precedence.
	registry := client.Resolver().(*awid.ChainResolver).Registry
	identity, err := registry.Resolve(context.Background(), "backend:acme.com/alice")
	if err != nil {
		t.Fatalf("configured caller cannot read private team: %v", err)
	}
	if identity.DID != caller {
		t.Fatalf("resolved DID=%q", identity.DID)
	}
}
