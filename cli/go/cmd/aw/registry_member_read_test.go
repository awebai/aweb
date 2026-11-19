package main

import (
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestConfigureResolvedClientSignsPrivateTeamReads(t *testing.T) {
	withHome(t)
	world := newRealCommandWorld(t)
	key := newKey(t)
	caller := didOf(key)
	// The world's team is private; only its members may read its roster.
	world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: caller, Alias: "alice", IdentityScope: awid.IdentityModeLocal})
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	raw, err := awid.NewWithIdentity(world.Stack.ServerURL, key, caller)
	if err != nil {
		t.Fatal(err)
	}
	client := &aweb.Client{Client: raw}
	if err := configureResolvedClient(client, &awconfig.Selection{
		RegistryURL: world.Stack.RegistryURL, Address: world.Domain + "/me", TeamID: world.TeamID,
	}, world.Stack.ServerURL); err != nil {
		t.Fatal(err)
	}
	// Exercise the configured registry directly: current-team roster routing is
	// a separate authenticated path and must retain its existing precedence.
	registry := client.Resolver().(*awid.ChainResolver).Registry
	identity, err := registry.Resolve(world.Context, world.TeamID+"/alice")
	if err != nil {
		t.Fatalf("configured caller cannot read private team: %v", err)
	}
	if identity.DID != caller {
		t.Fatalf("resolved DID=%q", identity.DID)
	}
}
