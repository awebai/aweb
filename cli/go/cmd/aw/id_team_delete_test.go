package main

import (
	"context"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// teamDeleteWorld is a real world whose namespace controller key is installed
// where aw id team delete loads it.
func teamDeleteWorld(t *testing.T) *realCommandWorld {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	world := newRealCommandWorld(t)
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	return world
}

func TestTeamDeleteHappyPath(t *testing.T) {
	world := teamDeleteWorld(t)

	// The registry refuses unknown body fields, so its acceptance proves the
	// reason travels under the field it defines.
	out, err := executeTeamDelete(world.Context, teamDeleteOptions{
		Domain: world.Domain,
		Team:   "backend",
		Reason: "retry clean byot setup",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Status != "deleted" || out.TeamID != world.TeamID || out.ControllerDID != didOf(world.NamespaceKey) {
		t.Fatalf("delete output = %+v, want deleted %s by %s", out, world.TeamID, didOf(world.NamespaceKey))
	}
	_, err = world.Registry.GetTeam(world.Context, world.Stack.RegistryURL, world.Domain, "backend", world.TeamKey)
	if code, ok := registryStatusCode(err); !ok || code != 404 {
		t.Fatalf("deleted team is still readable: %v", err)
	}
}

func TestTeamDeleteRejectsFullTeamID(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	_, err := executeTeamDelete(context.Background(), teamDeleteOptions{
		Domain: "acme.com",
		Team:   "backend:acme.com",
	})
	if err == nil || !strings.Contains(err.Error(), "not a full team id") {
		t.Fatalf("err=%v", err)
	}
}

func TestTeamDeleteActiveCertificatesMessage(t *testing.T) {
	world := teamDeleteWorld(t)
	member := newKey(t)
	certificate, err := awid.SignTeamCertificate(world.TeamKey, awid.TeamCertificateFields{
		Team: world.TeamID, MemberDIDKey: didOf(member), Alias: "alice", IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := world.Registry.RegisterCertificate(world.Context, world.Stack.RegistryURL, world.Domain, "backend", certificate, world.TeamKey); err != nil {
		t.Fatal(err)
	}

	_, err = executeTeamDelete(world.Context, teamDeleteOptions{
		Domain: world.Domain,
		Team:   "backend",
	})
	if err == nil || !strings.Contains(err.Error(), "remove-member") {
		t.Fatalf("err=%v", err)
	}
	if _, err := world.Registry.GetTeam(world.Context, world.Stack.RegistryURL, world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatalf("refused delete removed the team: %v", err)
	}
}
