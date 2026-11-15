package main

import (
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

// A team on the AWID release production runs takes a member through aw's
// invite and accept, as on any registry: that release says nothing about
// team protection, and accepting needs nothing it does not say.
func TestInviteAcceptAgainstTheProductionAWIDRelease(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := productionAWIDFixture(t)
	t.Setenv("AWID_REGISTRY_URL", registryURL)

	registry := awid.NewAWIDRegistryClient(nil, nil)
	controllerPub, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterNamespaceAt(ctx, registryURL, "acme.com", awid.ComputeDIDKey(controllerPub), controllerKey); err != nil {
		t.Fatalf("register namespace: %v", err)
	}
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateTeam(ctx, registryURL, "acme.com", "backend", "Backend", awid.ComputeDIDKey(teamPub), controllerKey); err != nil {
		t.Fatalf("create team: %v", err)
	}

	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	writeTeamKeyForTest(t, tmp, "acme.com", "backend", teamKey)
	env := append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+registryURL)
	run := func(dir string, args ...string) []byte {
		t.Helper()
		cmd := exec.CommandContext(ctx, bin, args...)
		cmd.Env = env
		cmd.Dir = dir
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("aw %v: %v\n%s", args, err, out)
		}
		return out
	}

	var invite struct {
		Token string `json:"token"`
	}
	out := run(tmp, "id", "team", "invite", "--team", "backend", "--namespace", "acme.com", "--member-local", "--json")
	if err := json.Unmarshal(extractJSON(t, out), &invite); err != nil || invite.Token == "" {
		t.Fatalf("invite: %v\n%s", err, out)
	}
	member := t.TempDir()
	run(member, "id", "team", "accept-invite", invite.Token, "--name", "bob")

	certificates, err := registry.ListCertificates(ctx, registryURL, "acme.com", "backend", true, teamKey)
	if err != nil {
		t.Fatal(err)
	}
	var aliases []string
	for _, certificate := range certificates {
		aliases = append(aliases, certificate.Alias)
	}
	if len(aliases) != 1 || aliases[0] != "bob" {
		t.Fatalf("registered members = %v, want [bob]", aliases)
	}
}
