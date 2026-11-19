package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// fetch-cert installs only a certificate under the team's current key, and
// checks the one it already holds as it checks any other: holding the
// certificate id asked for is not evidence that it is still current.
func TestTeamFetchCertRefusesTheHeldCertificateOnceTheTeamKeyChanged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	world := newRealCommandWorld(t)
	ctx, registryURL, domain, teamID := world.Context, world.Stack.RegistryURL, world.Domain, world.TeamID
	memberKey := newKey(t)
	cert := world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: didOf(memberKey), Alias: "alice", IdentityScope: awid.IdentityModeLocal})

	tmp := t.TempDir()
	home := filepath.Join(tmp, ".aw")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(home, teamID, cert); err != nil {
		t.Fatal(err)
	}
	if _, err := world.Registry.RotateTeamKey(ctx, registryURL, domain, "backend", didOf(newKey(t)), nil, world.NamespaceKey); err != nil {
		t.Fatalf("rotate team key: %v", err)
	}

	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	run := exec.CommandContext(ctx, bin, "id", "team", "fetch-cert",
		"--team", "backend", "--namespace", domain, "--cert-id", cert.CertificateID, "--json")
	run.Env = append(idCreateCommandEnv(tmp), "AWID_REGISTRY_URL="+registryURL)
	run.Dir = tmp
	out, err := run.Output()

	if err == nil {
		t.Fatalf("fetch-cert accepted a certificate under a superseded team key: %s", out)
	}
	var refusal struct {
		Error struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if jsonErr := json.Unmarshal(out, &refusal); jsonErr != nil || refusal.Error.Code != "team_key_not_current" {
		t.Fatalf("fetch-cert refusal = %s, want team_key_not_current", out)
	}
}
