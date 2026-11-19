package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// fetch-cert installs only a certificate under the team's current key, and
// checks the one it already holds as it checks any other: holding the
// certificate id asked for is not evidence that it is still current.
func TestTeamFetchCertRefusesTheHeldCertificateOnceTheTeamKeyChanged(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	t.Setenv("AWID_REGISTRY_URL", registryURL)
	registry := awid.NewAWIDRegistryClient(nil, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	const domain = "fetch-current.example"

	controllerPub, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterNamespaceAt(ctx, registryURL, domain, awid.ComputeDIDKey(controllerPub), controllerKey); err != nil {
		t.Fatalf("register namespace: %v", err)
	}
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.CreateTeam(ctx, registryURL, domain, "ops", "Ops", awid.ComputeDIDKey(teamPub), controllerKey); err != nil {
		t.Fatalf("create team: %v", err)
	}
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamID := awid.BuildTeamID(domain, "ops")
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team: teamID, MemberDIDKey: awid.ComputeDIDKey(memberPub), Alias: "alice", IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := registry.RegisterCertificate(ctx, registryURL, domain, "ops", cert, teamKey); err != nil {
		t.Fatalf("register certificate: %v", err)
	}

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
	nextPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RotateTeamKey(ctx, registryURL, domain, "ops", awid.ComputeDIDKey(nextPub), nil, controllerKey); err != nil {
		t.Fatalf("rotate team key: %v", err)
	}

	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	run := exec.CommandContext(ctx, bin, "id", "team", "fetch-cert",
		"--team", "ops", "--namespace", domain, "--cert-id", cert.CertificateID, "--json")
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
