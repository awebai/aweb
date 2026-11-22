package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
)

func TestRealTeamControllerUsesItsRegistryForMembershipEffects(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "member")
	peer := world.addLocalMember(t, "peer")
	t.Setenv("HOME", world.UserHome)
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := resolveOrCreateControllerKey(world.Domain, world.Stack.RegistryURL, time.Now().UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}

	// The process default names a different service in the same disposable
	// world. The controller record is the only saved route in these fresh
	// workspaces. Use the documented isolated-development registry transport.
	run := func(t *testing.T, dir string, args ...string) []byte {
		t.Helper()
		command := exec.CommandContext(world.Context, world.Binary, append([]string{"--json"}, args...)...)
		command.Dir = dir
		command.Env = append(idCreateCommandEnv(world.UserHome),
			"AWEB_IDENTITY_HOME=", "AWEB_API_KEY=", "AW_NO_UPDATE_CHECK=1",
			"APP_ENV=development", "AWEB_FEDERATION_TEST=1",
			"AWID_REGISTRY_URL="+world.Stack.ServerURL, "AWEB_URL="+world.Stack.ServerURL,
		)
		var diagnostic bytes.Buffer
		command.Stderr = &diagnostic
		out, err := command.Output()
		if err != nil {
			t.Fatalf("aw %v: %v\nstdout: %s\nstderr: %s", args, err, out, diagnostic.String())
		}
		return out
	}
	assertRegistryStatus := func(t *testing.T, certificateID, want string) {
		t.Helper()
		status, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", certificateID)
		if err != nil {
			t.Fatal(err)
		}
		if status.Status != want || status.TeamID != world.TeamID || status.TeamDIDKey != didOf(world.TeamKey) {
			t.Fatalf("certificate %s: wanted %s in %s under its team controller, got %+v", certificateID, want, world.TeamID, status)
		}
	}

	t.Run("remove-member", func(t *testing.T) {
		assertRegistryStatus(t, member.Certificate.CertificateID, "active")
		out := run(t, t.TempDir(), "id", "team", "remove-member", "--namespace", world.Domain, "--team", "backend", "--cert-id", member.Certificate.CertificateID)
		var removed teamRemoveMemberOutput
		if err := json.Unmarshal(out, &removed); err != nil || removed.TeamID != world.TeamID || removed.CertificateID != member.Certificate.CertificateID {
			t.Fatalf("remove member output: %v\n%s", err, out)
		}
		assertRegistryStatus(t, member.Certificate.CertificateID, "revoked")
		assertRegistryStatus(t, peer.Certificate.CertificateID, "active")
	})

	t.Run("legacy-invite-accept-and-revoke", func(t *testing.T) {
		var minted teamInviteOutput
		if err := json.Unmarshal(run(t, filepath.Dir(peer.Home), "team", "invite", "--team-id", world.TeamID), &minted); err != nil {
			t.Fatal(err)
		}
		invite, err := awconfig.LoadTeamInvite(minted.InviteID)
		if err != nil {
			t.Fatal(err)
		}
		invite.RegistryURL = ""
		if err := awconfig.SaveTeamInvite(invite); err != nil {
			t.Fatal(err)
		}

		dir := t.TempDir()
		run(t, dir, "id", "team", "accept-invite", minted.Token, "--name", "legacy-invite", "--local")
		certificate, err := awconfig.LoadTeamCertificateForTeam(dir, world.TeamID)
		if err != nil {
			t.Fatal(err)
		}
		assertRegistryStatus(t, certificate.CertificateID, "active")

		t.Setenv("AWID_REGISTRY_URL", world.Stack.ServerURL)
		t.Setenv("APP_ENV", "development")
		t.Setenv("AWEB_FEDERATION_TEST", "1")
		if err := revokeAcceptedTeamCertificate(&acceptedTeamInvite{Certificate: certificate, Domain: world.Domain, TeamName: "backend"}); err != nil {
			t.Fatal(err)
		}
		assertRegistryStatus(t, certificate.CertificateID, "revoked")
		assertRegistryStatus(t, peer.Certificate.CertificateID, "active")
	})

	t.Run("register-founding-membership", func(t *testing.T) {
		dir := t.TempDir()
		out := run(t, dir, "team", "admin", "create", "backend", "--byot", "--namespace", world.Domain, "--first-agent-name", "founder", "--first-agent-local")
		var created teamCreateOutput
		if err := json.Unmarshal(out, &created); err != nil || created.TeamID != world.TeamID || created.RegistryURL != world.Stack.RegistryURL {
			t.Fatalf("founding output: %v\n%s", err, out)
		}
		certificate, err := awconfig.LoadTeamCertificateForTeam(dir, world.TeamID)
		if err != nil {
			t.Fatal(err)
		}
		if certificate.Alias != "founder" || certificate.TeamDIDKey != didOf(world.TeamKey) {
			t.Fatalf("founding signed the wrong membership: %+v", certificate)
		}
		assertRegistryStatus(t, certificate.CertificateID, "active")
	})
}
