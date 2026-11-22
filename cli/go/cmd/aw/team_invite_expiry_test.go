package main

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOATSExpiredAndUnknownNativeInvitesRefuseBeforeRecipientCreation(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AWEB_IDENTITY_HOME", "")
	invite := &awconfig.TeamInvite{InviteID: "expired-native", Domain: "example.com", TeamName: "one", IdentityScope: awid.IdentityModeLocal, Secret: "private-bearer", CreatedAt: time.Now().Add(-25 * time.Hour).UTC().Format(time.RFC3339Nano)}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{invite.InviteID, "unknown-native"} {
		wire := *invite
		wire.InviteID = id
		token, err := awconfig.EncodeInviteToken(&wire)
		if err != nil {
			t.Fatal(err)
		}
		home := filepath.Join(dir, id, ".aw")
		_, err = acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
			WorkingDir: dir,
			Token:      token,
			Options:    teamAcceptInviteOptions{IdentityHome: home, Name: "recipient", Scope: awid.IdentityModeLocal},
		})
		if err == nil || errorCodeOf(err) != "invite_unknown_or_expired" || err.Error() != "This invitation is unknown or expired; ask its issuer for a new invite." {
			t.Fatalf("expiry/unknown refusal lost its one-sentence renewal action: %v", err)
		}
		var retention interface{ RetainsIdentity() bool }
		if errors.As(err, &retention) && retention.RetainsIdentity() {
			t.Fatal("an invite refused before recipient creation was classified as a retained issuance")
		}
		if _, err := os.Stat(home); !os.IsNotExist(err) {
			t.Fatalf("refused invite created a recipient: %v", err)
		}
	}
}

func TestOATSControllerInviteExpiresFlagUsesTheSavedLifetime(t *testing.T) {
	bin, dir := buildDoctorBinary(t)
	t.Setenv("HOME", dir)
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "one", key); err != nil {
		t.Fatal(err)
	}
	for _, prefix := range [][]string{{"team", "invite"}, {"id", "team", "invite"}} {
		cmd := exec.Command(bin, append(prefix, "--team-id", "one:example.com", "--expires", "48h", "--json")...)
		cmd.Dir = dir
		cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("controller --expires: %v\n%s", err, out)
		}
		var created teamInviteOutput
		if err := json.Unmarshal(out, &created); err != nil {
			t.Fatal(err)
		}
		saved, err := awconfig.LoadTeamInvite(created.InviteID)
		if err != nil {
			t.Fatal(err)
		}
		lifetime, err := awconfig.InspectTeamInviteLifecycle(awconfig.TeamInviteLifecycleRequest{Invite: saved, Now: time.Now()})
		if err != nil || lifetime.State != awconfig.TeamInviteUnused || lifetime.ExpiresAt.Sub(lifetime.CreatedAt) != 48*time.Hour || created.ExpiresAt != saved.ExpiresAt {
			t.Fatalf("CLI override did not reach saved policy/output: %v", err)
		}
	}
	keyPath, err := awconfig.TeamKeyPath("example.com", "one")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{ActiveTeam: "one:example.com", Memberships: []awconfig.TeamMembership{{
		TeamID: "one:example.com", Alias: "root", CertPath: "team-certs/one.pem",
		AwebURL: "https://service.invalid", RegistryURL: "https://registry.example.test",
	}}}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "team", "invite", "--team-id", "one:example.com", "--expires", "48h", "--preflight", "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
	out, err := cmd.CombinedOutput()
	if err == nil || !strings.Contains(string(out), "--expires selects a local controller invite lifetime; the hosted service sets its own expiry") {
		t.Fatalf("hosted explicit lifetime was admitted: %v\n%s", err, out)
	}
}

func TestOATSReleasedMalformedPositionalInviteRefusal(t *testing.T) {
	bin, dir := buildDoctorBinary(t)
	for _, verb := range [][]string{{"team", "join"}, {"id", "team", "accept-invite"}} {
		t.Run(strings.Join(verb, " "), func(t *testing.T) {
			cmd := exec.Command(bin, append(verb, "not-a-token", "--json")...)
			cmd.Dir = dir
			cmd.Env = append(testCommandEnv(dir), "AWEB_IDENTITY_HOME=", "AW_NO_UPDATE_CHECK=1")
			out, err := cmd.Output()
			exit, ok := err.(*exec.ExitError)
			_, decodeErr := awconfig.DecodeInviteToken("not-a-token")
			var envelope cliErrorEnvelope
			if !ok || exit.ExitCode() != 1 || json.Unmarshal(out, &envelope) != nil ||
				envelope.Error.Code != "error" || envelope.Error.Message != decodeErr.Error() {
				t.Fatalf("expected released malformed token refusal, got %v: %s", err, out)
			}
			if _, err := os.Lstat(filepath.Join(dir, ".aw")); !os.IsNotExist(err) {
				t.Fatalf("malformed token created an identity home: %v", err)
			}
		})
	}
}
