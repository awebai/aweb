package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestCustodyCaptureRequiresPinnedSigningKey(t *testing.T) {
	for _, scenario := range []string{"matching-key", "missing-key", "empty-capture", "local-without-identity"} {
		t.Run(scenario, func(t *testing.T) {
			service := newUnstartedCaptureService(t)
			if scenario == "missing-key" || scenario == "empty-capture" {
				if err := os.Remove(filepath.Join(service.home, "signing.key")); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "empty-capture" || scenario == "local-without-identity" {
				if err := os.Remove(filepath.Join(service.home, "identity.yaml")); err != nil {
					t.Fatal(err)
				}
			}
			capture, err := awconfig.CaptureCredentials(service.home)
			if err != nil {
				t.Fatal(err)
			}
			err = service.checkPinLocked(capture)
			valid := scenario == "matching-key" || scenario == "local-without-identity"
			if (err == nil) != valid {
				t.Fatalf("pin %s: %v", scenario, err)
			}
		})
	}
}

func TestCustodyFailedEnvelopeAttemptAllowsExactRetry(t *testing.T) {
	alice := newCustodyE2EETestIdentity(t, "acme.com/alice")
	bob := newCustodyE2EETestIdentity(t, "acme.com/bob")
	_, sessionKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	service := testCustodyE2EEService(t, alice, bob, sessionKey)
	request := signedE2EECreateRequest(t, sessionKey, alice, bob)
	service.e2eePrivateKey = nil
	if _, err := service.createE2EEEnvelope(context.Background(), request); err == nil {
		t.Fatal("missing encryption key was accepted")
	}
	service.e2eePrivateKey = alice.xPriv
	result, err := service.createE2EEEnvelope(context.Background(), request)
	if err != nil {
		t.Fatalf("retry after a failed attempt: %v", err)
	}
	retry, err := service.createE2EEEnvelope(context.Background(), request)
	if err != nil || retry != result {
		t.Fatalf("successful exact retry was not cached: %v", err)
	}
	changed := *request
	changed.Body += "changed"
	if err := awid.SignE2EECreateCustodyProof(sessionKey, &changed); err != nil {
		t.Fatal(err)
	}
	if _, err := service.createE2EEEnvelope(context.Background(), &changed); err == nil || !strings.Contains(err.Error(), "replay_detected") {
		t.Fatalf("changed reuse accepted: %v", err)
	}
}

func TestCustodySnapshotRefusesUnreadableSecondaryCertificate(t *testing.T) {
	resetCustodyClientGlobals(t)
	home := custodyFixtureHome(t)
	custodyConstructorIdentityFixture(t, home, "http://127.0.0.1:1", true)
	service, err := newCustodyService(home)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.UpdateCredentials(home.Root,
		awconfig.CredentialOperation{Command: "test-writer", Intent: "add-team"},
		func(begin func() error) error {
			if err := begin(); err != nil {
				return err
			}
			teams, err := awconfig.LoadTeamStateFromIdentityHome(home.Root)
			if err != nil {
				return err
			}
			teams.Memberships = append(teams.Memberships, awconfig.TeamMembership{
				TeamID: "secondary:example.com", Alias: "alice", CertPath: "team-certs/secondary.pem",
			})
			if err := os.WriteFile(filepath.Join(home.Root, "team-certs", "secondary.pem"), []byte("unreadable certificate"), 0o600); err != nil {
				return err
			}
			return awconfig.SaveTeamStateToIdentityHome(home.Root, teams)
		}); err != nil {
		t.Fatal(err)
	}
	capture, err := awconfig.CaptureCredentials(home.Root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.buildSnapshot(context.Background(), capture); err == nil || !strings.Contains(err.Error(), "load captured team certificates") {
		t.Fatalf("secondary certificate read was not the admission refusal: %v", err)
	}
}
