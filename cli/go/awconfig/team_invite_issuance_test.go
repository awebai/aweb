package awconfig

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/awebai/aw/awid"
)

func prepareInviteIssuanceTest(t *testing.T) BeginTeamInviteIssuanceInput {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv("USERPROFILE", root)
	_, controller, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	member, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{
		Team: "backend:acme.com", Alias: "recipient", MemberDIDKey: awid.ComputeDIDKey(member), IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	invite := &TeamInvite{InviteID: "issuance", Domain: "acme.com", TeamName: "backend", Secret: "original-bearer", CreatedAt: "2026-11-18T00:00:00Z", ExpiresAt: "2026-11-19T00:00:00Z"}
	if err := SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	return BeginTeamInviteIssuanceInput{InviteID: invite.InviteID, Context: TeamInviteIssuanceContext{IdentityHome: filepath.Join(root, "recipient", ".aw"), RegistryURL: "https://registry.example"}, Certificate: *cert}
}

func TestInviteAttemptRetainsExactCertificateAndBlocksReleasedSecretReader(t *testing.T) {
	input := prepareInviteIssuanceTest(t)
	if err := BeginTeamInviteIssuance(input); err != nil {
		t.Fatal(err)
	}
	invite, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := InspectTeamInviteIssuance(invite)
	if err != nil || issuance == nil || issuance.State != RecoveryAttempted || issuance.PreparedEffect.CertificateID != input.Certificate.CertificateID || issuance.Context != input.Context {
		t.Fatalf("exact attempt not retained: %v", err)
	}
	data, err := json.Marshal(invite)
	if err != nil {
		t.Fatal(err)
	}
	// Released acceptors compare only this known field with the bearer token.
	var released struct {
		Secret string `json:"secret"`
	}
	if err := json.Unmarshal(data, &released); err != nil {
		t.Fatal(err)
	}
	if released.Secret != "" || invite.SuspendedSecret != "original-bearer" || invite.ConsumedAt != "" {
		t.Fatal("attempt is exposed as unused or consumed")
	}
	if err := BeginTeamInviteIssuance(input); err == nil {
		t.Fatal("second issuance replaced a pending certificate")
	}
	if err := ConsumeTeamInvite(ConsumeTeamInviteInput{InviteID: input.InviteID, Now: time.Now()}); err == nil {
		t.Fatal("non-exact consumption bypassed the fence")
	}
}

func TestInviteDefiniteRefusalRestoresTheOriginalTokenAndLifetime(t *testing.T) {
	input := prepareInviteIssuanceTest(t)
	if err := BeginTeamInviteIssuance(input); err != nil {
		t.Fatal(err)
	}
	if err := ClearTeamInviteIssuanceAfterRefusal(TeamInviteIssuanceOutcomeInput{InviteID: input.InviteID, CertificateID: input.Certificate.CertificateID}); err != nil {
		t.Fatal(err)
	}
	invite, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if invite.Secret != "original-bearer" || invite.SuspendedSecret != "" || invite.Issuance != nil || invite.ConsumedAt != "" || invite.ExpiresAt != "2026-11-19T00:00:00Z" {
		t.Fatal("refusal changed the original invitation or its lifetime")
	}
}

func TestInviteConfirmationRequiresTheExactCertificateAndClearsAllBearerSecrets(t *testing.T) {
	input := prepareInviteIssuanceTest(t)
	if err := BeginTeamInviteIssuance(input); err != nil {
		t.Fatal(err)
	}
	outcome := TeamInviteIssuanceOutcomeInput{InviteID: input.InviteID, CertificateID: "different", Now: time.Now()}
	if err := ConfirmTeamInviteIssuance(outcome); err == nil {
		t.Fatal("different certificate consumed invite")
	}
	outcome.CertificateID = input.Certificate.CertificateID
	if err := ConfirmTeamInviteIssuance(outcome); err != nil {
		t.Fatal(err)
	}
	invite, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := InspectTeamInviteIssuance(invite)
	if err != nil || issuance.State != RecoveryConfirmed || invite.ConsumedAt == "" || invite.Secret != "" || invite.SuspendedSecret != "" {
		t.Fatalf("confirmation is not a secret-free tombstone: %v", err)
	}
	if err := ClearTeamInviteIssuanceAfterRefusal(outcome); err == nil {
		t.Fatal("confirmed issuance became unused")
	}
}

func TestInviteFailedConfirmationLeavesTheDurableAttemptForExactRecovery(t *testing.T) {
	input := prepareInviteIssuanceTest(t)
	if err := BeginTeamInviteIssuance(input); err != nil {
		t.Fatal(err)
	}
	path, err := teamInvitePath(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	retained := path + ".retained"
	if err := os.Rename(path, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	outcome := TeamInviteIssuanceOutcomeInput{InviteID: input.InviteID, CertificateID: input.Certificate.CertificateID, Now: time.Now()}
	if err := ConfirmTeamInviteIssuance(outcome); err == nil {
		t.Fatal("confirmation replaced a directory")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(retained, path); err != nil {
		t.Fatal(err)
	}
	invite, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := InspectTeamInviteIssuance(invite)
	if err != nil || issuance.State != RecoveryAttempted {
		t.Fatalf("failed confirmation lost its attempt: %v", err)
	}
	if err := ConfirmTeamInviteIssuance(outcome); err != nil {
		t.Fatal(err)
	}
}

func TestInviteUnknownProgressNeverBecomesUnused(t *testing.T) {
	input := prepareInviteIssuanceTest(t)
	if err := BeginTeamInviteIssuance(input); err != nil {
		t.Fatal(err)
	}
	invite, err := LoadTeamInvite(input.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	invite.Issuance.State = RecoveryState("future-state")
	if _, err := InspectTeamInviteIssuance(invite); !errors.Is(err, ErrInviteIssuanceUnknown) {
		t.Fatal("unknown progress treated as unused")
	}
}
