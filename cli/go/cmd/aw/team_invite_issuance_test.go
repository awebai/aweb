package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOATSAttemptedInviteCannotCancelItsLinkedChildOrReplaceItsRecipient(t *testing.T) {
	bin, dir := buildDoctorBinary(t)
	t.Setenv("HOME", dir)
	_, controller, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	member, memberKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(dir, "recipient", ".aw")
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), memberKey); err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(controller, awid.TeamCertificateFields{Team: "one:example.com", Alias: "recipient", MemberDIDKey: awid.ComputeDIDKey(member), IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	invite := &awconfig.TeamInvite{InviteID: "attempted-test", Domain: "example.com", TeamName: "one", Secret: "bearer-never-output", IdentityScope: awid.IdentityModeLocal, CreatedAt: time.Now().UTC().Format(time.RFC3339), IDChild: &awconfig.TeamInviteIDChild{InvitationID: "11111111-1111-4111-8111-111111111111", Parent: "did:aw:parent", Domain: "example.com", IssuerHome: filepath.Join(dir, "issuer")}}
	childStore := awconfig.IDInvitationFileStore{Dir: awconfig.IdentityInvitationsDir(invite.IDChild.IssuerHome)}
	child := &awid.IDInvitation{InvitationID: invite.IDChild.InvitationID, Mode: awid.IDInvitationSelfCustodial, Parent: map[string]any{"id": invite.IDChild.Parent}, Domain: invite.Domain, Kind: "agent", Recipient: "recipient", ExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339)}
	if err := childStore.PutInvitation(child); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamInvite(invite); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.BeginTeamInviteIssuance(awconfig.BeginTeamInviteIssuanceInput{InviteID: invite.InviteID, Context: awconfig.TeamInviteIssuanceContext{IdentityHome: home, RegistryURL: "https://registry.example.com"}, Certificate: *cert}); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "id", "team", "revoke-invite", "--invite-id", invite.InviteID, "--json")
	cmd.Dir = dir
	cmd.Env = append(testCommandEnv(dir), "AW_NO_UPDATE_CHECK=1", "AWEB_IDENTITY_HOME=")
	out, err := cmd.CombinedOutput()
	var cancellation inviteCancellationOutput
	wantNext := formatShellCommand([]string{"aw", "--identity-home", home, "id", "team", "check-invite", "--invite-id", "attempted-test", "--json"})
	if err == nil || json.NewDecoder(bytes.NewReader(out)).Decode(&cancellation) != nil || cancellation.Code != "invite_issuance_pending" || cancellation.LinkedChild != inviteChildRetained || cancellation.NextStep != wantNext {
		t.Fatalf("attempt cancellation did not give a distinct refusal/action: %v\n%s", err, out)
	}
	if strings.Contains(string(out), invite.Secret) || strings.Contains(string(out), `"status": "cancelled"`) {
		t.Fatal("attempt was cancelled or exposed its bearer")
	}
	expectedStep := formatShellCommand([]string{"aw", "--identity-home", home, "id", "team", "check-invite", "--invite-id", invite.InviteID, "--json"})
	if cancellation.IdentityHome != home || cancellation.NextStep != expectedStep {
		t.Fatalf("operator recovery lost the non-default recipient home: %#v", cancellation)
	}
	vectorBytes, err := os.ReadFile(filepath.Join("..", "..", "..", "..", "docs", "vectors", "cli-integration-codes-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vector struct {
		Cancellation struct {
			States []string `json:"states"`
			Codes  []string `json:"codes"`
		} `json:"invite_cancellation"`
	}
	if err := json.Unmarshal(vectorBytes, &vector); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(vector.Cancellation.States, string(cancellation.Status)) || !slices.Contains(vector.Cancellation.Codes, cancellation.Code) {
		t.Fatal("actual pending cancellation is missing from the published CLI vocabulary")
	}
	retainedChild, err := childStore.Invitation(child.InvitationID)
	if err != nil || retainedChild == nil || retainedChild.Void {
		t.Fatalf("attempt cancellation changed its child: %v", err)
	}
	retained, err := awconfig.LoadTeamInvite(invite.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	issuance, err := awconfig.InspectTeamInviteIssuance(retained)
	if err != nil {
		t.Fatal(err)
	}
	request := nativeInviteResumeRequest{WorkingDir: dir, Options: teamAcceptInviteOptions{IdentityHome: home}, Invite: retained, Issuance: issuance}
	if _, err := validateNativeInviteResumeTarget(request); err != nil {
		t.Fatalf("exact original recipient refused: %v", err)
	}
	request.Options.Name = "different-alias"
	if _, err := validateNativeInviteResumeTarget(request); err == nil || !strings.Contains(err.Error(), "original home, member and scope") {
		t.Fatalf("different member was allowed: %v", err)
	}
	request.Options.Name = ""
	_, replacementKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), replacementKey); err != nil {
		t.Fatal(err)
	}
	if _, err := validateNativeInviteResumeTarget(request); err == nil || !strings.Contains(err.Error(), "restore the original recipient key") {
		t.Fatalf("replacement recipient key was allowed: %v", err)
	}
	// Check the private record remains an exact attempted effect after refusals.
	data, err := json.Marshal(retained.Issuance)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), invite.Secret) || strings.Contains(string(data), "signing_key") {
		t.Fatal("public issuance payload contains private custody")
	}
	if _, err := os.Stat(filepath.Join(home, "teams.yaml")); !os.IsNotExist(err) {
		t.Fatalf("refusal installed membership: %v", err)
	}
}
