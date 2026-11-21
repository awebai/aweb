package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOATSRealInviteResumesExactIssuanceAfterControllerPersistenceFailure(t *testing.T) {
	world := newRealCommandWorld(t)
	source := world.addLocalMember(t, "root")
	userHome := world.UserHome
	t.Setenv("HOME", userHome)
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	var minted teamInviteOutput
	if err := json.Unmarshal([]byte(world.requireCommand(t, source.Home, "team", "invite", "--team-id", world.TeamID)), &minted); err != nil {
		t.Fatal(err)
	}
	// Identity homes share one OS/controller store, as they do in join-from.
	child := filepath.Join(userHome, ".recipient.aw")
	world.requireCommand(t, child, "id", "create", "--local")
	key, err := awid.LoadSigningKey(filepath.Join(child, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := teamInviteSigningPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(world.TeamKey, awid.TeamCertificateFields{Team: world.TeamID, Alias: "recipient", MemberDIDKey: awid.ComputeDIDKey(pub), IdentityScope: awid.IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	lock, err := awconfig.LockTeamInvite(minted.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.BeginTeamInviteIssuance(awconfig.BeginTeamInviteIssuanceInput{InviteID: minted.InviteID, Context: awconfig.TeamInviteIssuanceContext{IdentityHome: child, RegistryURL: world.Stack.RegistryURL, AwebURL: world.Stack.ServerURL}, Certificate: *cert}); err != nil {
		t.Fatal(err)
	}
	if err := world.Registry.RegisterCertificate(world.Context, world.Stack.RegistryURL, world.Domain, "backend", cert, world.TeamKey); err != nil {
		t.Fatal(err)
	}
	// The remote effect is real. A directory now blocks the local outcome
	// writer; the retained pre-effect record survives and must govern retry.
	dir, err := awconfig.DefaultTeamInvitesDir()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, minted.InviteID+".json")
	retained := path + ".retained"
	if err := os.Rename(path, retained); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.ConfirmTeamInviteIssuance(awconfig.TeamInviteIssuanceOutcomeInput{InviteID: minted.InviteID, CertificateID: cert.CertificateID, Now: time.Now()}); err == nil {
		t.Fatal("confirmation overwrote a directory")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(retained, path); err != nil {
		t.Fatal(err)
	}
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	out, err := world.runInIdentityHome(source.Home, "id", "team", "revoke-invite", "--invite-id", minted.InviteID)
	if err == nil || !strings.Contains(out, "invite_issuance_pending") {
		t.Fatalf("uncertain issuer persistence was cancelled: %v\n%s", err, out)
	}
	checked := world.requireCommand(t, source.Home, "id", "team", "check-invite", "--invite-id", minted.InviteID)
	if !strings.Contains(checked, "invite_certificate_active") || !strings.Contains(checked, cert.CertificateID) {
		t.Fatalf("online check lost exact active effect: %s", checked)
	}
	// This necessarily reaches the actual registry's already-registered branch.
	world.requireCommand(t, child, "id", "team", "resume-invite", "--invite-id", minted.InviteID)
	installed, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(child, world.TeamID)
	if err != nil || installed.CertificateID != cert.CertificateID {
		t.Fatalf("recovery replaced the exact certificate: %v", err)
	}
	row, err := world.Registry.ResolveTeamMember(world.Context, world.Stack.RegistryURL, world.Domain, "backend", "recipient", world.TeamKey)
	if err != nil || row.CertificateID != cert.CertificateID {
		t.Fatalf("registry effect changed during exact replay: %v", err)
	}
	invite, err := awconfig.LoadTeamInvite(minted.InviteID)
	if err != nil {
		t.Fatal(err)
	}
	if invite.ConsumedAt == "" || invite.Secret != "" || invite.SuspendedSecret != "" || invite.Issuance.State != awconfig.RecoveryConfirmed {
		t.Fatal("confirmed membership did not consume its exact invite")
	}
	world.requireCommand(t, child, "id", "team", "resume-invite", "--invite-id", minted.InviteID)
	// Definite refusal of a fresh attempt is a different boundary: it restores
	// the original bearer for a corrected alias and does not revoke the peer.
	var unused teamInviteOutput
	if err := json.Unmarshal([]byte(world.requireCommand(t, source.Home, "team", "invite", "--team-id", world.TeamID)), &unused); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(userHome, ".other.aw")
	world.requireCommand(t, other, "id", "create", "--local")
	_, err = acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: userHome,
		Token:      unused.Token,
		Options:    teamAcceptInviteOptions{IdentityHome: other, Name: "recipient", Scope: awid.IdentityModeLocal},
	})
	if err == nil || !strings.Contains(err.Error(), "Your invite is still valid.") {
		t.Fatalf("fresh alias refusal lost its remedy: %v", err)
	}
	available, err := awconfig.LoadTeamInvite(unused.InviteID)
	if err != nil || available.Issuance != nil || available.Secret == "" || available.ConsumedAt != "" {
		t.Fatalf("definite refusal did not restore unused enrollment: %v", err)
	}
	accepted, err := acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: userHome,
		Token:      unused.Token,
		Options:    teamAcceptInviteOptions{IdentityHome: other, Name: "different-recipient", Scope: awid.IdentityModeLocal},
	})
	if err != nil || accepted.Certificate.CertificateID == cert.CertificateID {
		t.Fatalf("valid alias retry failed: %v", err)
	}
	if err := world.Registry.RevokeCertificate(world.Context, world.Stack.RegistryURL, world.Domain, "backend", cert.CertificateID, world.TeamKey); err != nil {
		t.Fatal(err)
	}
	var revoked inviteInspectionOutput
	if err := json.Unmarshal([]byte(world.requireCommand(t, source.Home, "id", "team", "check-invite", "--invite-id", minted.InviteID)), &revoked); err != nil {
		t.Fatal(err)
	}
	if revoked.State != awconfig.TeamInviteConsumed || revoked.Code != "invite_certificate_revoked" || revoked.NextStep != "" || !strings.Contains(revoked.Message, "request a new unused invitation from its issuer") {
		t.Fatalf("revoked history became unused or offered a guessed recovery command: %#v", revoked)
	}
}

func TestOATSRealGlobalRosterRetriesAfterLostRegistrationResponse(t *testing.T) {
	const alias = "recipient"
	target := filepath.Join(t.TempDir(), alias)
	home := awconfig.WorktreeIdentityHome(target)
	world := newRealCommandWorldWithRecipientFault(t, home, true)
	source := world.addLocalMember(t, "issuer")
	t.Setenv("HOME", world.UserHome)
	if err := awconfig.SaveControllerKey(world.Domain, world.NamespaceKey); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}

	if err := awconfig.SaveControllerMeta(world.Domain, &awconfig.ControllerMeta{Domain: world.Domain, RegistryURL: world.Stack.RegistryURL}); err != nil {
		t.Fatal(err)
	}

	args := []string{"team", "admin", "add", alias + ":global", "--home", target}
	out, err := world.runInIdentityHome(source.Home, args...)
	if err == nil || !strings.Contains(err.Error(), "issuance is incomplete or unknown") || !strings.Contains(err.Error(), "unexpected EOF") {
		t.Fatalf("expected the client to lose a successful registry response: %v\n%s", err, out)
	}

	keyPath := filepath.Join(home, "signing.key")
	key, err := awid.LoadSigningKey(keyPath)
	if err != nil {
		t.Fatal(err)
	}
	before, err := world.Registry.ResolveTeamMember(world.Context, world.Stack.RegistryURL, world.Domain, "backend", alias, world.TeamKey)
	if err != nil || before.MemberDIDKey != didOf(key) || before.MemberDIDAW == "" {
		t.Fatalf("real AWID did not admit the retained global identity: %#v; %v", before, err)
	}
	assertOneMembership := func() {
		t.Helper()
		rows, err := world.Registry.ListCertificates(world.Context, world.Stack.RegistryURL, world.Domain, "backend", false, world.TeamKey)
		if err != nil {
			t.Fatal(err)
		}
		var count int
		for _, row := range rows {
			if row.Alias != alias && row.MemberDIDKey != before.MemberDIDKey && row.MemberDIDAW != before.MemberDIDAW {
				continue
			}
			count++
			if row.Alias != alias || row.MemberDIDKey != before.MemberDIDKey || row.MemberDIDAW != before.MemberDIDAW ||
				row.CertificateID != before.CertificateID || row.RevokedAt != "" {
				t.Fatalf("registry changed the admitted membership: %+v", row)
			}
		}
		if count != 1 {
			t.Fatalf("expected one registry membership for %s, found %d", alias, count)
		}
	}
	assertOneMembership()

	wrong, err := world.runInIdentityHome(source.Home, "team", "admin", "add", "wrong-recipient:global", "--home", target)
	if err == nil || !strings.Contains(err.Error(), "requires the original command") {
		t.Fatalf("retry with a different name did not refuse: %v\n%s", err, wrong)
	}
	world.requireCommand(t, source.Home, args...)
	after, err := awid.LoadSigningKey(keyPath)
	if err != nil || didOf(after) != before.MemberDIDKey {
		t.Fatalf("rerun replaced the member key: %v", err)
	}
	cert, err := awconfig.LoadTeamCertificateForTeamFromIdentityHome(home, world.TeamID)
	if err != nil || cert.CertificateID != before.CertificateID || cert.MemberDIDAW != before.MemberDIDAW {
		t.Fatalf("rerun did not install the admitted certificate: %#v; %v", cert, err)
	}
	assertOneMembership()
}
