package awconfig

import (
	"github.com/awebai/aw/awid"
	"path/filepath"
	"strings"
	"testing"
)

func TestTeamKeyConfirmationPersistsAndRejectsAStaleCertificateWrite(t *testing.T) {
	for _, path := range []string{TeamCertificateRelativePath("ops:example.test"), "legacy/certificate.pem"} {
		t.Run(path, func(t *testing.T) { checkTeamKeyConfirmationWrite(t, path) })
	}
}

func checkTeamKeyConfirmationWrite(t *testing.T, certificatePath string) {
	t.Helper()
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberKey, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team: "ops:example.test", MemberDIDKey: awid.ComputeDIDKey(memberKey),
		Alias: "worker", IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := awid.SaveTeamCertificate(filepath.Join(home, certificatePath), cert); err != nil {
		t.Fatal(err)
	}
	state := &TeamState{ActiveTeam: cert.Team, Memberships: []TeamMembership{{
		TeamID: cert.Team, Alias: cert.Alias, CertPath: certificatePath,
		TeamKey: &awid.TeamKeyEvidence{DIDKey: cert.TeamDIDKey, State: awid.TeamKeyUnconfirmed},
	}}}
	if err := SaveTeamStateToIdentityHome(home, state); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTeamStateFromIdentityHome(home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveMembership().TeamKey.State != awid.TeamKeyUnconfirmed {
		t.Fatal("pending key was promoted")
	}
	update := TeamKeyEvidenceUpdate{IdentityHome: home, TeamID: cert.Team, CertificateID: cert.CertificateID,
		Evidence: awid.TeamKeyEvidence{DIDKey: cert.TeamDIDKey, State: awid.TeamKeyConfirmed}}
	if err := RecordTeamKeyEvidence(update); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadTeamStateFromIdentityHome(home)
	if err != nil {
		t.Fatal(err)
	}
	if *loaded.ActiveMembership().TeamKey != update.Evidence {
		t.Fatal("registry confirmation was not retained")
	}
	update.CertificateID = "another-certificate"
	update.Evidence.State = awid.TeamKeyUnconfirmed
	if err := RecordTeamKeyEvidence(update); err == nil || !strings.Contains(err.Error(), "certificate changed during confirmation") {
		t.Fatalf("stale write: %v", err)
	}
	loaded, err = LoadTeamStateFromIdentityHome(home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveMembership().TeamKey.State != awid.TeamKeyConfirmed {
		t.Fatal("stale write changed confirmation")
	}
}
