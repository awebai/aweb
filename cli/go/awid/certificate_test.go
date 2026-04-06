package awid

import (
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSignAndVerifyTeamCertificate(t *testing.T) {
	teamPub, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDIDKey := ComputeDIDKey(teamPub)
	memberDIDKey := ComputeDIDKey(memberPub)

	cert, err := SignTeamCertificate(teamPriv, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: memberDIDKey,
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.TeamAddress != "acme.com/backend" {
		t.Fatalf("team_address=%q", cert.TeamAddress)
	}
	if cert.MemberDIDKey != memberDIDKey {
		t.Fatalf("member_did_key=%q", cert.MemberDIDKey)
	}
	if cert.Alias != "alice" {
		t.Fatalf("alias=%q", cert.Alias)
	}
	if cert.Lifetime != LifetimePersistent {
		t.Fatalf("lifetime=%q", cert.Lifetime)
	}
	if cert.TeamDIDKey != teamDIDKey {
		t.Fatalf("team_did_key=%q", cert.TeamDIDKey)
	}
	if cert.CertificateID == "" {
		t.Fatal("certificate_id is empty")
	}
	if cert.IssuedAt == "" {
		t.Fatal("issued_at is empty")
	}
	if cert.Signature == "" {
		t.Fatal("signature is empty")
	}

	if err := VerifyTeamCertificate(cert, teamPub); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyTeamCertificateRejectsTampered(t *testing.T) {
	teamPub, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := SignTeamCertificate(teamPriv, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	tampered := *cert
	tampered.Alias = "mallory"
	if err := VerifyTeamCertificate(&tampered, teamPub); err == nil {
		t.Fatal("expected verification to fail for tampered certificate")
	}
}

func TestVerifyTeamCertificateRejectsWrongTeamKey(t *testing.T) {
	_, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	otherPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := SignTeamCertificate(teamPriv, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	if err := VerifyTeamCertificate(cert, otherPub); err == nil {
		t.Fatal("expected verification to fail with wrong team key")
	}
}

func TestSaveAndLoadTeamCertificate(t *testing.T) {
	_, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := SignTeamCertificate(teamPriv, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, ".aw", "team-cert.pem")

	if err := SaveTeamCertificate(path, cert); err != nil {
		t.Fatal(err)
	}

	loaded, err := LoadTeamCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.CertificateID != cert.CertificateID {
		t.Fatalf("certificate_id=%q want %q", loaded.CertificateID, cert.CertificateID)
	}
	if loaded.TeamAddress != cert.TeamAddress {
		t.Fatalf("team_address=%q want %q", loaded.TeamAddress, cert.TeamAddress)
	}
	if loaded.MemberDIDKey != cert.MemberDIDKey {
		t.Fatalf("member_did_key=%q", loaded.MemberDIDKey)
	}
	if loaded.Signature != cert.Signature {
		t.Fatalf("signature mismatch")
	}
}

func TestSaveTeamCertificatePermissions(t *testing.T) {
	_, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := SignTeamCertificate(teamPriv, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "team-cert.pem")
	if err := SaveTeamCertificate(path, cert); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("mode=%#o want %#o", got, 0o600)
	}
}

func TestEncodeTeamCertificateForHeader(t *testing.T) {
	_, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := SignTeamCertificate(teamPriv, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	encoded, err := EncodeTeamCertificateHeader(cert)
	if err != nil {
		t.Fatal(err)
	}
	if encoded == "" {
		t.Fatal("encoded certificate header is empty")
	}

	decoded, err := DecodeTeamCertificateHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.CertificateID != cert.CertificateID {
		t.Fatalf("decoded certificate_id=%q want %q", decoded.CertificateID, cert.CertificateID)
	}
}

func TestTeamCertificateJSON(t *testing.T) {
	_, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	cert, err := SignTeamCertificate(teamPriv, TeamCertificateFields{
		TeamAddress:  "acme.com/backend",
		MemberDIDKey: ComputeDIDKey(memberPub),
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}

	data, err := json.Marshal(cert)
	if err != nil {
		t.Fatal(err)
	}

	var decoded TeamCertificate
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.CertificateID != cert.CertificateID {
		t.Fatalf("certificate_id mismatch after JSON round-trip")
	}

	// Verify the key signature_payload is present when verifying
	teamPub := teamPriv.Public().(ed25519.PublicKey)
	if err := VerifyTeamCertificate(&decoded, teamPub); err != nil {
		t.Fatalf("verify after JSON round-trip: %v", err)
	}
}
