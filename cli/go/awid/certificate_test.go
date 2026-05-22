package awid

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
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
		Team:         "backend:acme.com",
		MemberDIDKey: memberDIDKey,
		Alias:        "alice",
		Lifetime:     LifetimePersistent,
	})
	if err != nil {
		t.Fatal(err)
	}
	if cert.Team != "backend:acme.com" {
		t.Fatalf("team_id=%q", cert.Team)
	}
	if cert.MemberDIDKey != memberDIDKey {
		t.Fatalf("member_did_key=%q", cert.MemberDIDKey)
	}
	if cert.Alias != "alice" {
		t.Fatalf("alias=%q", cert.Alias)
	}
	if cert.IdentityScope != IdentityModeGlobal {
		t.Fatalf("identity_scope=%q", cert.IdentityScope)
	}
	if cert.Lifetime != LifetimePersistent {
		t.Fatalf("legacy lifetime=%q", cert.Lifetime)
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
		Team:         "backend:acme.com",
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
		Team:         "backend:acme.com",
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
		Team:         "backend:acme.com",
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
	if loaded.Team != cert.Team {
		t.Fatalf("team_id=%q want %q", loaded.Team, cert.Team)
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
		Team:         "backend:acme.com",
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
		Team:         "backend:acme.com",
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
		Team:         "backend:acme.com",
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
	if decoded.IdentityScope != IdentityModeGlobal {
		t.Fatalf("identity_scope=%q", decoded.IdentityScope)
	}
	if strings.Contains(string(data), "lifetime") {
		t.Fatalf("new certificate JSON must not emit lifetime: %s", string(data))
	}

	// Verify the key signature_payload is present when verifying
	teamPub := teamPriv.Public().(ed25519.PublicKey)
	if err := VerifyTeamCertificate(&decoded, teamPub); err != nil {
		t.Fatalf("verify after JSON round-trip: %v", err)
	}
}

func TestLegacyLifetimeTeamCertificatePreservesSignedWireShape(t *testing.T) {
	teamPub, teamPriv, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPub, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberDIDKey := ComputeDIDKey(memberPub)
	certID := "cert-legacy"
	teamID := "default:alice.aweb.ai"
	teamDIDKey := ComputeDIDKey(teamPub)
	issuedAt := "2026-05-22T00:00:00Z"

	payload := canonicalCertificatePayload(
		certID,
		teamID,
		teamDIDKey,
		memberDIDKey,
		"",
		"",
		"alice",
		LifetimePersistent,
		issuedAt,
		true,
	)
	signature := base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamPriv, []byte(payload)))
	type legacyWire struct {
		Version       int    `json:"version"`
		CertificateID string `json:"certificate_id"`
		Team          string `json:"team_id"`
		TeamDIDKey    string `json:"team_did_key"`
		MemberDIDKey  string `json:"member_did_key"`
		Alias         string `json:"alias"`
		Lifetime      string `json:"lifetime"`
		IssuedAt      string `json:"issued_at"`
		Signature     string `json:"signature"`
	}
	legacyJSON, err := json.Marshal(legacyWire{
		Version:       1,
		CertificateID: certID,
		Team:          teamID,
		TeamDIDKey:    teamDIDKey,
		MemberDIDKey:  memberDIDKey,
		Alias:         "alice",
		Lifetime:      LifetimePersistent,
		IssuedAt:      issuedAt,
		Signature:     signature,
	})
	if err != nil {
		t.Fatal(err)
	}

	decoded, err := DecodeTeamCertificateHeader(base64.StdEncoding.EncodeToString(legacyJSON))
	if err != nil {
		t.Fatal(err)
	}
	if decoded.IdentityScope != IdentityModeGlobal {
		t.Fatalf("identity_scope=%q", decoded.IdentityScope)
	}
	if err := VerifyTeamCertificate(decoded, teamPub); err != nil {
		t.Fatalf("verify decoded legacy certificate: %v", err)
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "team-cert.pem")
	if err := SaveTeamCertificate(path, decoded); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadTeamCertificate(path)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeTeamCertificateHeader(loaded)
	if err != nil {
		t.Fatal(err)
	}
	roundTripJSON, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(roundTripJSON), `"lifetime"`) {
		t.Fatalf("legacy certificate header lost signed lifetime field: %s", string(roundTripJSON))
	}
	if strings.Contains(string(roundTripJSON), `"identity_scope"`) {
		t.Fatalf("legacy certificate header must not rewrite signed lifetime to identity_scope: %s", string(roundTripJSON))
	}
	roundTrip, err := DecodeTeamCertificateHeader(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyTeamCertificate(roundTrip, teamPub); err != nil {
		t.Fatalf("verify preserved legacy certificate: %v", err)
	}
}

func TestCanonicalCertificatePayloadSortsKeys(t *testing.T) {
	payload := canonicalCertificatePayload(
		"cert-1",
		"backend:acme.com",
		"did:key:zteam",
		"did:key:zmember",
		"did:aw:test",
		"acme.com/alice",
		"alice",
		IdentityModeGlobal,
		"2026-04-09T00:00:00Z",
		false,
	)

	if strings.Index(payload, `"team_did_key"`) > strings.Index(payload, `"team_id"`) {
		t.Fatalf("payload keys not sorted as expected: %s", payload)
	}
}
