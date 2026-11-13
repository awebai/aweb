package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// signTeamCertificateWithoutIDForTest returns a certificate whose signature
// verifies under its own team key but whose certificate_id is empty, which
// the strict team certificate check refuses as an invalid field.
func signTeamCertificateWithoutIDForTest(t *testing.T, teamKey ed25519.PrivateKey, cert awid.TeamCertificate) *awid.TeamCertificate {
	t.Helper()
	cert.Version = 1
	cert.CertificateID = ""
	cert.TeamDIDKey = awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	if cert.IssuedAt == "" {
		cert.IssuedAt = "2026-11-12T00:00:00Z"
	}
	unsigned := map[string]any{
		"version":        1,
		"certificate_id": cert.CertificateID,
		"team_id":        cert.Team,
		"team_did_key":   cert.TeamDIDKey,
		"member_did_key": cert.MemberDIDKey,
		"alias":          cert.Alias,
		"identity_scope": cert.IdentityScope,
		"issued_at":      cert.IssuedAt,
	}
	if cert.MemberDIDAW != "" {
		unsigned["member_did_aw"] = cert.MemberDIDAW
	}
	if cert.MemberAddress != "" {
		unsigned["member_address"] = cert.MemberAddress
	}
	payload, err := awid.CanonicalJSONValue(unsigned)
	if err != nil {
		t.Fatal(err)
	}
	cert.Signature = base64.RawStdEncoding.EncodeToString(ed25519.Sign(teamKey, []byte(payload)))
	return &cert
}

func TestAPIKeyBootstrapRefusesAWellSignedCertificateWithoutID(t *testing.T) {
	t.Parallel()

	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert := signTeamCertificateWithoutIDForTest(t, teamKey, awid.TeamCertificate{
		Team:          "backend:acme.com",
		MemberDIDKey:  awid.ComputeDIDKey(memberPub),
		Alias:         "alice",
		IdentityScope: awid.IdentityModeLocal,
	})
	if err := verifyAPIKeyBootstrapCertificate(cert); err == nil {
		t.Fatal("accepted a certificate without a certificate_id")
	}
}

func TestHostedTeamInviteAcceptRefusesAWellSignedCertificateWithoutID(t *testing.T) {
	t.Parallel()

	memberPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(memberPub)
	cert := signTeamCertificateWithoutIDForTest(t, teamKey, awid.TeamCertificate{
		Team:          "backend:acme.com",
		MemberDIDKey:  didKey,
		Alias:         "alice",
		IdentityScope: awid.IdentityModeLocal,
	})
	encoded, err := awid.EncodeTeamCertificateHeader(cert)
	if err != nil {
		t.Fatal(err)
	}
	resp := &awid.SpawnAcceptInviteResponse{ServerURL: "https://app.example.com/api", TeamCert: encoded}
	_, _, err = validateHostedTeamInviteAcceptResponse(resp, didKey, "alice", "", "", awid.IdentityModeLocal, true)
	if err == nil || !strings.Contains(err.Error(), "certificate_id") {
		t.Fatalf("want a certificate_id refusal, got %v", err)
	}
}

func TestAwDoctorLocalFailsAWellSignedCertificateWithoutID(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorLocalFixture(t, tmp, "https://app.example.com/api")
	certPath := awconfig.TeamCertificatePath(tmp, resolvedTeamIDForTest("backend:example.com"))
	installed, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(certPath, signTeamCertificateWithoutIDForTest(t, teamKey, *installed)); err != nil {
		t.Fatal(err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor should report the certificate as a check: %v\n%s", err, string(out))
	}
	requireDoctorCheckStatus(t, decodeDoctorOutput(t, out), doctorCheckCertificateSignature, doctorStatusFail)
}
