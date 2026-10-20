package main

import (
	"context"
	"crypto/ed25519"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type rotateKeyFixture struct {
	registryURL   string
	storage       realAWIDStorage
	registry      *awid.RegistryClient
	domain        string
	team          string
	teamID        string
	teamKey       ed25519.PrivateKey
	teamDID       string
	controllerKey ed25519.PrivateKey
	certificates  []*awid.TeamCertificate
}

// newRotateKeyFixture is a real AWID with a namespace, a team, two member
// certificates, and the namespace controller and team keys stored locally.
func newRotateKeyFixture(t *testing.T, domain string) rotateKeyFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL, storage := realAWIDFixtureWithStorage(t)
	registry := awid.NewAWIDRegistryClient(nil, nil)
	ctx := context.Background()

	controllerPub, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterNamespaceAt(ctx, registryURL, domain, awid.ComputeDIDKey(controllerPub), controllerKey); err != nil {
		t.Fatalf("register namespace: %v", err)
	}
	if err := awconfig.SaveControllerKey(domain, controllerKey); err != nil {
		t.Fatal(err)
	}
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDID := awid.ComputeDIDKey(teamPub)
	if _, err := registry.CreateTeam(ctx, registryURL, domain, "ops", "Ops", teamDID, controllerKey); err != nil {
		t.Fatalf("create team: %v", err)
	}
	if err := awconfig.SaveTeamKey(domain, "ops", teamKey); err != nil {
		t.Fatal(err)
	}
	f := rotateKeyFixture{
		registryURL: registryURL, storage: storage, registry: registry, domain: domain, team: "ops",
		teamID: awid.BuildTeamID(domain, "ops"), teamKey: teamKey, teamDID: teamDID, controllerKey: controllerKey,
	}
	for _, alias := range []string{"alice", "bob"} {
		memberPub, _, err := awid.GenerateKeypair()
		if err != nil {
			t.Fatal(err)
		}
		cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
			Team: f.teamID, MemberDIDKey: awid.ComputeDIDKey(memberPub), Alias: alias, IdentityScope: "local",
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := registry.RegisterCertificate(ctx, registryURL, domain, "ops", cert, teamKey); err != nil {
			t.Fatalf("register certificate %s: %v", alias, err)
		}
		f.certificates = append(f.certificates, cert)
	}
	return f
}

func (f rotateKeyFixture) options() teamRotateKeyOptions {
	return teamRotateKeyOptions{Domain: f.domain, Team: f.team, RegistryURL: f.registryURL}
}

func (f rotateKeyFixture) record(kind string, fields map[string]any, issuedAt time.Time) map[string]any {
	record := map[string]any{
		"v": 1, "type": kind, "team_id": f.teamID, "team_did_key": f.teamDID,
		"issued_at": issuedAt.UTC().Format("2006-01-02T15:04:05Z"),
	}
	for key, value := range fields {
		record[key] = value
	}
	return record
}

func (f rotateKeyFixture) seed(t *testing.T, kind string, record map[string]any, signer ed25519.PrivateKey) {
	t.Helper()
	signature, err := awid.SignAttestationRecord(signer, record)
	if err != nil {
		t.Fatal(err)
	}
	seedAWIDAttestationRecords(t, f.storage, f.domain, f.team, []map[string]any{{"kind": kind, "record": record, "signature": signature}})
}

func (f rotateKeyFixture) custodian(t *testing.T, custodianID string, at time.Time) {
	t.Helper()
	issuerPub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	f.seed(t, "team_custodians", f.record(awid.TeamCustodianRecordType, map[string]any{
		"custodian_id": custodianID, "issuer_did_keys": []any{awid.ComputeDIDKey(issuerPub)},
	}, at), f.teamKey)
}

// seedEveryKind stores one record of each kind plus a custodian with no
// custody record, which aw cannot discover except from AWID's 409.
func (f rotateKeyFixture) seedEveryKind(t *testing.T, at time.Time) {
	t.Helper()
	ctx := context.Background()
	serverRecord := awid.NewTeamServerRecord(f.teamID, f.teamDID, "https://coord."+f.domain+"/api", at)
	serverSignature, err := awid.SignTeamServerRecord(f.teamKey, serverRecord)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.registry.PublishTeamServerRecord(ctx, f.registryURL, f.domain, f.team, serverRecord, serverSignature); err != nil {
		t.Fatalf("publish team server: %v", err)
	}
	f.custodian(t, "custodian.example", at)
	f.custodian(t, "standby.example", at)
	alice, bob := f.certificates[0], f.certificates[1]
	f.seed(t, "member_custody", f.record(awid.MemberCustodyRecordType, map[string]any{
		"certificate_id": alice.CertificateID, "member_did_key": alice.MemberDIDKey, "custodian_id": "custodian.example",
	}, at), f.teamKey)
	f.seed(t, "member_person", f.record(awid.MemberPersonRecordType, map[string]any{
		"certificate_id": bob.CertificateID, "member_did_key": bob.MemberDIDKey, "single_person": true,
	}, at), f.teamKey)
}

// currentTeamDID reads the private team's key at AWID, signing with whichever
// local key AWID currently holds.
func (f rotateKeyFixture) currentTeamDID(t *testing.T) string {
	t.Helper()
	keys := []ed25519.PrivateKey{f.teamKey}
	if local, err := awconfig.LoadTeamKey(f.domain, f.team); err == nil {
		keys = append(keys, local)
	}
	if pending, err := awconfig.LoadPendingTeamKey(f.domain, f.team); err == nil && pending != nil {
		keys = append(keys, pending)
	}
	var lastErr error
	for _, key := range keys {
		team, err := f.registry.GetTeam(context.Background(), f.registryURL, f.domain, f.team, key)
		if err == nil {
			return team.TeamDIDKey
		}
		lastErr = err
	}
	t.Fatalf("get team: %v", lastErr)
	return ""
}

func requireVerifiesUnder(t *testing.T, record *awid.SignedAttestationRecord, err error, teamDID string) {
	t.Helper()
	if err != nil {
		t.Fatalf("read record: %v", err)
	}
	if verr := awid.VerifyAttestationRecord(record.Record, record.Signature, teamDID); verr != nil {
		t.Fatalf("record does not verify under the new key: %v", verr)
	}
}

func TestRotateKeyReSignsEveryRecordAndLearnsCustodiansFromTheServer(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-all.example")
	f.seedEveryKind(t, time.Now().UTC().Add(-time.Minute))
	ctx := context.Background()

	out, err := executeTeamRotateKey(ctx, f.options())
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}

	newDID := f.currentTeamDID(t)
	if newDID == f.teamDID || out.NewTeamDIDKey != newDID || out.OldTeamDIDKey != f.teamDID {
		t.Fatalf("team key after rotation = %s, output %+v", newDID, out)
	}
	if strings.Join(out.LearnedCustodians, ",") != "standby.example" {
		t.Fatalf("learned custodians = %v, want the one without custody records", out.LearnedCustodians)
	}
	if !out.ResignedTeamServer || out.ResignedCustodians != 2 || out.ResignedCustody != 1 || out.ResignedPerson != 1 {
		t.Fatalf("re-signed counts = %+v", out)
	}
	local, err := awconfig.LoadTeamKey(f.domain, f.team)
	if err != nil {
		t.Fatal(err)
	}
	if awid.ComputeDIDKey(local.Public().(ed25519.PublicKey)) != newDID {
		t.Fatal("the local team key is not the new key")
	}
	if pending, _ := awconfig.LoadPendingTeamKey(f.domain, f.team); pending != nil {
		t.Fatal("the pending team key remains after a completed rotation")
	}
	if !strings.Contains(out.Notice, "aw id team reissue-cert") {
		t.Fatalf("notice does not name the certificate re-issue command: %q", out.Notice)
	}

	server, err := f.registry.GetTeamServerRecord(ctx, f.registryURL, f.domain, f.team)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awid.VerifyTeamServerRecord(server.Record, server.Signature, f.teamID, newDID, time.Now()); err != nil {
		t.Fatalf("team server record does not verify under the new key: %v", err)
	}
	for _, custodianID := range []string{"custodian.example", "standby.example"} {
		record, err := f.registry.GetTeamCustodianRecord(ctx, f.registryURL, f.domain, f.team, custodianID)
		requireVerifiesUnder(t, record, err, newDID)
	}
	custody, err := f.registry.GetMemberCustodyRecord(ctx, f.registryURL, f.domain, f.team, f.certificates[0].CertificateID)
	requireVerifiesUnder(t, custody, err, newDID)
	person, err := f.registry.GetMemberPersonRecord(ctx, f.registryURL, f.domain, f.team, f.certificates[1].CertificateID)
	requireVerifiesUnder(t, person, err, newDID)
}

func TestRotateKeyRefusesWhenTheOneRetryStillFails(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-retry.example")
	at := time.Now().UTC().Add(-time.Minute)
	f.seedEveryKind(t, at)
	opts := f.options()
	opts.BeforeRetry = func() { f.custodian(t, "late.example", at) }

	_, err := executeTeamRotateKey(context.Background(), opts)
	if err == nil {
		t.Fatal("rotation succeeded although a second custodian appeared before the retry")
	}
	if !strings.Contains(err.Error(), "late.example") || !strings.Contains(err.Error(), "resigned_records_incomplete") {
		t.Fatalf("refusal does not carry the server's detail: %v", err)
	}
	if f.currentTeamDID(t) != f.teamDID {
		t.Fatal("the team key changed although the rotation was refused")
	}
	pending, err := awconfig.LoadPendingTeamKey(f.domain, f.team)
	if err != nil || pending == nil {
		t.Fatalf("the pending key must survive a refused rotation for the rerun: %v", err)
	}
}

func TestRotateKeyRefusesARecordThatDoesNotVerifyBeforeSigningIt(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-forged.example")
	_, otherKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	alice := f.certificates[0]
	f.seed(t, "member_person", f.record(awid.MemberPersonRecordType, map[string]any{
		"certificate_id": alice.CertificateID, "member_did_key": alice.MemberDIDKey, "single_person": true,
	}, time.Now().UTC().Add(-time.Minute)), otherKey)

	_, err = executeTeamRotateKey(context.Background(), f.options())
	if awid.AttestationRecordErrorCode(err) != "record_invalid" {
		t.Fatalf("rotation re-signed a record that does not verify under the current key: %v", err)
	}
	if f.currentTeamDID(t) != f.teamDID {
		t.Fatal("the team key changed although a stored record did not verify")
	}
}

func TestRotateKeyWithoutRecordsRotatesTheKey(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-empty.example")

	out, err := executeTeamRotateKey(context.Background(), f.options())
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}
	if f.currentTeamDID(t) != out.NewTeamDIDKey || out.NewTeamDIDKey == f.teamDID {
		t.Fatalf("team key not rotated: %+v", out)
	}
	if out.ResignedTeamServer || out.ResignedCustodians+out.ResignedCustody+out.ResignedPerson != 0 {
		t.Fatalf("re-signed records for a team without any: %+v", out)
	}
}

func TestRotateKeyResumesWithThePendingKeyAfterAnInterruption(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-resume.example")
	pendingPub, pendingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SavePendingTeamKey(f.domain, f.team, pendingKey); err != nil {
		t.Fatal(err)
	}

	out, err := executeTeamRotateKey(context.Background(), f.options())
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}
	if out.NewTeamDIDKey != awid.ComputeDIDKey(pendingPub) || f.currentTeamDID(t) != out.NewTeamDIDKey {
		t.Fatalf("rotation did not reuse the pending key: %+v", out)
	}
}

func TestRotateKeyPromotesAPendingKeyAWIDAlreadyHolds(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-promote.example")
	pendingPub, pendingKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SavePendingTeamKey(f.domain, f.team, pendingKey); err != nil {
		t.Fatal(err)
	}
	pendingDID := awid.ComputeDIDKey(pendingPub)
	if _, err := f.registry.RotateTeamKey(context.Background(), f.registryURL, f.domain, f.team, pendingDID, nil, f.controllerKey); err != nil {
		t.Fatalf("rotate at AWID: %v", err)
	}

	out, err := executeTeamRotateKey(context.Background(), f.options())
	if err != nil {
		t.Fatalf("rotate-key: %v", err)
	}
	if out.Status != "promoted" || out.NewTeamDIDKey != pendingDID {
		t.Fatalf("output = %+v, want the pending key promoted", out)
	}
	local, err := awconfig.LoadTeamKey(f.domain, f.team)
	if err != nil || awid.ComputeDIDKey(local.Public().(ed25519.PublicKey)) != pendingDID {
		t.Fatalf("local team key after promotion: %v", err)
	}
}

func TestRotateKeyRefusesWhenTheLocalKeyIsNotAWIDs(t *testing.T) {
	f := newRotateKeyFixture(t, "rotate-stale.example")
	_, strangerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(f.domain, f.team, strangerKey); err != nil {
		t.Fatal(err)
	}

	_, err = executeTeamRotateKey(context.Background(), f.options())
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("rotated with a local key AWID does not hold: %v", err)
	}
	if f.currentTeamDID(t) != f.teamDID {
		t.Fatal("the team key changed")
	}
}
