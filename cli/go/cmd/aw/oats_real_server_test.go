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

func TestOATSRealSingletonWorkspaceStatus(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	out := world.requireCommand(t, member.Home, "workspace", "status")
	var result map[string]json.RawMessage
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("status: %v\n%s", err, out)
	}
	if string(result["team"]) != "[]" {
		t.Fatalf("singleton roster must carry team: []: %s", out)
	}
}

func TestOATSRealExplicitHomeJoinFrom(t *testing.T) {
	world := newRealCommandWorld(t)
	source := world.addLocalMember(t, "root")
	target := filepath.Join(t.TempDir(), "named-identity")
	t.Setenv("HOME", filepath.Dir(target))
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	sourceBefore := fileDigestsForTest(t, source.Home)
	out := world.requireCommand(t, target, "init", "--join-from", source.Home, "--join-team", world.TeamID, "--name", "worker", "--do-not-touch-agents-md")
	if strings.Contains(out, "aw_inv_") {
		t.Fatalf("join exposed invite token: %s", out)
	}
	status := world.requireCommand(t, target, "id", "status", "--team", world.TeamID)
	var result identityStatusOutput
	if err := json.Unmarshal([]byte(status), &result); err != nil {
		t.Fatalf("status: %v\n%s", err, status)
	}
	if !result.MintComplete || result.Alias != "worker" {
		t.Fatalf("explicit target incomplete: %s", status)
	}
	if _, err := os.Stat(filepath.Join(target, "signing.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(target), ".aw", "signing.key")); !os.IsNotExist(err) {
		t.Fatalf("join wrote checkout identity: %v", err)
	}
	after := fileDigestsForTest(t, source.Home)
	if len(after) != len(sourceBefore) {
		t.Fatal("source state changed")
	}
	for path, digest := range sourceBefore {
		if after[path] != digest {
			t.Fatalf("source changed: %s", path)
		}
	}
}

func TestOATSRealServiceRegisterPreservesCode(t *testing.T) {
	world := newRealCommandWorld(t)
	target, err := resolveTeamRegistrationEndpoint(world.Stack.ServerURL)
	if err != nil {
		t.Fatal(err)
	}
	_, err = executeTeamRegisterWithTarget(world.Context, world.TeamKey, world.TeamID, target, false, time.Now().Add(-24*time.Hour).UTC().Format(time.RFC3339))
	if err == nil {
		t.Fatal("server must refuse an expired registration timestamp")
	}
	envelope := errorEnvelope(err, err.Error())
	if envelope.Error.Code != "invalid_controller_timestamp" || envelope.Error.HTTPStatus != 422 {
		t.Fatalf("lost service code: %#v; %v", envelope, err)
	}
	if !strings.Contains(err.Error(), "service register: http 422:") {
		t.Fatalf("changed registration refusal sentence: %v", err)
	}
}

func TestOATSRealTeamNameTakenPreservesThePrivateTeamBoundary(t *testing.T) {
	world := newRealCommandWorld(t)
	t.Setenv("HOME", t.TempDir())
	_, err := ensureLocalTeamRegistered(world.Context, world.Registry, world.Stack.RegistryURL, world.Domain, "backend", "Existing private team", world.NamespaceKey)
	if err == nil || errorCodeOf(err) != codeTeamNameTaken || !strings.HasSuffix(err.Error(), "Restore this team's controller key to reuse it, or choose another --name.") {
		t.Fatalf("private name conflict lost code or action: %v", err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	registered, err := ensureLocalTeamRegistered(world.Context, world.Registry, world.Stack.RegistryURL, world.Domain, "backend", "Existing private team", world.NamespaceKey)
	if err != nil || registered == nil {
		t.Fatalf("existing controller cannot reuse its own team: %v", err)
	}
}

func TestOATSRealIssuedInviteRemainsUsedWhenRecipientPersistenceFails(t *testing.T) {
	world := newRealCommandWorld(t)
	source := world.addLocalMember(t, "root")
	t.Setenv("HOME", filepath.Dir(source.Home))
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	createdJSON := world.requireCommand(t, source.Home, "team", "invite", "--team-id", world.TeamID)
	var created teamInviteOutput
	if err := json.Unmarshal([]byte(createdJSON), &created); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(t.TempDir(), ".aw")
	world.requireCommand(t, child, "id", "create", "--local")
	certificatePath, err := awconfig.TeamCertificatePathFromIdentityHome(child, world.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	// The registry write can finish while the subsequent local certificate
	// rename fails. An actual directory at the destination reproduces that
	// filesystem failure without replacing either the registry or the writer.
	if err := os.MkdirAll(certificatePath, 0o700); err != nil {
		t.Fatal(err)
	}
	_, acceptErr := acceptTeamInviteWithDetails(filepath.Dir(child), created.Token, teamAcceptInviteOptions{IdentityHome: child, Name: "recipient", Scope: awid.IdentityModeLocal})
	if acceptErr == nil {
		t.Fatal("accept unexpectedly persisted over the blocked certificate path")
	}
	member, err := world.Registry.ResolveTeamMember(world.Context, world.Stack.RegistryURL, world.Domain, "backend", "recipient", world.TeamKey)
	if err != nil || member.CertificateID == "" {
		t.Fatalf("test did not reach actual membership issuance: %#v; %v", member, err)
	}
	out, err := world.runInIdentityHome(source.Home, "id", "team", "revoke-invite", "--invite-id", created.InviteID)
	if err == nil || !strings.Contains(out, "invite_already_used") {
		t.Fatalf("issued membership was described as an unused cancellation: %v\n%s", err, out)
	}
	if errorCodeOf(acceptErr) != "certificate_persistence_incomplete" || !strings.Contains(acceptErr.Error(), member.CertificateID) || !strings.Contains(acceptErr.Error(), "repair its certificate path, and run `aw id team fetch-cert") {
		t.Fatalf("issued certificate has no exact recovery action: %v", acceptErr)
	}
	status, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.CertificateID)
	if err != nil || status.Status != "active" {
		t.Fatalf("invite cancellation revoked the issued certificate: %#v; %v", status, err)
	}
	if err := os.Remove(certificatePath); err != nil {
		t.Fatal(err)
	}
	world.requireCommand(t, child, "id", "team", "fetch-cert", "--namespace", world.Domain, "--team", "backend", "--cert-id", member.CertificateID, "--registry", world.Stack.RegistryURL)
}

func TestOATSRealControllerRetirement(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	peer := world.addLocalMember(t, "peer")
	t.Setenv("HOME", filepath.Dir(member.Home))
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	peerStatus := world.requireCommand(t, peer.Home, "id", "status", "--team", world.TeamID)
	var peerBinding identityStatusOutput
	if err := json.Unmarshal([]byte(peerStatus), &peerBinding); err != nil {
		t.Fatal(err)
	}
	refusal, err := world.runInIdentityHome(member.Home, "workspace", "delete", peerBinding.WorkspaceID)
	if err == nil || !strings.Contains(refusal, aliasReleaseNotSelf) {
		t.Fatalf("controller custody broadened other-member retirement: %v\n%s", err, refusal)
	}
	peerCertificate, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", peer.Certificate.CertificateID)
	if err != nil || peerCertificate.Status != "active" {
		t.Fatalf("other member's certificate changed: %#v; %v", peerCertificate, err)
	}
	out := world.requireCommand(t, member.Home, "id", "status", "--team", world.TeamID)
	var status identityStatusOutput
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatal(err)
	}
	out = world.requireCommand(t, member.Home, "workspace", "delete", status.WorkspaceID)
	var retired workspaceDeleteOutput
	if err := json.Unmarshal([]byte(out), &retired); err != nil {
		t.Fatalf("delete: %v\n%s", err, out)
	}
	if !retired.AliasReleased {
		t.Fatalf("controller-holder retirement leaked active membership: %s", out)
	}
	certificate, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil {
		t.Fatal(err)
	}
	if certificate.Status != "revoked" {
		t.Fatalf("reported complete with active certificate: %#v", certificate)
	}
}

func TestOATSRealRetirementResumesOnlyControllerRevocation(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	t.Setenv("HOME", filepath.Dir(member.Home))
	statusJSON := world.requireCommand(t, member.Home, "id", "status", "--team", world.TeamID)
	var status identityStatusOutput
	if err := json.Unmarshal([]byte(statusJSON), &status); err != nil {
		t.Fatal(err)
	}
	out, err := world.runInIdentityHome(member.Home, "workspace", "delete", status.WorkspaceID)
	if err == nil {
		t.Fatalf("missing controller must be incomplete: %s", out)
	}
	var pending workspaceDeleteOutput
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&pending); err != nil {
		t.Fatalf("pending receipt: %v\n%s", err, out)
	}
	if pending.AliasReleased || pending.RetirementCode != retiredKeyHolderRequired || pending.ReceiptPath == "" || !strings.Contains(pending.NextStep, member.Certificate.CertificateID) {
		t.Fatalf("false retirement completion: %s", out)
	}
	if _, err := os.Stat(pending.ReceiptPath); err != nil {
		t.Fatal(err)
	}
	receiptBytes, err := os.ReadFile(pending.ReceiptPath)
	if err != nil {
		t.Fatal(err)
	}
	var receipt localRetirementReceipt
	if err := json.Unmarshal(receiptBytes, &receipt); err != nil {
		t.Fatal(err)
	}
	receipt.CertificateID = "11111111-1111-4111-8111-111111111111"
	if err := saveLocalRetirementReceipt(pending.ReceiptPath, receipt); err != nil {
		t.Fatal(err)
	}
	mismatch, err := world.runInIdentityHome(member.Home, "workspace", "delete", status.WorkspaceID)
	if err == nil || !strings.Contains(mismatch, "select its original identity home before retrying") {
		t.Fatalf("mismatched receipt was accepted: %v\n%s", err, mismatch)
	}
	if err := os.WriteFile(pending.ReceiptPath, receiptBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	certificate, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil || certificate.Status != "active" {
		t.Fatalf("missing key revoked membership: %#v; %v", certificate, err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	out = world.requireCommand(t, member.Home, "workspace", "delete", status.WorkspaceID)
	var retired workspaceDeleteOutput
	if err := json.Unmarshal([]byte(out), &retired); err != nil {
		t.Fatal(err)
	}
	if !retired.AliasReleased || retired.RetirementCode != retiredAndRevoked {
		t.Fatalf("controller-only retry incomplete: %s", out)
	}
	certificate, err = world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil || certificate.Status != "revoked" {
		t.Fatalf("retry did not revoke exact certificate: %#v; %v", certificate, err)
	}
	// A completed local receipt is enough for another idempotent read of the
	// result, even after the operator removes its local controller key.
	keyPath, err := awconfig.TeamKeyPath(world.Domain, "backend")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(keyPath); err != nil {
		t.Fatal(err)
	}
	world.requireCommand(t, member.Home, "workspace", "delete", status.WorkspaceID)
}
