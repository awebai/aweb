package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestOATSRealFailedRevocationKeepsTheLocalCertificate(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	t.Setenv("HOME", world.UserHome)
	t.Setenv("AWID_REGISTRY_URL", world.Stack.RegistryURL)
	_, wrongKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", wrongKey); err != nil {
		t.Fatal(err)
	}
	accepted := &acceptedTeamInvite{
		Output:      &teamAcceptInviteOutput{CertPath: awconfig.TeamCertificateRelativePath(world.TeamID)},
		Certificate: member.Certificate, Domain: world.Domain, TeamName: "backend", RegistryURL: world.Stack.RegistryURL,
	}
	path, err := awconfig.TeamCertificatePathFromIdentityHome(member.Home, world.TeamID)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("recording accepted workspace membership failed")
	err = rollbackAddedTeamCertificate(filepath.Dir(member.Home), member.Home, accepted, cause)
	if !errors.Is(err, cause) || errorCodeOf(err) != "certificate_rollback_pending" || !strings.Contains(err.Error(), member.Certificate.CertificateID) || !strings.HasSuffix(err.Error(), "Retain the identity home and ask the team controller to revoke this certificate before retrying.") {
		t.Fatalf("failed revoke lost its exact recovery: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("failed revoke discarded the local certificate: %v", err)
	}
	status, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil || status.Status != "active" {
		t.Fatalf("wrong controller changed the certificate: %#v; %v", status, err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	if err := rollbackAddedTeamCertificate(filepath.Dir(member.Home), member.Home, accepted, cause); !errors.Is(err, cause) || errorCodeOf(err) == "certificate_rollback_pending" {
		t.Fatalf("valid controller could not revoke: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("confirmed revoke left the local certificate: %v", err)
	}
	status, err = world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil || status.Status != "revoked" {
		t.Fatalf("valid controller did not revoke the certificate: %#v; %v", status, err)
	}
}

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
	t.Setenv("HOME", world.UserHome)
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
	// The supported token-taking team join path must also connect to the saved
	// service when its unsigned token carries another hint. The explicit-home
	// init path above and below uses --join-from, as its public flags require.
	createdJSON := world.requireCommand(t, source.Home, "team", "invite", "--team-id", world.TeamID)
	var created teamInviteOutput
	if err := json.Unmarshal([]byte(createdJSON), &created); err != nil {
		t.Fatal(err)
	}
	wire, err := awconfig.DecodeInviteToken(created.Token)
	if err != nil {
		t.Fatal(err)
	}
	wire.AwebURL = "http://127.0.0.1:1"
	changedToken, err := awconfig.EncodeInviteToken(&awconfig.TeamInvite{InviteID: wire.InviteID, Domain: wire.Domain, TeamName: wire.TeamName, Secret: wire.Secret, RegistryURL: wire.RegistryURL, AwebURL: wire.AwebURL})
	if err != nil {
		t.Fatal(err)
	}
	nativeTarget := filepath.Join(filepath.Dir(target), "native-identity")
	world.requireCommand(t, nativeTarget, "team", "join", changedToken, "--name", "native-worker")
	nativeStatus := world.requireCommand(t, nativeTarget, "id", "status", "--team", world.TeamID)
	var native identityStatusOutput
	if err := json.Unmarshal([]byte(nativeStatus), &native); err != nil {
		t.Fatal(err)
	}
	if !native.MintComplete || native.Service != world.Stack.ServerURL || native.Alias != "native-worker" {
		t.Fatalf("native join did not complete at its saved service: %s", nativeStatus)
	}
	// A selected fresh home must not read or replace a different checkout's
	// principal while the same real invitation flow creates its recipient.
	checkoutHome := filepath.Join(filepath.Dir(target), ".aw")
	world.requireCommand(t, checkoutHome, "id", "create", "--local")
	checkoutBefore := fileDigestsForTest(t, checkoutHome)
	checkoutKey, err := awid.LoadSigningKey(filepath.Join(checkoutHome, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	neighborTarget := filepath.Join(filepath.Dir(target), "named-with-checkout-principal")
	world.requireCommand(t, neighborTarget, "init", "--join-from", source.Home, "--join-team", world.TeamID, "--name", "neighbor-worker", "--do-not-touch-agents-md")
	neighborJSON := world.requireCommand(t, neighborTarget, "id", "status", "--team", world.TeamID)
	var neighbor identityStatusOutput
	if err := json.Unmarshal([]byte(neighborJSON), &neighbor); err != nil {
		t.Fatal(err)
	}
	if !neighbor.MintComplete || neighbor.Alias != "neighbor-worker" || neighbor.DID == didOf(checkoutKey) {
		t.Fatalf("explicit join used the unrelated checkout principal: %s", neighborJSON)
	}
	checkoutAfter := fileDigestsForTest(t, checkoutHome)
	if len(checkoutAfter) != len(checkoutBefore) {
		t.Fatal("explicit join changed unrelated checkout files")
	}
	for path, digest := range checkoutBefore {
		if checkoutAfter[path] != digest {
			t.Fatalf("explicit join changed unrelated checkout file: %s", path)
		}
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
	t.Setenv("HOME", world.UserHome)
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
	t.Setenv("HOME", world.UserHome)
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
	_, acceptErr := acceptTeamInviteWithDetails(teamInviteAcceptanceRequest{
		WorkingDir: filepath.Dir(child),
		Token:      created.Token,
		Options:    teamAcceptInviteOptions{IdentityHome: child, Name: "recipient", Scope: awid.IdentityModeLocal},
	})
	if acceptErr == nil {
		t.Fatal("accept unexpectedly persisted over the blocked certificate path")
	}
	member, err := world.Registry.ResolveTeamMember(world.Context, world.Stack.RegistryURL, world.Domain, "backend", "recipient", world.TeamKey)
	if err != nil || member.CertificateID == "" {
		t.Fatalf("test did not reach actual membership issuance: %#v; %v", member, err)
	}
	out, err := world.runInIdentityHome(source.Home, "id", "team", "revoke-invite", "--invite-id", created.InviteID)
	var cancellation inviteCancellationOutput
	if err == nil || json.Unmarshal([]byte(out), &cancellation) != nil || cancellation.Code != "invite_already_used" || cancellation.Status != inviteAlreadyUsed {
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
	t.Setenv("HOME", world.UserHome)
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

func TestOATSRealNonHostedRetirementPreservesReleasedNoControllerOutcomes(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	var status identityStatusOutput
	if err := json.Unmarshal([]byte(world.requireCommand(t, member.Home, "id", "status", "--team", world.TeamID)), &status); err != nil {
		t.Fatal(err)
	}
	out, err := world.runInIdentityHome(member.Home, "workspace", "delete", status.WorkspaceID)
	var envelope cliErrorEnvelope
	wantMessage := fmt.Sprintf("refusing aw workspace delete through external identity home for principal %s; only own hosted local self-release is supported for an external identity home (reason: team_not_hosted)", member.Certificate.MemberDIDKey)
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 2 || strings.TrimSpace(strings.TrimPrefix(err.Error(), exit.Error()+": ")) != wantMessage || json.Unmarshal([]byte(out), &envelope) != nil || envelope.Error.Code != "team_not_hosted" || envelope.Error.Message != wantMessage {
		t.Fatalf("released OATS refusal changed: %v\n%s", err, out)
	}
	// The implicit workspace command retains its existing workspace-only delete.
	cmd := exec.CommandContext(world.Context, world.Binary, "--json", "workspace", "delete", status.WorkspaceID)
	cmd.Dir = filepath.Dir(member.Home)
	cmd.Env = append(idCreateCommandEnv(world.UserHome), "AWEB_IDENTITY_HOME=", "AWID_REGISTRY_URL="+world.Stack.RegistryURL, "AW_NO_UPDATE_CHECK=1")
	plain, err := cmd.CombinedOutput()
	var deleted workspaceDeleteOutput
	if err != nil || json.Unmarshal(plain, &deleted) != nil || deleted.WorkspaceID != status.WorkspaceID || !deleted.IdentityDeleted || deleted.AliasReleased || deleted.AliasReleasedReason != "team_not_hosted" || deleted.ReceiptPath != "" {
		t.Fatalf("plain workspace-only delete changed: %v\n%s", err, plain)
	}
	certificate, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil || certificate.Status != "active" {
		t.Fatalf("workspace-only delete touched registry membership: %#v; %v", certificate, err)
	}
}

func TestOATSRealRetirementRequiresPreparedReceiptBeforeDeleting(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	t.Setenv("HOME", world.UserHome)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	var status identityStatusOutput
	if err := json.Unmarshal([]byte(world.requireCommand(t, member.Home, "id", "status", "--team", world.TeamID)), &status); err != nil {
		t.Fatal(err)
	}
	receipt, err := localRetirementReceiptPath(awconfig.IdentityHome{Root: member.Home}, status.WorkspaceID)
	if err != nil {
		t.Fatal(err)
	}
	// A directory at the lock file is a deterministic failure even as root.
	if err := os.MkdirAll(receipt+".lock", 0o700); err != nil {
		t.Fatal(err)
	}
	out, err := world.runInIdentityHome(member.Home, "workspace", "delete", status.WorkspaceID)
	var envelope cliErrorEnvelope
	if err == nil || json.Unmarshal([]byte(out), &envelope) != nil || envelope.Error.Code != "retirement_receipt_unavailable" {
		t.Fatalf("retirement did not refuse before deleting: %v\n%s", err, out)
	}
	world.requireCommand(t, member.Home, "workspace", "status")
	cert, err := world.Registry.GetTeamCertificateStatus(world.Context, world.Stack.RegistryURL, world.Domain, "backend", member.Certificate.CertificateID)
	if err != nil || cert.Status != "active" {
		t.Fatalf("receipt failure changed membership: %#v; %v", cert, err)
	}
	if err := os.Remove(receipt + ".lock"); err != nil {
		t.Fatal(err)
	}
	var retired workspaceDeleteOutput
	if out := world.requireCommand(t, member.Home, "workspace", "delete", status.WorkspaceID); json.Unmarshal([]byte(out), &retired) != nil || retired.RetirementCode != retiredAndRevoked {
		t.Fatalf("repaired receipt destination could not retire: %s", out)
	}
}

func TestOATSRealRetirementResumesOnlyControllerRevocation(t *testing.T) {
	world := newRealCommandWorld(t)
	member := world.addLocalMember(t, "worker")
	t.Setenv("HOME", world.UserHome)
	_, wrongKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(world.Domain, "backend", wrongKey); err != nil {
		t.Fatal(err)
	}
	statusJSON := world.requireCommand(t, member.Home, "id", "status", "--team", world.TeamID)
	var status identityStatusOutput
	if err := json.Unmarshal([]byte(statusJSON), &status); err != nil {
		t.Fatal(err)
	}
	out, err := world.runInIdentityHome(member.Home, "workspace", "delete", status.WorkspaceID)
	if err == nil {
		t.Fatalf("refused controller revocation must be incomplete: %s", out)
	}
	var pending workspaceDeleteOutput
	if err := json.NewDecoder(strings.NewReader(out)).Decode(&pending); err != nil {
		t.Fatalf("pending receipt: %v\n%s", err, out)
	}
	if pending.AliasReleased || pending.RetirementCode != retiredRevocationPending || pending.ReceiptPath == "" || !strings.Contains(pending.NextStep, member.Certificate.CertificateID) {
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
