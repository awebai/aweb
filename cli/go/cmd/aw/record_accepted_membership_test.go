package main

import (
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// writeSelfCustodyIdentityForTest lays down a self-custody identity (signing key,
// team certificate, and identity.yaml) for teamID WITHOUT a workspace.yaml, so a
// test can observe whether a finalize step writes the worktree binding. It mirrors
// what an accept/enroll path leaves on disk before recording the membership.
func writeSelfCustodyIdentityForTest(t *testing.T, workingDir, teamID string) (*teamAcceptInviteOutput, *awid.TeamCertificate) {
	t.Helper()
	memberKey := newKey(t)
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate team keypair: %v", err)
	}
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:          teamID,
		MemberDIDKey:  didOf(memberKey),
		Alias:         "bob",
		IdentityScope: awid.IdentityModeLocal,
	})
	if err != nil {
		t.Fatalf("sign team certificate: %v", err)
	}
	return writeSelfCustodyIdentityWithCertificate(t, workingDir, memberKey, cert), cert
}

// writeWorldMemberIdentityForTest is writeSelfCustodyIdentityForTest for a
// member of world's team whose certificate the registry holds.
func writeWorldMemberIdentityForTest(t *testing.T, world *realCommandWorld, workingDir string) (*teamAcceptInviteOutput, *awid.TeamCertificate) {
	t.Helper()
	memberKey := newKey(t)
	cert := world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: didOf(memberKey), Alias: "bob", IdentityScope: awid.IdentityModeLocal})
	return writeSelfCustodyIdentityWithCertificate(t, workingDir, memberKey, cert), cert
}

func writeSelfCustodyIdentityWithCertificate(t *testing.T, workingDir string, memberKey ed25519.PrivateKey, cert *awid.TeamCertificate) *teamAcceptInviteOutput {
	t.Helper()
	teamID := cert.Team
	memberDID := didOf(memberKey)
	certPath, err := awconfig.SaveTeamCertificateForTeam(workingDir, teamID, cert)
	if err != nil {
		t.Fatalf("write team certificate: %v", err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), memberKey); err != nil {
		t.Fatalf("write signing key: %v", err)
	}
	if err := awconfig.SaveWorktreeIdentityTo(
		filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath()),
		&awconfig.WorktreeIdentity{
			DID:           memberDID,
			Custody:       awid.CustodySelf,
			IdentityScope: awid.IdentityModeLocal,
			CreatedAt:     "2026-04-04T00:00:00Z",
		},
	); err != nil {
		t.Fatalf("write worktree identity: %v", err)
	}
	return &teamAcceptInviteOutput{
		Status:   "accepted",
		TeamID:   teamID,
		Alias:    cert.Alias,
		CertPath: certPath,
	}
}

func workspaceYAMLExists(t *testing.T, workingDir string) bool {
	t.Helper()
	_, err := os.Stat(filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath()))
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	t.Fatalf("stat workspace.yaml: %v", err)
	return false
}

func requireEncryptionKeyRecordForTest(t *testing.T, workingDir string) {
	t.Helper()
	state, err := awconfig.LoadEncryptionKeyStateFrom(awconfig.WorktreeEncryptionStatePath(workingDir))
	if err != nil {
		t.Fatalf("load encryption state: %v", err)
	}
	if state.ActiveRecord() == nil {
		t.Fatalf("finalize left no active encryption key: %#v", state)
	}
}

// TestRecordAcceptedTeamMembershipJoinLeavesNoWorkspaceBinding pins the join model
// boundary: recording a membership without the worktree binding still records the
// teams.yaml membership and ensures the encryption key, but MUST NOT write
// workspace.yaml (that is deferred to `aw init`).
func TestRecordAcceptedTeamMembershipJoinLeavesNoWorkspaceBinding(t *testing.T) {
	dir := t.TempDir()
	teamID := "default:gracehosted.aweb.ai"
	output, cert := writeSelfCustodyIdentityForTest(t, dir, teamID)

	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: dir, Output: output, Certificate: cert, RegistryURL: "", AwebURL: "https://app.aweb.ai", IdentityHome: currentEncryptionKeyIdentityHome(), Activation: membershipMakeActive}); err != nil {
		t.Fatalf("record accepted membership: %v", err)
	}

	teamState, err := awconfig.LoadTeamState(dir)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.Membership(teamID) == nil {
		t.Fatalf("join did not record teams.yaml membership: %#v", teamState)
	}
	requireEncryptionKeyRecordForTest(t, dir)
	if workspaceYAMLExists(t, dir) {
		t.Fatal("join must not write workspace.yaml before aw init")
	}
}

// TestRecordAcceptedTeamMembershipProvisionWritesTargetEncryptionKeyNotOperators
// pins the provision model: foreign agent provisioning writes the worktree binding
// and target encryption key without following the operator's active identity home.
func TestRecordAcceptedTeamMembershipProvisionWritesTargetEncryptionKeyNotOperators(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	world := newRealCommandWorld(t)
	awebURL := world.Stack.ServerURL

	dir := filepath.Join(root, "target")
	operatorDir := filepath.Join(root, "operator")
	teamID := world.TeamID
	output, cert := writeWorldMemberIdentityForTest(t, world, dir)
	// The operator never reaches the service; its identity stays local.
	_, _ = writeSelfCustodyIdentityForTest(t, operatorDir, teamID)
	operatorIdentityHome := awconfig.WorktreeIdentityHome(operatorDir)
	t.Setenv(awconfig.IdentityHomeEnv, operatorIdentityHome)
	resolvedHome, err := identityHomeForDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if resolvedHome.Root != operatorIdentityHome || !resolvedHome.External() {
		t.Fatalf("fixture did not activate distinct operator identity home: %+v", resolvedHome)
	}
	targetEncryptionStatePath := awconfig.WorktreeEncryptionStatePath(dir)
	operatorEncryptionStatePath := awconfig.WorktreeEncryptionStatePath(operatorDir)

	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: dir, Output: output, Certificate: cert, RegistryURL: "", AwebURL: awebURL,
		IdentityHome: explicitEncryptionKeyIdentityHome(awconfig.WorktreeIdentityHome(dir)), Activation: membershipMakeActive, Binding: membershipWriteWorkspaceBinding,
	}); err != nil {
		t.Fatalf("record accepted membership: %v", err)
	}

	teamState, err := awconfig.LoadTeamState(dir)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.Membership(teamID) == nil {
		t.Fatalf("provision did not record teams.yaml membership: %#v", teamState)
	}
	targetState, targetStateErr := awconfig.LoadEncryptionKeyStateFrom(targetEncryptionStatePath)
	if targetStateErr != nil || targetState.ActiveRecord() == nil {
		t.Errorf("target E2E encryption key was not created: state=%+v err=%v", targetState, targetStateErr)
	}
	if _, operatorStateErr := os.Stat(operatorEncryptionStatePath); !os.IsNotExist(operatorStateErr) {
		t.Errorf("operator E2E encryption key changed at %s: %v", operatorEncryptionStatePath, operatorStateErr)
	}
	if !workspaceYAMLExists(t, dir) {
		t.Fatal("provision must write workspace.yaml")
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(dir, awconfig.DefaultWorktreeWorkspaceRelativePath()))
	if err != nil {
		t.Fatalf("load workspace binding: %v", err)
	}
	if workspace.AwebURL != awebURL {
		t.Fatalf("workspace aweb_url=%q want the service URL", workspace.AwebURL)
	}
	if workspace.Membership(teamID) == nil {
		t.Fatalf("workspace binding missing membership cache: %#v", workspace)
	}
	membership := teamState.Membership(teamID)
	if membership.AwebURL != awebURL {
		t.Fatalf("teams.yaml membership aweb_url=%q want the service URL", membership.AwebURL)
	}
	// aweb-abfd: provisioning must also publish the target's encryption-key
	// assertion; a key whose assertion is only local cannot be discovered by
	// any counterparty. A teammate's encrypted mail reaches bob only through
	// the published key.
	alice := world.addLocalMember(t, "alice")
	world.requireCommand(t, alice.Home, "mail", "send", "--to", "bob", "--subject", "after-provision", "--body", "sealed for bob")
	if inbox := world.requireCommand(t, awconfig.WorktreeIdentityHome(dir), "mail", "inbox"); !strings.Contains(inbox, "sealed for bob") {
		t.Fatalf("bob cannot read mail sealed to the published key: %s", inbox)
	}
	targetState, targetStateErr = awconfig.LoadEncryptionKeyStateFrom(targetEncryptionStatePath)
	if targetStateErr != nil || targetState.ActiveRecord() == nil {
		t.Fatalf("reload target encryption state: %+v err=%v", targetState, targetStateErr)
	}
	if targetState.ActiveRecord().PublishedAt == "" {
		t.Fatal("publish was not recorded as published_at on the active key record")
	}
}

// TestRecordAcceptedTeamMembershipPreservesJoinedAt pins the re-accept/rotation
// semantics: JoinedAt is the original join time. Recording a membership that
// already exists MUST preserve its JoinedAt rather than overwriting it with the
// (newer) cert.IssuedAt.
func TestRecordAcceptedTeamMembershipPreservesJoinedAt(t *testing.T) {
	dir := t.TempDir()
	teamID := "default:gracehosted.aweb.ai"
	output, cert := writeSelfCustodyIdentityForTest(t, dir, teamID)

	const originalJoinedAt = "2026-01-01T00:00:00Z"
	cert.IssuedAt = originalJoinedAt
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: dir, Output: output, Certificate: cert, RegistryURL: "", AwebURL: "https://app.aweb.ai", IdentityHome: currentEncryptionKeyIdentityHome(), Activation: membershipMakeActive}); err != nil {
		t.Fatalf("record first membership: %v", err)
	}

	// Re-accept with a newer certificate (a later IssuedAt, e.g. a rotation).
	cert.IssuedAt = "2026-06-01T00:00:00Z"
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: dir, Output: output, Certificate: cert, RegistryURL: "", AwebURL: "https://app.aweb.ai", IdentityHome: currentEncryptionKeyIdentityHome(), Activation: membershipMakeActive}); err != nil {
		t.Fatalf("re-record membership: %v", err)
	}

	teamState, err := awconfig.LoadTeamState(dir)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	membership := teamState.Membership(teamID)
	if membership == nil {
		t.Fatalf("re-accept dropped teams.yaml membership: %#v", teamState)
	}
	if membership.JoinedAt != originalJoinedAt {
		t.Fatalf("joined_at=%q want %q (must preserve original join time across re-accept)", membership.JoinedAt, originalJoinedAt)
	}
}

// TestRecordAcceptedTeamMembershipEnsuresEncryptionKeyForCreator is the (a) gap
// characterization: the BYOT creator self-enroll path must end with an encryption
// key so it can do E2E messaging. recordAcceptedTeamMembership guarantees it.
func TestRecordAcceptedTeamMembershipEnsuresEncryptionKeyForCreator(t *testing.T) {
	dir := t.TempDir()
	world := newRealCommandWorld(t)
	output, cert := writeWorldMemberIdentityForTest(t, world, dir)

	if _, err := os.Stat(awconfig.WorktreeEncryptionStatePath(dir)); !os.IsNotExist(err) {
		t.Fatalf("precondition: encryption state should be absent, stat err=%v", err)
	}

	// The real service, never the production URL: with the binding written,
	// the aweb-abfd wiring publishes the encryption-key assertion to it.
	if err := recordAcceptedTeamMembership(acceptedTeamMembershipRequest{WorkingDir: dir, Output: output, Certificate: cert, RegistryURL: "", AwebURL: world.Stack.ServerURL, IdentityHome: currentEncryptionKeyIdentityHome(), Activation: membershipMakeActive, Binding: membershipWriteWorkspaceBinding}); err != nil {
		t.Fatalf("record accepted membership: %v", err)
	}
	requireEncryptionKeyRecordForTest(t, dir)
}
