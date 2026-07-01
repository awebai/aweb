package main

import (
	"os"
	"path/filepath"
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
	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate member keypair: %v", err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate team keypair: %v", err)
	}
	memberDID := awid.ComputeDIDKey(memberPub)
	cert, err := awid.SignTeamCertificate(teamKey, awid.TeamCertificateFields{
		Team:         teamID,
		MemberDIDKey: memberDID,
		Alias:        "bob",
		Lifetime:     awid.LifetimeEphemeral,
	})
	if err != nil {
		t.Fatalf("sign team certificate: %v", err)
	}
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
			DID:       memberDID,
			Custody:   awid.CustodySelf,
			Lifetime:  awid.LifetimeEphemeral,
			CreatedAt: "2026-04-04T00:00:00Z",
		},
	); err != nil {
		t.Fatalf("write worktree identity: %v", err)
	}
	return &teamAcceptInviteOutput{
		Status:   "accepted",
		TeamID:   teamID,
		Alias:    "bob",
		CertPath: certPath,
	}, cert
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

	if err := recordAcceptedTeamMembership(dir, output, cert, "", "https://app.aweb.ai", recordMembershipOptions{SetActive: true}); err != nil {
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

// TestRecordAcceptedTeamMembershipProvisionWritesWorkspaceBinding pins the
// provision model: agent-provisioning records the membership, writes the worktree
// binding, and ensures the encryption key.
func TestRecordAcceptedTeamMembershipProvisionWritesWorkspaceBinding(t *testing.T) {
	dir := t.TempDir()
	teamID := "default:gracehosted.aweb.ai"
	output, cert := writeSelfCustodyIdentityForTest(t, dir, teamID)

	if err := recordAcceptedTeamMembership(dir, output, cert, "", "https://app.aweb.ai", recordMembershipOptions{SetActive: true, WriteWorkspaceBinding: true}); err != nil {
		t.Fatalf("record accepted membership: %v", err)
	}

	teamState, err := awconfig.LoadTeamState(dir)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if teamState.Membership(teamID) == nil {
		t.Fatalf("provision did not record teams.yaml membership: %#v", teamState)
	}
	requireEncryptionKeyRecordForTest(t, dir)
	if !workspaceYAMLExists(t, dir) {
		t.Fatal("provision must write workspace.yaml")
	}
	workspace, err := awconfig.LoadWorktreeWorkspaceFrom(filepath.Join(dir, awconfig.DefaultWorktreeWorkspaceRelativePath()))
	if err != nil {
		t.Fatalf("load workspace binding: %v", err)
	}
	if workspace.AwebURL != "https://app.aweb.ai" {
		t.Fatalf("workspace aweb_url=%q want https://app.aweb.ai", workspace.AwebURL)
	}
	if workspace.Membership(teamID) == nil {
		t.Fatalf("workspace binding missing membership cache: %#v", workspace)
	}
	membership := teamState.Membership(teamID)
	if membership.AwebURL != "https://app.aweb.ai" {
		t.Fatalf("teams.yaml membership aweb_url=%q want https://app.aweb.ai", membership.AwebURL)
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
	if err := recordAcceptedTeamMembership(dir, output, cert, "", "https://app.aweb.ai", recordMembershipOptions{SetActive: true}); err != nil {
		t.Fatalf("record first membership: %v", err)
	}

	// Re-accept with a newer certificate (a later IssuedAt, e.g. a rotation).
	cert.IssuedAt = "2026-06-01T00:00:00Z"
	if err := recordAcceptedTeamMembership(dir, output, cert, "", "https://app.aweb.ai", recordMembershipOptions{SetActive: true}); err != nil {
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
	teamID := "default:byotcreator.example.com"
	output, cert := writeSelfCustodyIdentityForTest(t, dir, teamID)

	if _, err := os.Stat(awconfig.WorktreeEncryptionStatePath(dir)); !os.IsNotExist(err) {
		t.Fatalf("precondition: encryption state should be absent, stat err=%v", err)
	}

	if err := recordAcceptedTeamMembership(dir, output, cert, "", "https://app.aweb.ai", recordMembershipOptions{SetActive: true, WriteWorkspaceBinding: true}); err != nil {
		t.Fatalf("record accepted membership: %v", err)
	}
	requireEncryptionKeyRecordForTest(t, dir)
}
