package main

import (
	"crypto/ed25519"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestWorktreeNativeUnknownIssuanceRetainsItsExactRecipient(t *testing.T) {
	input := newRecoveryWorktree(t)
	registryURL := closedWorktreeEndpoint(t)
	t.Setenv("AWID_REGISTRY_URL", registryURL)
	if err := awconfig.SaveControllerMeta("example.com", &awconfig.ControllerMeta{RegistryURL: registryURL}); err != nil {
		t.Fatal(err)
	}
	_, controller, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "backend", controller); err != nil {
		t.Fatal(err)
	}
	home := awconfig.WorktreeIdentityHome(input.WorktreePath)
	_, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(filepath.Join(home, "signing.key"), key); err != nil {
		t.Fatal(err)
	}
	_, acceptErr := addWorktreeViaLocalTeamKey(input)
	var transport *net.OpError
	if !errors.As(acceptErr, &transport) || errorCodeOf(acceptErr) != "invite_issuance_pending" || !retainUnfinishedProvisioningIdentity(acceptErr) {
		t.Fatalf("worktree did not reach uncertain native issuance: %v", acceptErr)
	}
	retainedKey, err := awid.LoadSigningKey(filepath.Join(home, "signing.key"))
	if err != nil {
		t.Fatalf("uncertain issuance destroyed its original recipient: %v", err)
	}
	if !retainedKey.Equal(key) {
		t.Fatal("worktree recovery replaced the original recipient key")
	}
	requireRegisteredRecoveryWorktree(t, input)
	invitesDir, err := awconfig.DefaultTeamInvitesDir()
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(invitesDir, "*.json"))
	if err != nil || len(files) != 1 {
		t.Fatalf("expected one issuer record, got %d: %v", len(files), err)
	}
	invite, err := awconfig.LoadTeamInvite(strings.TrimSuffix(filepath.Base(files[0]), ".json"))
	if err != nil {
		t.Fatal(err)
	}
	fence, err := awconfig.InspectTeamInviteIssuance(invite)
	if err != nil || fence == nil || fence.State != awconfig.RecoveryAttempted {
		t.Fatalf("worktree lost its attempted fence: %v", err)
	}
	if fence.Context.IdentityHome != home || fence.Context.RegistryURL != registryURL || fence.PreparedEffect.MemberDIDKey != awid.ComputeDIDKey(key.Public().(ed25519.PublicKey)) || fence.PreparedEffect.Alias != input.Alias {
		t.Fatal("worktree fence does not name the retained exact recipient and selected registry")
	}
}

func TestWorktreePreAdmissionRefusalRemovesItsUnusedRecipient(t *testing.T) {
	input := newRecoveryWorktree(t)
	registryURL := closedWorktreeEndpoint(t)
	t.Setenv("AWID_REGISTRY_URL", registryURL)
	if err := awconfig.SaveControllerMeta("example.com", &awconfig.ControllerMeta{RegistryURL: registryURL}); err != nil {
		t.Fatal(err)
	}
	_, err := addWorktreeViaLocalTeamKey(input)
	if err == nil || errorCodeOf(err) != codeControllerKeyMissing || retainUnfinishedProvisioningIdentity(err) {
		t.Fatalf("missing controller was not a safe pre-admission refusal: %v", err)
	}
	if _, err := os.Stat(input.WorktreePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("unused worktree remains after pre-admission refusal: %v", err)
	}
	if workspaceBranchExists(input.RepoRoot, input.BranchName) {
		t.Fatal("unused worktree branch remains after pre-admission refusal")
	}
}

func newRecoveryWorktree(t *testing.T) worktreeAgentCreation {
	t.Helper()
	root := t.TempDir()
	t.Setenv("HOME", root)
	t.Setenv(awconfig.IdentityHomeEnv, "")
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o700); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOriginAndCommit(t, repo, "https://example.invalid/recovery.git")
	child := filepath.Join(root, "recipient")
	created, err := createWorkspaceGitWorktree(repo, child, "recipient", true)
	if err != nil {
		t.Fatal(err)
	}
	return worktreeAgentCreation{WorkingDir: repo, CreatorHome: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(repo)}, WorktreePath: child, RepoRoot: repo, BranchName: "recipient", BranchCreated: created, TeamID: "backend:example.com", Alias: "recipient", ServerURL: "https://service.example.invalid", Workspace: &awconfig.WorktreeWorkspace{}}
}

func closedWorktreeEndpoint(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	url := "http://" + listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return url
}

func requireRegisteredRecoveryWorktree(t *testing.T, input worktreeAgentCreation) {
	t.Helper()
	held, err := workspaceBranchInUse(input.RepoRoot, input.BranchName)
	if err != nil {
		t.Fatal(err)
	}
	if !held {
		t.Fatal("retained recipient lost its registered Git worktree")
	}
}
