package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestLocalProvisionEnrollmentUsesExplicitIdentityHome(t *testing.T) {
	root := t.TempDir()
	t.Setenv("HOME", root)
	workingDir := filepath.Join(root, "instance")
	identityHome := filepath.Join(root, "principal")
	if err := os.MkdirAll(filepath.Join(workingDir, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, ".gitignore"), []byte(".aw/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	initGitRepoWithOrigin(t, workingDir, "https://example.com/repo.git")

	_, shadowKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	shadowKeyPath := filepath.Join(workingDir, ".aw", "signing.key")
	if err := awid.SaveSigningKey(shadowKeyPath, shadowKey); err != nil {
		t.Fatal(err)
	}
	shadowBefore, err := os.ReadFile(shadowKeyPath)
	if err != nil {
		t.Fatal(err)
	}

	plan, err := resolveTeamMemberEnrollment(context.Background(), teamMemberEnrollmentResolveOptions{
		WorkingDir:     workingDir,
		IdentityHome:   identityHome,
		TeamDomain:     "acme.test",
		Name:           "provisioned",
		Scope:          awid.IdentityModeLocal,
		AllowLocalMint: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	principalKey, err := awid.LoadSigningKey(filepath.Join(identityHome, "signing.key"))
	if err != nil {
		t.Fatalf("load explicit principal key: %v", err)
	}
	principalDID := awid.ComputeDIDKey(principalKey.Public().(ed25519.PublicKey))
	if plan.MemberDIDKey != principalDID {
		t.Fatalf("member_did_key=%q want explicit principal %q", plan.MemberDIDKey, principalDID)
	}
	if plan.MemberDIDKey == awid.ComputeDIDKey(shadowKey.Public().(ed25519.PublicKey)) {
		t.Fatal("local provision selected the cwd shadow key")
	}
	shadowAfter, err := os.ReadFile(shadowKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shadowBefore, shadowAfter) {
		t.Fatal("local provision mutated the cwd shadow key")
	}
}
