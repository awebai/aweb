package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestExternalIdentityRotationRecoveryPathsFailClosedAtEachUse(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identityHome := filepath.Join(root, "identity")
	outside := filepath.Join(root, "outside")
	if err := os.MkdirAll(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(identityHome, "rotation")); err != nil {
		t.Fatal(err)
	}
	identity := &awconfig.ResolvedIdentity{IdentityHome: identityHome}
	if _, err := rotationStateDirForIdentity(identity); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("rotation directory symlink error=%v", err)
	}
	if err := os.Remove(filepath.Join(identityHome, "rotation")); err != nil {
		t.Fatal(err)
	}
	rotationDir := filepath.Join(identityHome, "rotation")
	if err := os.Mkdir(rotationDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(rotationDir, "pending")); err != nil {
		t.Fatal(err)
	}
	state := &pendingRotationState{StableID: "did:aw:stable", PendingKey: "pending.key"}
	if err := savePendingRotationState(rotationDir, state); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("pending-state write symlink error=%v", err)
	}
	if _, err := loadPendingRotationState(rotationDir, state.StableID); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("pending-state read symlink error=%v", err)
	}
}

func TestExternalIdentityEncryptionPathsFailClosedAtEachUse(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identityHome := filepath.Join(root, "identity")
	keyDir := filepath.Join(identityHome, "encryption-keys")
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside")
	if err := os.WriteFile(outside, []byte("not identity material"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, privatePath := range []string{"../escape.key", "/absolute/key", "encryption-keys\\..\\escape.key"} {
		_, err := validateEncryptionRecordPrivateKeyAt(root, identityHome, &awconfig.EncryptionKeyRecord{PrivateKeyPath: privatePath})
		if err == nil {
			t.Fatalf("private-key path %q accepted", privatePath)
		}
	}
	for _, assertionPath := range []string{"../escape.json", "/absolute/assertion", "encryption-keys\\..\\escape.json"} {
		_, err := loadEncryptionAssertionAt(root, identityHome, assertionPath)
		if err == nil {
			t.Fatalf("assertion path %q accepted", assertionPath)
		}
	}

	privateLink := filepath.Join(keyDir, "linked.x25519.key")
	assertionLink := filepath.Join(keyDir, "linked.assertion.json")
	if err := os.Symlink(outside, privateLink); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, assertionLink); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEncryptionRecordPrivateKeyAt(root, identityHome, &awconfig.EncryptionKeyRecord{PrivateKeyPath: "encryption-keys/linked.x25519.key"}); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("private-key symlink error=%v", err)
	}
	if _, err := loadEncryptionAssertionAt(root, identityHome, "encryption-keys/linked.assertion.json"); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("assertion symlink error=%v", err)
	}
}
