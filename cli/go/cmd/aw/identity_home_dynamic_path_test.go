package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestPrincipalRecoveryMarkersRejectSymlinksAtEachUse(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identityHome := filepath.Join(root, "identity")
	if err := os.MkdirAll(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	outsidePartial := filepath.Join(root, "outside-partial.yaml")
	if err := os.WriteFile(outsidePartial, []byte("version: 1\nsigning_key_b64: outside\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	partialLink := filepath.Join(identityHome, "partial-init.yaml")
	if err := os.Symlink(outsidePartial, partialLink); err != nil {
		t.Fatal(err)
	}
	if _, err := loadAPIKeyPartialInit(partialLink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("partial-init read symlink error=%v", err)
	}
	if err := saveAPIKeyPartialInit(root, &apiKeyPartialInitState{Version: 1}, identityHome); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("partial-init write symlink error=%v", err)
	}
	if err := removeAPIKeyPartialInit(root, identityHome); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("partial-init remove symlink error=%v", err)
	}

	outsideMarker := filepath.Join(root, "outside-marker")
	if err := os.WriteFile(outsideMarker, []byte("outside"), 0o600); err != nil {
		t.Fatal(err)
	}
	markerLink := filepath.Join(identityHome, "pending-hosted-accept")
	if err := os.Symlink(outsideMarker, markerLink); err != nil {
		t.Fatal(err)
	}
	if err := statHostedAcceptPendingMarker(markerLink, filepath.Join(identityHome, "signing.key")); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("hosted marker stat symlink error=%v", err)
	}
	if err := writeHostedAcceptPendingMarker(markerLink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("hosted marker write symlink error=%v", err)
	}
	if err := removeHostedAcceptPendingMarker(markerLink); err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("hosted marker remove symlink error=%v", err)
	}
}

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
	state := &pendingRotationState{OperationID: "11111111-1111-4111-8111-111111111111", StableID: "did:aw:stable", PendingKey: "pending.key"}
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
