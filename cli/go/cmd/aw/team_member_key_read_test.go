package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestLocalMemberEnrollmentKeepsAKeyReadFailureDistinctFromAbsence(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "member-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(home, "signing.key")
	invalid := []byte("invalid signing key\n")
	if err := os.WriteFile(path, invalid, 0o600); err != nil {
		t.Fatal(err)
	}
	request := teamMemberEnrollmentResolveOptions{WorkingDir: dir, IdentityHome: home, Name: "recipient", Scope: awid.IdentityModeLocal, AllowLocalMint: true}
	_, err := resolveTeamMemberEnrollment(context.Background(), request)
	if err == nil || !strings.Contains(err.Error(), "read selected member signing key") || !strings.HasSuffix(err.Error(), "restore its original signing.key and retry") {
		t.Fatalf("key read failure became a fresh mint or lost its repair action: %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, invalid) {
		t.Fatalf("failed read changed the selected key: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("failed read installed an identity: %v", err)
	}
	public, private, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(path, private); err != nil {
		t.Fatal(err)
	}
	plan, err := resolveTeamMemberEnrollment(context.Background(), request)
	if err != nil || plan.MemberDIDKey != awid.ComputeDIDKey(public) {
		t.Fatalf("valid existing key cannot enroll: %v", err)
	}
	stored, err := awid.LoadSigningKey(path)
	if err != nil || !bytes.Equal(stored, private) {
		t.Fatalf("enrollment replaced the existing key: %v", err)
	}
	if _, err := awconfig.LoadTeamStateFromIdentityHome(home); !os.IsNotExist(err) {
		t.Fatalf("planning unexpectedly installed membership: %v", err)
	}
}
