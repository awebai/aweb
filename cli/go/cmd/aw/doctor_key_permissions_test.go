//go:build !windows

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestDoctorSigningKeyPermissionFixPreservesKey(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "signing.key")
	if err := awid.SaveSigningKey(path, ed25519.NewKeyFromSeed(make([]byte, 32))); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	handler := signingKeyPermissionsFix{}
	ctx := doctorFixContext{IdentityHome: home}
	check := localPathCheck(doctorCheckSigningKeyPermissions, doctorStatusWarn, path, "Signing key is readable by group or others.", "", nil)
	plan, err := handler.Plan(context.Background(), ctx, check)
	if err != nil {
		t.Fatal(err)
	}
	if plan.Status != doctorFixStatusPlanned || len(plan.PlannedMutations) != 1 {
		t.Fatalf("plan: %#v", plan)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatal("planning changed permissions")
	}
	applied, err := handler.Apply(context.Background(), ctx, plan)
	if err != nil || applied.Status != doctorFixStatusApplied {
		t.Fatalf("apply: %#v %v", applied, err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("fix changed key bytes")
	}
	info, err = os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatal("fix left key permissions open")
	}
}

func TestDoctorSigningKeyFixRefusesAChangedSelection(t *testing.T) {
	selected, other := t.TempDir(), t.TempDir()
	for _, home := range []string{selected, other} {
		if err := os.WriteFile(filepath.Join(home, "signing.key"), []byte("metadata only"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	fix := signingKeyPermissionsFix{}
	plan, err := fix.Plan(context.Background(), doctorFixContext{IdentityHome: selected}, doctorCheck{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fix.Apply(context.Background(), doctorFixContext{IdentityHome: other}, plan)
	if err == nil || !strings.Contains(err.Error(), "rerun doctor and review a new fix plan") {
		t.Fatalf("changed selection accepted: %v", err)
	}
	info, err := os.Stat(filepath.Join(other, "signing.key"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatal("changed selection was mutated")
	}
}
