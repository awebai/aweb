//go:build !windows

package main

import (
	"context"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestDoctorPrivateRootReportsWithoutChangingExistingParent(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	workspace := t.TempDir()
	root := filepath.Join(workspace, ".aw")
	if err := os.Mkdir(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o755); err != nil {
		t.Fatal(err)
	}
	runner := doctorRunner{workingDir: workspace, identityHome: root}
	runner.runPrivateRootPermissionsChecks()
	var found *doctorCheck
	for i := range runner.output.Checks {
		check := &runner.output.Checks[i]
		if check.ID == "local.private_directory.workspace" {
			found = check
		}
	}
	if found == nil || found.Status != doctorStatusWarn {
		t.Fatalf("missing directory warning: %#v", runner.output.Checks)
	}
	command, err := awid.PermissionFixCommand(root, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if found.NextStep != "Run "+command+"." {
		t.Fatalf("actionable repair: %q", found.NextStep)
	}
	info, err := os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatal("diagnosis changed directory permissions")
	}
	fix := privateRootPermissionsFix{Root: privateRootCheck{ID: found.ID, Kind: workspacePrivateRoot}}
	ctx := doctorFixContext{WorkingDir: workspace, IdentityHome: root}
	plan, err := fix.Plan(context.Background(), ctx, *found)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := fix.Apply(context.Background(), ctx, plan)
	if err != nil || applied.Status != doctorFixStatusApplied {
		t.Fatalf("fix: %#v %v", applied, err)
	}
	info, err = os.Stat(root)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Fatal("requested fix did not restrict the named root")
	}
}

func TestDoctorFindsAndFixesOtherPrivateKeysInNamedRoots(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	workspace := t.TempDir()
	root := filepath.Join(workspace, ".aw")
	paths := []string{filepath.Join(root, "encryption-keys", "key.key"), filepath.Join(home, ".awid", "controllers", "team.key")}
	key := ed25519.NewKeyFromSeed(make([]byte, 32))
	for _, path := range paths {
		if err := awid.SaveSigningKey(path, key); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := doctorFixContext{WorkingDir: workspace, IdentityHome: root}
	findings, err := additionalPrivateKeyPermissionFindings(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != len(paths) {
		t.Fatalf("findings: %#v", findings)
	}
	runner := doctorRunner{workingDir: workspace, identityHome: root}
	runner.runAdditionalPrivateKeyPermissionsChecks()
	if len(runner.output.Checks) != 1 {
		t.Fatalf("checks: %#v", runner.output.Checks)
	}
	for _, finding := range findings {
		if !strings.Contains(runner.output.Checks[0].NextStep, finding.Command) {
			t.Fatal("missing exact chmod action")
		}
	}
	fix := additionalPrivateKeyPermissionsFix{}
	plan, err := fix.Plan(context.Background(), ctx, runner.output.Checks[0])
	if err != nil {
		t.Fatal(err)
	}
	applied, err := fix.Apply(context.Background(), ctx, plan)
	if err != nil || applied.Status != doctorFixStatusApplied {
		t.Fatalf("fix: %#v %v", applied, err)
	}
	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("mode left open: %s", path)
		}
		loaded, err := awid.LoadSigningKey(path)
		if err != nil || !loaded.Equal(key) {
			t.Fatalf("key changed: %s %v", path, err)
		}
	}
}

func TestDoctorDirectoryFixRefusesAChangedSelection(t *testing.T) {
	selected := t.TempDir()
	other := t.TempDir()
	if err := os.Chmod(selected, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(other, 0o755); err != nil {
		t.Fatal(err)
	}
	fix := privateRootPermissionsFix{Root: privateRootCheck{ID: "local.private_directory.identity_home", Kind: selectedIdentityPrivateRoot}}
	plan, err := fix.Plan(context.Background(), doctorFixContext{IdentityHome: selected}, doctorCheck{})
	if err != nil {
		t.Fatal(err)
	}
	_, err = fix.Apply(context.Background(), doctorFixContext{IdentityHome: other}, plan)
	if err == nil || !strings.Contains(err.Error(), "rerun doctor and review a new fix plan") {
		t.Fatalf("changed selection accepted: %v", err)
	}
	info, err := os.Stat(other)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatal("changed selection was mutated")
	}
}

func TestDoctorAdditionalKeyFixDoesNotExpandItsPlan(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	first := filepath.Join(root, "first.key")
	later := filepath.Join(root, "later.key")
	if err := os.WriteFile(first, []byte("metadata only"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := doctorFixContext{WorkingDir: t.TempDir(), IdentityHome: root}
	fix := additionalPrivateKeyPermissionsFix{}
	plan, err := fix.Plan(context.Background(), ctx, doctorCheck{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(later, []byte("metadata only"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := fix.Apply(context.Background(), ctx, plan); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(later)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatal("newly discovered key outside the plan was mutated")
	}
}
