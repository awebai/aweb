//go:build !windows

package main

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorFrameworkRepairsPrivateKeyModesWithoutChangingBytes(t *testing.T) {
	cases := []struct{ Name, CheckID, RelativePath string }{
		{Name: "selected signing key", CheckID: doctorCheckSigningKeyPermissions, RelativePath: "signing.key"},
		{Name: "additional private key", CheckID: doctorCheckAdditionalKeyPermissions, RelativePath: "encryption-keys/receiver.key"},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			t.Setenv("HOME", t.TempDir())
			home := t.TempDir()
			path := filepath.Join(home, c.RelativePath)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			before := []byte("unchanged secret fixture")
			if err := os.WriteFile(path, before, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0o644); err != nil {
				t.Fatal(err)
			}
			check := localPathCheck(c.CheckID, doctorStatusWarn, path, "Private key mode needs repair.", "", nil)
			check.Fix = safeDoctorFixInfo(c.CheckID)
			runner := doctorRunner{workingDir: t.TempDir(), identityHome: home, opts: doctorRunOptions{Fix: true, DryRun: true, FixTarget: c.CheckID}}
			runner.output.Checks = []doctorCheck{check}
			runner.runFixFramework()
			requireDoctorFixStatus(t, runner.output, doctorFixStatusPlanned)
			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o644 {
				t.Fatal("dry-run changed permissions")
			}
			afterDryRun, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, afterDryRun) {
				t.Fatal("dry-run changed private key bytes")
			}
			runner.opts.DryRun = false
			runner.output.Checks = []doctorCheck{check}
			runner.output.Fixes = nil
			runner.runFixFramework()
			requireDoctorFixStatus(t, runner.output, doctorFixStatusApplied)
			info, err = os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			if info.Mode().Perm() != 0o600 {
				t.Fatal("framework did not apply mode0600")
			}
			after, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(before, after) {
				t.Fatal("framework changed private key bytes")
			}
		})
	}
}

func TestDoctorFrameworkStillRefusesPrivateKeyContentMutations(t *testing.T) {
	cases := []struct{ CheckID, RelativePath string }{
		{doctorCheckSigningKeyPermissions, "signing.key"},
		{doctorCheckAdditionalKeyPermissions, "encryption-keys/receiver.key"},
	}
	for _, c := range cases {
		for _, operation := range []doctorFixOperation{"write", "delete", "replace", doctorFixChmod} {
			t.Run(c.CheckID+"/"+string(operation), func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				home := t.TempDir()
				path := filepath.Join(home, c.RelativePath)
				if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
					t.Fatal(err)
				}
				before := []byte("unchanged secret fixture")
				if err := os.WriteFile(path, before, 0o644); err != nil {
					t.Fatal(err)
				}
				mutation := doctorFixMutation{
					Operation: operation, Path: path, permissionMode: privateKeyPermissionMode,
					Description: "Change private key material",
				}
				if operation == doctorFixChmod {
					mutation.Path = filepath.Join(t.TempDir(), "unselected.key")
				}
				handler := &fakeDoctorFixHandler{
					id: c.CheckID, scopeOwner: doctorFixHandlers[c.CheckID],
					plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{mutation}},
				}
				setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{c.CheckID: handler})
				runner := doctorRunner{
					workingDir:   t.TempDir(),
					identityHome: home,
					opts:         doctorRunOptions{Fix: true, FixTarget: c.CheckID},
				}
				runner.output.Checks = []doctorCheck{advertisedDoctorFixCheck(c.CheckID, true)}
				runner.runFixFramework()
				plan := requireDoctorFixStatus(t, runner.output, doctorFixStatusRefused)
				if plan.NextStep != doctorFixSafetyNextStep {
					t.Fatalf("missing actionable refusal: %q", plan.NextStep)
				}
				if plan.RefusalDetail != string(doctorFixPrivateKeyMaterial) || handler.applyCalled != 0 {
					t.Fatalf("unsafe key mutation admitted: %#v", plan)
				}
				after, err := os.ReadFile(path)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(before, after) {
					t.Fatal("refused plan changed private key bytes")
				}
			})
		}
	}
}

func TestDoctorOwnedKeyPermissionGateRefusesBroaderPlans(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	home := t.TempDir()
	path := filepath.Join(home, "signing.key")
	if err := os.WriteFile(path, []byte("unchanged secret fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx := doctorFixContext{WorkingDir: t.TempDir(), IdentityHome: home}
	check := localPathCheck(doctorCheckSigningKeyPermissions, doctorStatusWarn, path, "Private key mode needs repair.", "", nil)
	check.Fix = safeDoctorFixInfo(check.ID)
	handler := signingKeyPermissionsFix{}
	plan, err := handler.Plan(context.Background(), ctx, check)
	if err != nil {
		t.Fatal(err)
	}
	if reason := validateDoctorFixPlan(ctx, check, plan); reason != "" {
		t.Fatalf("owned repair refused: %s", reason)
	}
	cases := []struct {
		Name     string
		Mutation doctorFixMutation
	}{
		{Name: "content write", Mutation: doctorFixMutation{Operation: "write", Path: path}},
		{Name: "key deletion", Mutation: doctorFixMutation{Operation: "delete", Path: path}},
		{Name: "key replacement", Mutation: doctorFixMutation{Operation: "replace", Path: path}},
		{Name: "open mode", Mutation: doctorFixMutation{Operation: doctorFixChmod, permissionMode: 0o644, Path: path}},
		{Name: "unselected path", Mutation: doctorFixMutation{Operation: doctorFixChmod, permissionMode: privateKeyPermissionMode, Path: filepath.Join(t.TempDir(), "other.key")}},
		{Name: "extra resource", Mutation: doctorFixMutation{Operation: doctorFixChmod, permissionMode: privateKeyPermissionMode, Path: path, Resource: "other"}},
	}
	for _, c := range cases {
		t.Run(c.Name, func(t *testing.T) {
			altered := plan
			altered.PlannedMutations = []doctorFixMutation{c.Mutation}
			if reason := validateDoctorFixPlan(ctx, check, altered); reason != doctorFixPrivateKeyMaterial {
				t.Fatalf("unapproved mutation admitted: %q", reason)
			}
		})
	}
}
