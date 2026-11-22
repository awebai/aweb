//go:build !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

// Reword only the genuine owner's plan; its filesystem repair is unchanged.
type describedWorkspaceURLFix struct {
	localWorkspaceURLFixHandler
	description string
}

func (fix describedWorkspaceURLFix) Plan(ctx context.Context, selection doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan, err := fix.localWorkspaceURLFixHandler.Plan(ctx, selection, check)
	if err != nil {
		return plan, err
	}
	for index := range plan.PlannedMutations {
		plan.PlannedMutations[index].Description = fix.description
	}
	return plan, nil
}

func TestDoctorFrameworkSafetyDoesNotDependOnDescription(t *testing.T) {
	for _, description := range []string{"Normalize workspace metadata.", "Repair a private key reference in workspace metadata."} {
		t.Run(description, func(t *testing.T) {
			root := t.TempDir()
			path := writeDoctorFixWorkspaceYAML(t, root, "https://app.example.test/mount?token=remove#fragment", "", []awconfig.WorktreeMembership{{TeamID: "team:example.test", Alias: "member", WorkspaceID: "ws-1", CertPath: "team-certs/team__example.test.pem"}})
			handler := describedWorkspaceURLFix{description: description}
			setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{handler.CheckID(): handler})
			check := localPathCheck(handler.CheckID(), doctorStatusWarn, path, "Normalize workspace URL.", "", nil)
			check.Fix = safeDoctorFixInfo(handler.CheckID())
			runner := doctorRunner{workingDir: root, identityHome: filepath.Join(root, ".aw"), opts: doctorRunOptions{Fix: true, FixTarget: handler.CheckID()}}
			runner.output.Checks = []doctorCheck{check}
			runner.runFixFramework()
			requireDoctorFixStatus(t, runner.output, doctorFixStatusApplied)
			workspace, err := loadDoctorWorkspaceFrom(path)
			if err != nil {
				t.Fatal(err)
			}
			if workspace.AwebURL != "https://app.example.test/mount" {
				t.Fatalf("real owner did not sanitize the URL: %q", workspace.AwebURL)
			}
		})
	}
}

type innocentKeyRewriteFix struct{ signingKeyPermissionsFix }

func (fix innocentKeyRewriteFix) Plan(ctx context.Context, selection doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan, err := fix.signingKeyPermissionsFix.Plan(ctx, selection, check)
	if err != nil {
		return plan, err
	}
	plan.PlannedMutations[0].Operation = "write"
	plan.PlannedMutations[0].Description = "Refresh local settings."
	return plan, nil
}

func TestDoctorFrameworkRefusesKeyContentRegardlessOfDescription(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "signing.key")
	before := []byte("preserve these exact key bytes")
	if err := os.WriteFile(path, before, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	handler := innocentKeyRewriteFix{}
	setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{handler.CheckID(): handler})
	check := localPathCheck(handler.CheckID(), doctorStatusWarn, path, "Restrict key permissions.", "", nil)
	check.Fix = safeDoctorFixInfo(handler.CheckID())
	runner := doctorRunner{workingDir: t.TempDir(), identityHome: home, opts: doctorRunOptions{Fix: true, FixTarget: handler.CheckID()}}
	runner.output.Checks = []doctorCheck{check}
	runner.runFixFramework()
	plan := requireDoctorFixStatus(t, runner.output, doctorFixStatusRefused)
	if plan.RefusalDetail != string(doctorFixPrivateKeyMaterial) || plan.NextStep != doctorFixSafetyNextStep {
		t.Fatalf("wrong typed key refusal: %#v", plan)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("refused plan changed the key")
	}
}
