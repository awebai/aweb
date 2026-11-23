package main

import (
	"context"
	"fmt"

	"github.com/awebai/aw/awid"
)

type signingKeyPermissionsFix struct{}

func init()                                      { registerDoctorFixHandler(signingKeyPermissionsFix{}) }
func (signingKeyPermissionsFix) CheckID() string { return doctorCheckSigningKeyPermissions }
func (signingKeyPermissionsFix) Plan(_ context.Context, ctx doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan := localFixBasePlan(check)
	path := doctorFixIdentityPath(ctx, "signing.key")
	command, err := awid.PrivateKeyPermissionFix(path)
	if err != nil {
		return plan, fmt.Errorf("inspect signing key permissions; restore a readable key before applying this fix: %w", err)
	}
	if command == "" {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	plan.PlannedMutations = []doctorFixMutation{{Operation: doctorFixChmod, permissionMode: privateKeyPermissionMode, Path: path, Description: "Restrict signing key permissions to 0600 without changing its bytes."}}
	return plan, nil
}
func (signingKeyPermissionsFix) Apply(_ context.Context, ctx doctorFixContext, plan doctorFixPlan) (doctorFixPlan, error) {
	if len(plan.PlannedMutations) == 0 {
		return plan, nil
	}
	path := doctorFixIdentityPath(ctx, "signing.key")
	if len(plan.PlannedMutations) != 1 || plan.PlannedMutations[0].Path != path {
		return plan, fmt.Errorf("selected signing key changed; rerun doctor and review a new fix plan")
	}
	if err := awid.FixPrivateKeyPermissions(path); err != nil {
		return plan, fmt.Errorf("restrict signing key permissions; run chmod 600 on the selected signing.key if the mounted secret permits it: %w", err)
	}
	plan.Status = doctorFixStatusApplied
	return plan, nil
}
