package main

import (
	"context"
	"log"
	"os"
	"strings"
)

type doctorFixStatus string

const (
	doctorFixStatusPlanned doctorFixStatus = "planned"
	doctorFixStatusApplied doctorFixStatus = "applied"
	doctorFixStatusRefused doctorFixStatus = "refused"
	doctorFixStatusNoop    doctorFixStatus = "noop"
	doctorFixStatusFailed  doctorFixStatus = "failed"
)

type doctorFixPlan struct {
	PlanID           string                  `json:"plan_id"`
	CheckID          string                  `json:"check_id"`
	Status           doctorFixStatus         `json:"status"`
	Source           doctorSource            `json:"source"`
	Authority        doctorAuthority         `json:"authority"`
	Target           *doctorTarget           `json:"target,omitempty"`
	Safe             bool                    `json:"safe"`
	HighImpact       bool                    `json:"high_impact"`
	DryRun           bool                    `json:"dry_run"`
	PlannedMutations []doctorFixMutation     `json:"planned_mutations,omitempty"`
	Preconditions    []doctorFixPrecondition `json:"preconditions,omitempty"`
	RefusalReason    string                  `json:"refusal_reason,omitempty"`
	RefusalDetail    string                  `json:"refusal_detail,omitempty"`
	RollbackGuidance string                  `json:"rollback_guidance,omitempty"`
	NextStep         string                  `json:"next_step,omitempty"`
}

type doctorFixOperation string

const (
	doctorFixChmod                    doctorFixOperation = "chmod"
	doctorFixRewriteTeamsMetadata     doctorFixOperation = "rewrite_teams_metadata"
	doctorFixRewriteWorkspaceMetadata doctorFixOperation = "rewrite_workspace_metadata"
	doctorFixRewriteIdentityMetadata  doctorFixOperation = "rewrite_identity_metadata"
)

type doctorFixSafetyReason string

const (
	doctorFixUnsafe             doctorFixSafetyReason = "unsafe"
	doctorFixAuthority          doctorFixSafetyReason = "authority"
	doctorFixReasonPrecondition doctorFixSafetyReason = "precondition"
	doctorFixNotAdvertised      doctorFixSafetyReason = "fix_not_advertised"
	doctorFixHighImpact         doctorFixSafetyReason = "high_impact"
	doctorFixPrivateKeyMaterial doctorFixSafetyReason = "private_key_material"
)

type doctorFixMetadataField string

const (
	doctorFixActiveTeamField  doctorFixMetadataField = "active_team"
	doctorFixAwebURLField     doctorFixMetadataField = "aweb_url"
	doctorFixRegistryURLField doctorFixMetadataField = "registry_url"
)

const doctorFixSafetyNextStep = "Run aw doctor without --fix to inspect this check, then follow its next step."

type doctorFixMutation struct {
	// permissionMode is an internal constraint for mode-only repairs. Doctor
	// exports a description; serialized plans are not an execution capability.
	permissionMode os.FileMode
	Operation      doctorFixOperation     `json:"operation"`
	Description    string                 `json:"description,omitempty"`
	Target         *doctorTarget          `json:"target,omitempty"`
	Path           string                 `json:"path,omitempty"`
	Resource       doctorFixMetadataField `json:"resource,omitempty"`
	SourceOfTruth  string                 `json:"source_of_truth,omitempty"`
}

type doctorFixPrecondition struct {
	ID     string `json:"id"`
	Passed bool   `json:"passed"`
	// Detail is available in ordinary doctor output, but is omitted from
	// shareable support bundles because its dynamic keys cannot be allowlisted.
	Detail map[string]any `json:"detail,omitempty"`
}

type doctorFixContext struct {
	WorkingDir   string
	IdentityHome string
	Mode         doctorMode
	DryRun       bool
	FixTarget    string
}

type doctorFixHandler interface {
	CheckID() string
	// Every registered repair names its allowed local effects independently
	// of the user-facing plan (docs/signature-primitives.md).
	doctorMutationScope(doctorFixContext) (doctorMutationScope, error)
	Plan(context.Context, doctorFixContext, doctorCheck) (doctorFixPlan, error)
	Apply(context.Context, doctorFixContext, doctorFixPlan) (doctorFixPlan, error)
}

var doctorFixHandlers = map[string]doctorFixHandler{}

func (r *doctorRunner) runFixFramework() {
	target := strings.TrimSpace(r.opts.FixTarget)
	checks := r.fixTargetChecks(target)
	if target != "" && len(checks) == 0 {
		r.addFixPlan(refusedDoctorFixPlan(target, nil, "target_not_found", "", "No emitted doctor check matched the requested --fix target."))
		return
	}
	if len(checks) == 0 {
		r.addFixPlan(refusedDoctorFixPlan("all", nil, "fix_not_advertised", "", "No emitted doctor checks advertised an available safe fix."))
		return
	}
	ctx := doctorFixContext{
		WorkingDir:   r.workingDir,
		IdentityHome: r.identityHome,
		Mode:         r.opts.Mode,
		DryRun:       r.opts.DryRun,
		FixTarget:    target,
	}
	for _, check := range checks {
		r.runFixForCheck(ctx, check)
	}
}

func (r *doctorRunner) fixTargetChecks(target string) []doctorCheck {
	if target != "" {
		for _, check := range r.output.Checks {
			if check.ID == target {
				return []doctorCheck{check}
			}
		}
		return nil
	}
	var checks []doctorCheck
	for _, check := range r.output.Checks {
		if check.Fix != nil && check.Fix.Available {
			checks = append(checks, check)
		}
	}
	return checks
}

func (r *doctorRunner) runFixForCheck(ctx doctorFixContext, check doctorCheck) {
	if check.Fix == nil || !check.Fix.Available {
		r.addFixPlan(refusedDoctorFixPlan(check.ID, &check, "fix_not_advertised", "", "This check does not advertise an available doctor fix."))
		return
	}
	handler, ok := doctorFixHandlers[check.ID]
	if !ok || handler == nil {
		r.addFixPlan(refusedDoctorFixPlan(check.ID, &check, "no_fix_registered", "", "This check advertises a fix, but no fix handler is registered in this build."))
		return
	}
	plan, err := handler.Plan(context.Background(), ctx, check)
	if err != nil {
		r.addFixPlan(refusedDoctorFixPlan(check.ID, &check, "safety_refused", "precondition", "Fix planning failed; no mutation was attempted."))
		return
	}
	plan = normalizeDoctorFixPlan(plan, check, ctx)
	if plan.Status == doctorFixStatusRefused {
		r.addFixPlan(plan)
		return
	}
	if detail := validateDoctorFixPlan(ctx, check, plan); detail != "" {
		r.addFixPlan(refusedDoctorFixPlan(check.ID, &check, "safety_refused", string(detail), doctorFixSafetyNextStep))
		return
	}
	if ctx.DryRun {
		plan.Status = doctorFixStatusPlanned
		plan.DryRun = true
		r.addFixPlan(plan)
		return
	}
	applied, err := handler.Apply(context.Background(), ctx, plan)
	if err != nil {
		plan.Status = doctorFixStatusFailed
		plan.RefusalReason = "apply_failed"
		plan.RefusalDetail = "precondition"
		plan.NextStep = "Fix apply failed; inspect local state or rerun doctor."
		r.addFixPlan(plan)
		return
	}
	applied = normalizeDoctorFixPlan(applied, check, ctx)
	if applied.Status == "" || applied.Status == doctorFixStatusPlanned {
		applied.Status = doctorFixStatusApplied
	}
	r.addFixPlan(applied)
}

func normalizeDoctorFixPlan(plan doctorFixPlan, check doctorCheck, ctx doctorFixContext) doctorFixPlan {
	if strings.TrimSpace(plan.CheckID) == "" {
		plan.CheckID = check.ID
	}
	if strings.TrimSpace(plan.PlanID) == "" {
		plan.PlanID = "fix:" + plan.CheckID
	}
	if plan.Source == "" {
		plan.Source = check.Source
	}
	if plan.Authority == "" {
		plan.Authority = check.Authority
	}
	if plan.Target == nil {
		plan.Target = check.Target
	}
	plan.DryRun = ctx.DryRun
	return plan
}

func validateDoctorFixPlan(ctx doctorFixContext, check doctorCheck, plan doctorFixPlan) doctorFixSafetyReason {
	switch {
	case check.Fix == nil || !check.Fix.Available:
		return doctorFixNotAdvertised
	case !check.Fix.Safe:
		return doctorFixUnsafe
	case !plan.Safe:
		return doctorFixUnsafe
	case plan.HighImpact:
		return doctorFixHighImpact
	case plan.Authority != "" && plan.Authority != doctorAuthorityCaller:
		return doctorFixAuthority
	}
	for _, precondition := range plan.Preconditions {
		if !precondition.Passed {
			return doctorFixReasonPrecondition
		}
	}
	handler, registered := doctorFixHandlers[check.ID]
	if !registered || handler == nil || handler.CheckID() != check.ID || plan.CheckID != check.ID || plan.Source != check.Source {
		return doctorFixAuthority
	}
	scope, err := handler.doctorMutationScope(ctx)
	if err != nil {
		log.Printf("aw doctor: cannot inspect the registered repair scope: %v. Inspect the selected local state and retry.", err)
		return doctorFixReasonPrecondition
	}
	if scope.CheckID != check.ID || check.Source != doctorSourceLocal {
		return doctorFixAuthority
	}
	for _, mutation := range plan.PlannedMutations {
		if !scope.permits(mutation) {
			return scope.Refusal
		}
	}
	return ""
}

func refusedDoctorFixPlan(checkID string, check *doctorCheck, reason, detail, message string) doctorFixPlan {
	plan := doctorFixPlan{
		PlanID:        "fix:" + strings.TrimSpace(checkID),
		CheckID:       strings.TrimSpace(checkID),
		Status:        doctorFixStatusRefused,
		Source:        doctorSourceLocal,
		Authority:     doctorAuthorityCaller,
		Safe:          false,
		HighImpact:    false,
		RefusalReason: reason,
		RefusalDetail: detail,
		NextStep:      message,
	}
	if check != nil {
		plan.Source = check.Source
		plan.Authority = check.Authority
		plan.Target = check.Target
	}
	return plan
}

func (r *doctorRunner) addFixPlan(plan doctorFixPlan) {
	plan.DryRun = r.opts.DryRun
	r.output.Fixes = append(r.output.Fixes, plan)
	status := doctorStatusInfo
	message := "Doctor fix plan is available."
	checkID := "doctor.fix.planned"
	switch plan.Status {
	case doctorFixStatusRefused:
		status = doctorStatusBlocked
		checkID = "doctor.fix." + strings.TrimSpace(plan.RefusalReason)
		message = "Doctor fix was refused."
	case doctorFixStatusApplied, doctorFixStatusNoop:
		status = doctorStatusOK
		checkID = "doctor.fix." + string(plan.Status)
		message = "Doctor fix completed."
	case doctorFixStatusFailed:
		status = doctorStatusFail
		checkID = "doctor.fix.failed"
		message = "Doctor fix failed."
	case doctorFixStatusPlanned:
		checkID = "doctor.fix.planned"
	}
	if checkID == "doctor.fix." {
		checkID = "doctor.fix.safety_refused"
	}
	detail := map[string]any{
		"check_id": plan.CheckID,
		"plan_id":  plan.PlanID,
		"dry_run":  plan.DryRun,
	}
	if plan.RefusalReason != "" {
		detail["reason"] = plan.RefusalReason
	}
	if plan.RefusalDetail != "" {
		detail["safety_reason"] = plan.RefusalDetail
	}
	r.add(doctorCheck{
		ID:            checkID,
		Status:        status,
		Source:        doctorSourceLocal,
		Authority:     doctorAuthorityCaller,
		Target:        plan.Target,
		Authoritative: true,
		Message:       message,
		Detail:        detail,
		NextStep:      plan.NextStep,
		Fix: &doctorFixInfo{
			Available: plan.Status != doctorFixStatusRefused,
			Safe:      plan.Safe,
			DryRun:    plan.DryRun,
			Reason:    plan.RefusalReason,
		},
	})
}
