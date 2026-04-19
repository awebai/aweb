package main

import (
	"context"
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

type doctorFixMutation struct {
	Operation     string        `json:"operation"`
	Description   string        `json:"description,omitempty"`
	Target        *doctorTarget `json:"target,omitempty"`
	Path          string        `json:"path,omitempty"`
	Resource      string        `json:"resource,omitempty"`
	SourceOfTruth string        `json:"source_of_truth,omitempty"`
}

type doctorFixPrecondition struct {
	ID     string         `json:"id"`
	Passed bool           `json:"passed"`
	Detail map[string]any `json:"detail,omitempty"`
}

type doctorFixContext struct {
	WorkingDir string
	Mode       doctorMode
	DryRun     bool
	FixTarget  string
}

type doctorFixHandler interface {
	CheckID() string
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
		WorkingDir: r.workingDir,
		Mode:       r.opts.Mode,
		DryRun:     r.opts.DryRun,
		FixTarget:  target,
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
	if detail := validateDoctorFixPlan(check, plan); detail != "" {
		r.addFixPlan(refusedDoctorFixPlan(check.ID, &check, "safety_refused", detail, "Common doctor fix safety gates refused this plan."))
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

func validateDoctorFixPlan(check doctorCheck, plan doctorFixPlan) string {
	switch {
	case check.Fix == nil || !check.Fix.Available:
		return "fix_not_advertised"
	case !check.Fix.Safe:
		return "unsafe"
	case !plan.Safe:
		return "unsafe"
	case plan.HighImpact:
		return "high_impact"
	case plan.Authority != "" && plan.Authority != doctorAuthorityCaller:
		return "authority"
	}
	for _, precondition := range plan.Preconditions {
		if !precondition.Passed {
			return "precondition"
		}
	}
	for _, mutation := range plan.PlannedMutations {
		if reason := prohibitedDoctorFixMutation(mutation); reason != "" {
			return reason
		}
	}
	return ""
}

func prohibitedDoctorFixMutation(mutation doctorFixMutation) string {
	text := strings.ToLower(strings.Join([]string{
		mutation.Operation,
		mutation.Description,
		mutation.Path,
		mutation.Resource,
		targetText(mutation.Target),
	}, " "))
	normalized := strings.NewReplacer("_", " ", "-", " ", "\\", "/", ".", " ").Replace(text)
	switch {
	case hasDoctorFixTerm(text, ".aw/signing.key", "signing.key") || hasDoctorFixTerm(normalized, "signing key", "private key", "private key material"):
		return "private_key_material"
	case strings.Contains(normalized, "unclaim") || (strings.Contains(normalized, "presence") && hasDoctorFixTerm(normalized, "cleanup", "clear", "delete")):
		return "coordination_cleanup"
	case doctorFixLifecycleMutation(text, normalized):
		return "persistent_identity_lifecycle"
	default:
		return ""
	}
}

func doctorFixLifecycleMutation(text, normalized string) bool {
	if !hasDoctorFixTerm(normalized, "delete", "archive", "replace", "retire", "lifecycle", "reassign") {
		return false
	}
	return strings.Contains(text, "did:aw:") ||
		strings.Contains(normalized, "did aw") ||
		strings.Contains(normalized, "identity") ||
		strings.Contains(normalized, "address")
}

func hasDoctorFixTerm(text string, terms ...string) bool {
	for _, term := range terms {
		if strings.Contains(text, term) {
			return true
		}
	}
	return false
}

func targetText(target *doctorTarget) string {
	if target == nil {
		return ""
	}
	return strings.Join([]string{target.Type, target.ID, target.Display}, " ")
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
