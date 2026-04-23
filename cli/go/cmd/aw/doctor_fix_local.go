package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
)

const (
	localFixReasonAmbiguousState = "ambiguous_state"
	localFixReasonStateChanged   = "state_changed"

	localFixPreconditionWorkspaceYAMLUnchanged = "workspace_yaml_unchanged"
	localFixPreconditionIdentityYAMLUnchanged  = "identity_yaml_unchanged"
	localFixPreconditionSingleMembership       = "single_unambiguous_membership"
	localFixPreconditionSanitizedURLValid      = "sanitized_url_valid"
	localFixPreconditionRegistryURLOnly        = "registry_url_only"
)

type doctorLocalURLNormalization struct {
	URL             string
	RemovedUserinfo bool
	RemovedQuery    bool
	RemovedFragment bool
}

func init() {
	registerDoctorFixHandler(localActiveTeamFixHandler{checkID: doctorCheckTeamsActiveTeam})
	registerDoctorFixHandler(localActiveTeamFixHandler{checkID: doctorCheckWorkspaceMembership})
	registerDoctorFixHandler(localWorkspaceURLFixHandler{})
	registerDoctorFixHandler(localIdentityRegistryURLFixHandler{})
}

func registerDoctorFixHandler(handler doctorFixHandler) {
	if handler == nil || strings.TrimSpace(handler.CheckID()) == "" {
		return
	}
	doctorFixHandlers[handler.CheckID()] = handler
}

func safeDoctorFixInfo(checkID string) *doctorFixInfo {
	return &doctorFixInfo{
		Available: true,
		Safe:      true,
		Command:   "aw doctor --fix --dry-run " + strings.TrimSpace(checkID),
		DryRun:    true,
	}
}

func normalizeLocalURLForDoctor(raw string) (doctorLocalURLNormalization, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return doctorLocalURLNormalization{}, errors.New("empty URL")
	}
	parsed, err := url.Parse(raw)
	if err != nil {
		return doctorLocalURLNormalization{}, errors.New("invalid URL syntax")
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return doctorLocalURLNormalization{}, errors.New("URL must include scheme and host")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return doctorLocalURLNormalization{}, errors.New("URL must use http or https")
	}
	out := doctorLocalURLNormalization{
		RemovedUserinfo: parsed.User != nil,
		RemovedQuery:    parsed.RawQuery != "",
		RemovedFragment: parsed.Fragment != "",
	}
	parsed.User = nil
	parsed.RawQuery = ""
	parsed.Fragment = ""
	out.URL = parsed.String()
	return out, nil
}

func (n doctorLocalURLNormalization) needsRewrite() bool {
	return n.RemovedUserinfo || n.RemovedQuery || n.RemovedFragment
}

func doctorURLDetail(urlKey string, n doctorLocalURLNormalization) map[string]any {
	detail := map[string]any{urlKey: n.URL}
	if n.needsRewrite() {
		detail["removed_userinfo"] = n.RemovedUserinfo
		detail["removed_query"] = n.RemovedQuery
		detail["removed_fragment"] = n.RemovedFragment
	}
	return detail
}

type localFileSnapshot struct {
	Digest      string
	Size        int64
	ModUnixNano int64
}

func snapshotLocalFile(path string) (localFileSnapshot, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return localFileSnapshot{}, err
	}
	stat, err := os.Stat(path)
	if err != nil {
		return localFileSnapshot{}, err
	}
	sum := sha256.Sum256(data)
	return localFileSnapshot{
		Digest:      fmt.Sprintf("sha256:%x", sum[:]),
		Size:        stat.Size(),
		ModUnixNano: stat.ModTime().UnixNano(),
	}, nil
}

func (s localFileSnapshot) detail() map[string]any {
	return map[string]any{
		"file_digest":     s.Digest,
		"size_bytes":      s.Size,
		"mtime_unix_nano": s.ModUnixNano,
	}
}

func snapshotFromPrecondition(plan doctorFixPlan, id string) (localFileSnapshot, bool) {
	for _, precondition := range plan.Preconditions {
		if precondition.ID != id || precondition.Detail == nil {
			continue
		}
		digest, _ := precondition.Detail["file_digest"].(string)
		size, sizeOK := int64FromAny(precondition.Detail["size_bytes"])
		mtime, mtimeOK := int64FromAny(precondition.Detail["mtime_unix_nano"])
		if digest == "" || !sizeOK || !mtimeOK {
			return localFileSnapshot{}, false
		}
		return localFileSnapshot{Digest: digest, Size: size, ModUnixNano: mtime}, true
	}
	return localFileSnapshot{}, false
}

func int64FromAny(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case int32:
		return int64(n), true
	case float64:
		return int64(n), n == float64(int64(n))
	default:
		return 0, false
	}
}

func fileSnapshotMatches(a, b localFileSnapshot) bool {
	return a.Digest == b.Digest && a.Size == b.Size && a.ModUnixNano == b.ModUnixNano
}

func preconditionDetailString(plan doctorFixPlan, id, key string) string {
	for _, precondition := range plan.Preconditions {
		if precondition.ID != id || precondition.Detail == nil {
			continue
		}
		value, _ := precondition.Detail[key].(string)
		return strings.TrimSpace(value)
	}
	return ""
}

func localFixBasePlan(check doctorCheck) doctorFixPlan {
	return doctorFixPlan{
		PlanID:     "fix:" + check.ID,
		CheckID:    check.ID,
		Status:     doctorFixStatusPlanned,
		Source:     doctorSourceLocal,
		Authority:  doctorAuthorityCaller,
		Target:     check.Target,
		Safe:       true,
		HighImpact: false,
	}
}

func refusedLocalFixPlan(plan doctorFixPlan, reason, detail, nextStep string) doctorFixPlan {
	plan.Status = doctorFixStatusRefused
	plan.Safe = false
	plan.HighImpact = false
	plan.RefusalReason = reason
	plan.RefusalDetail = detail
	plan.NextStep = nextStep
	return plan
}

type localActiveTeamFixHandler struct {
	checkID string
}

func (h localActiveTeamFixHandler) CheckID() string {
	return h.checkID
}

func (h localActiveTeamFixHandler) Plan(_ context.Context, ctx doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan := localFixBasePlan(check)
	workspacePath := filepath.Join(ctx.WorkingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	workspace, err := loadDoctorWorkspaceFrom(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be loaded for teams.yaml active_team repair."), nil
	}
	teamID, reason := localSelectableActiveTeam(workspace)
	if reason != "" {
		return refusedLocalFixPlan(plan, localFixReasonAmbiguousState, reason, "Repair workspace memberships manually or reinitialize the workspace binding."), nil
	}
	if teamState, err := awconfig.LoadTeamState(ctx.WorkingDir); err == nil && teamState.Membership(teamID) != nil && strings.EqualFold(strings.TrimSpace(teamState.ActiveTeam), teamID) {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	snapshot, err := snapshotLocalFile(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be inspected for teams.yaml active_team repair."), nil
	}
	detail := snapshot.detail()
	detail["selected_team_id"] = teamID
	plan.PlannedMutations = []doctorFixMutation{{
		Operation:     "rewrite_teams_metadata",
		Description:   "Set teams.yaml active_team from the sole local workspace membership.",
		Target:        localPathTarget(awconfig.TeamStatePath(ctx.WorkingDir)),
		Path:          awconfig.DefaultTeamStateRelativePath(),
		Resource:      "active_team",
		SourceOfTruth: "local workspace memberships",
	}}
	plan.Preconditions = []doctorFixPrecondition{
		{ID: localFixPreconditionWorkspaceYAMLUnchanged, Passed: true, Detail: detail},
		{ID: localFixPreconditionSingleMembership, Passed: true, Detail: map[string]any{"team_id": teamID}},
	}
	plan.NextStep = "Run without --dry-run to update teams.yaml active_team from local workspace metadata."
	return plan, nil
}

func (h localActiveTeamFixHandler) Apply(_ context.Context, ctx doctorFixContext, plan doctorFixPlan) (doctorFixPlan, error) {
	workspacePath := filepath.Join(ctx.WorkingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	wantTeamID := preconditionDetailString(plan, localFixPreconditionSingleMembership, "team_id")
	if wantTeamID == "" {
		wantTeamID = preconditionDetailString(plan, localFixPreconditionWorkspaceYAMLUnchanged, "selected_team_id")
	}
	current, err := snapshotLocalFile(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be inspected for teams.yaml active_team repair."), nil
	}
	workspace, err := loadDoctorWorkspaceFrom(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be loaded for teams.yaml active_team repair."), nil
	}
	if teamState, err := awconfig.LoadTeamState(ctx.WorkingDir); err == nil && wantTeamID != "" && teamState.Membership(wantTeamID) != nil && strings.EqualFold(strings.TrimSpace(teamState.ActiveTeam), wantTeamID) {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	expected, ok := snapshotFromPrecondition(plan, localFixPreconditionWorkspaceYAMLUnchanged)
	if !ok || !fileSnapshotMatches(expected, current) {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "workspace_yaml_changed", "Workspace binding changed after planning; rerun doctor before applying fixes."), nil
	}
	teamID, reason := localSelectableActiveTeam(workspace)
	if reason != "" || (wantTeamID != "" && !strings.EqualFold(teamID, wantTeamID)) {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "workspace_membership_changed", "Workspace memberships changed after planning; rerun doctor before applying fixes."), nil
	}
	teamState := teamStateRepairFromWorkspaceMemberships(workspace, teamID)
	if err := awconfig.SaveTeamState(ctx.WorkingDir, teamState); err != nil {
		return doctorFixPlan{}, err
	}
	plan.Status = doctorFixStatusApplied
	return plan, nil
}

func teamStateRepairFromWorkspaceMemberships(workspace *awconfig.WorktreeWorkspace, activeTeam string) *awconfig.TeamState {
	if workspace == nil {
		return nil
	}
	state := &awconfig.TeamState{ActiveTeam: strings.TrimSpace(activeTeam)}
	for _, membership := range workspace.Memberships {
		state.Memberships = append(state.Memberships, awconfig.TeamMembership{
			TeamID:   strings.TrimSpace(membership.TeamID),
			Alias:    strings.TrimSpace(membership.Alias),
			CertPath: filepath.ToSlash(strings.TrimSpace(membership.CertPath)),
			JoinedAt: strings.TrimSpace(membership.JoinedAt),
		})
	}
	return state
}

func localSelectableActiveTeam(workspace *awconfig.WorktreeWorkspace) (string, string) {
	if workspace == nil {
		return "", "workspace_missing"
	}
	seen := map[string]struct{}{}
	var teamID string
	for _, membership := range workspace.Memberships {
		currentTeamID := strings.TrimSpace(membership.TeamID)
		if currentTeamID == "" {
			return "", "malformed_membership"
		}
		key := strings.ToLower(currentTeamID)
		if _, ok := seen[key]; ok {
			return "", "duplicate_membership"
		}
		seen[key] = struct{}{}
		if teamID != "" {
			return "", "multiple_memberships"
		}
		if strings.TrimSpace(membership.CertPath) == "" || !validLocalWorkspaceID(strings.TrimSpace(membership.WorkspaceID)) {
			return "", "malformed_membership"
		}
		teamID = currentTeamID
	}
	if teamID == "" {
		return "", "empty_memberships"
	}
	return teamID, ""
}

type localWorkspaceURLFixHandler struct{}

func (localWorkspaceURLFixHandler) CheckID() string {
	return doctorCheckWorkspaceAwebURL
}

func (localWorkspaceURLFixHandler) Plan(_ context.Context, ctx doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan := localFixBasePlan(check)
	workspacePath := filepath.Join(ctx.WorkingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	workspace, err := loadDoctorWorkspaceFrom(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be loaded for URL normalization."), nil
	}
	normalization, err := normalizeLocalURLForDoctor(workspace.AwebURL)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "invalid_url", "Workspace aweb_url is not eligible for conservative normalization."), nil
	}
	if !normalization.needsRewrite() {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	snapshot, err := snapshotLocalFile(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be inspected for URL normalization."), nil
	}
	detail := snapshot.detail()
	detail["desired_url"] = normalization.URL
	detail["removed_userinfo"] = normalization.RemovedUserinfo
	detail["removed_query"] = normalization.RemovedQuery
	detail["removed_fragment"] = normalization.RemovedFragment
	plan.PlannedMutations = []doctorFixMutation{{
		Operation:     "rewrite_workspace_metadata",
		Description:   "Normalize aweb_url by removing credential/query/fragment material already present in the local field.",
		Target:        localPathTarget(workspacePath),
		Path:          awconfig.DefaultWorktreeWorkspaceRelativePath(),
		Resource:      "aweb_url",
		SourceOfTruth: "existing local aweb_url",
	}}
	plan.Preconditions = []doctorFixPrecondition{
		{ID: localFixPreconditionWorkspaceYAMLUnchanged, Passed: true, Detail: detail},
		{ID: localFixPreconditionSanitizedURLValid, Passed: true, Detail: doctorURLDetail("aweb_url", normalization)},
	}
	plan.NextStep = "Run without --dry-run to write the sanitized aweb_url."
	return plan, nil
}

func (localWorkspaceURLFixHandler) Apply(_ context.Context, ctx doctorFixContext, plan doctorFixPlan) (doctorFixPlan, error) {
	workspacePath := filepath.Join(ctx.WorkingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	wantURL := preconditionDetailString(plan, localFixPreconditionWorkspaceYAMLUnchanged, "desired_url")
	current, err := snapshotLocalFile(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be inspected for URL normalization."), nil
	}
	workspace, err := loadDoctorWorkspaceFrom(workspacePath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "workspace_yaml_unreadable", "Workspace binding could not be loaded for URL normalization."), nil
	}
	normalization, err := normalizeLocalURLForDoctor(workspace.AwebURL)
	if err != nil {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "invalid_url", "Workspace aweb_url changed after planning; rerun doctor before applying fixes."), nil
	}
	if wantURL != "" && strings.TrimSpace(workspace.AwebURL) == wantURL {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	expected, ok := snapshotFromPrecondition(plan, localFixPreconditionWorkspaceYAMLUnchanged)
	if !ok || !fileSnapshotMatches(expected, current) {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "workspace_yaml_changed", "Workspace binding changed after planning; rerun doctor before applying fixes."), nil
	}
	if wantURL == "" || normalization.URL != wantURL || !normalization.needsRewrite() {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "aweb_url_changed", "Workspace aweb_url changed after planning; rerun doctor before applying fixes."), nil
	}
	workspace.AwebURL = normalization.URL
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		return doctorFixPlan{}, err
	}
	plan.Status = doctorFixStatusApplied
	return plan, nil
}

type localIdentityRegistryURLFixHandler struct{}

func (localIdentityRegistryURLFixHandler) CheckID() string {
	return doctorCheckIdentityRegistryURL
}

func (localIdentityRegistryURLFixHandler) Plan(_ context.Context, ctx doctorFixContext, check doctorCheck) (doctorFixPlan, error) {
	plan := localFixBasePlan(check)
	identityPath := filepath.Join(ctx.WorkingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "identity_yaml_unreadable", "Identity metadata could not be loaded for registry_url normalization."), nil
	}
	normalization, err := normalizeLocalURLForDoctor(identity.RegistryURL)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "invalid_url", "Identity registry_url is not eligible for conservative normalization."), nil
	}
	if !normalization.needsRewrite() {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	snapshot, err := snapshotLocalFile(identityPath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "identity_yaml_unreadable", "Identity metadata could not be inspected for registry_url normalization."), nil
	}
	detail := snapshot.detail()
	detail["desired_url"] = normalization.URL
	detail["removed_userinfo"] = normalization.RemovedUserinfo
	detail["removed_query"] = normalization.RemovedQuery
	detail["removed_fragment"] = normalization.RemovedFragment
	plan.PlannedMutations = []doctorFixMutation{{
		Operation:     "rewrite_identity_metadata",
		Description:   "Normalize registry_url by removing credential/query/fragment material already present in the local field.",
		Target:        localPathTarget(identityPath),
		Path:          awconfig.DefaultWorktreeIdentityRelativePath(),
		Resource:      "registry_url",
		SourceOfTruth: "existing local registry_url",
	}}
	plan.Preconditions = []doctorFixPrecondition{
		{ID: localFixPreconditionIdentityYAMLUnchanged, Passed: true, Detail: detail},
		{ID: localFixPreconditionSanitizedURLValid, Passed: true, Detail: doctorURLDetail("registry_url", normalization)},
		{ID: localFixPreconditionRegistryURLOnly, Passed: true, Detail: map[string]any{"field": "registry_url"}},
	}
	plan.NextStep = "Run without --dry-run to write the sanitized registry_url."
	return plan, nil
}

func (localIdentityRegistryURLFixHandler) Apply(_ context.Context, ctx doctorFixContext, plan doctorFixPlan) (doctorFixPlan, error) {
	identityPath := filepath.Join(ctx.WorkingDir, awconfig.DefaultWorktreeIdentityRelativePath())
	wantURL := preconditionDetailString(plan, localFixPreconditionIdentityYAMLUnchanged, "desired_url")
	current, err := snapshotLocalFile(identityPath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "identity_yaml_unreadable", "Identity metadata could not be inspected for registry_url normalization."), nil
	}
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		return refusedLocalFixPlan(plan, "precondition", "identity_yaml_unreadable", "Identity metadata could not be loaded for registry_url normalization."), nil
	}
	normalization, err := normalizeLocalURLForDoctor(identity.RegistryURL)
	if err != nil {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "invalid_url", "Identity registry_url changed after planning; rerun doctor before applying fixes."), nil
	}
	if wantURL != "" && strings.TrimSpace(identity.RegistryURL) == wantURL {
		plan.Status = doctorFixStatusNoop
		return plan, nil
	}
	expected, ok := snapshotFromPrecondition(plan, localFixPreconditionIdentityYAMLUnchanged)
	if !ok || !fileSnapshotMatches(expected, current) {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "identity_yaml_changed", "Identity metadata changed after planning; rerun doctor before applying fixes."), nil
	}
	if wantURL == "" || normalization.URL != wantURL || !normalization.needsRewrite() {
		return refusedLocalFixPlan(plan, localFixReasonStateChanged, "registry_url_changed", "Identity registry_url changed after planning; rerun doctor before applying fixes."), nil
	}
	identity.RegistryURL = normalization.URL
	if err := awconfig.SaveWorktreeIdentityTo(identityPath, identity); err != nil {
		return doctorFixPlan{}, err
	}
	plan.Status = doctorFixStatusApplied
	return plan, nil
}
