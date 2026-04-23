package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func requireDoctorFixStatus(t *testing.T, out doctorOutput, status doctorFixStatus) doctorFixPlan {
	t.Helper()
	for _, fix := range out.Fixes {
		if fix.Status == status {
			return fix
		}
	}
	t.Fatalf("missing fix status %q: %#v", status, out.Fixes)
	return doctorFixPlan{}
}

func requireNoDoctorOutputLeak(t *testing.T, out []byte, secrets ...string) {
	t.Helper()
	text := string(out)
	for _, secret := range secrets {
		if strings.TrimSpace(secret) == "" {
			continue
		}
		if strings.Contains(text, secret) {
			t.Fatalf("doctor output leaked %q:\n%s", secret, text)
		}
	}
}

func writeDoctorFixWorkspaceYAML(t *testing.T, workingDir, awebURL, activeTeam string, memberships []awconfig.WorktreeMembership) string {
	t.Helper()
	workspacePath := filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath())
	if err := os.MkdirAll(filepath.Dir(workspacePath), 0o700); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	var sb strings.Builder
	sb.WriteString("aweb_url: " + awebURL + "\n")
	sb.WriteString("memberships:\n")
	for _, membership := range memberships {
		sb.WriteString("  - team_id: " + membership.TeamID + "\n")
		if membership.Alias != "" {
			sb.WriteString("    alias: " + membership.Alias + "\n")
		}
		if membership.WorkspaceID != "" {
			sb.WriteString("    workspace_id: " + membership.WorkspaceID + "\n")
		}
		if membership.CertPath != "" {
			sb.WriteString("    cert_path: " + membership.CertPath + "\n")
		}
	}
	if err := os.WriteFile(workspacePath, []byte(sb.String()), 0o600); err != nil {
		t.Fatalf("write workspace.yaml: %v", err)
	}
	if activeTeam != "" {
		teamState := &awconfig.TeamState{ActiveTeam: activeTeam}
		for _, membership := range memberships {
			teamState.Memberships = append(teamState.Memberships, awconfig.TeamMembership{
				TeamID:   membership.TeamID,
				Alias:    membership.Alias,
				CertPath: membership.CertPath,
				JoinedAt: membership.JoinedAt,
			})
		}
		if err := awconfig.SaveTeamState(workingDir, teamState); err != nil {
			t.Fatalf("write teams.yaml: %v", err)
		}
	}
	return workspacePath
}

func TestAwDoctorLocalFixActiveTeamDryRunApplyAndNoop(t *testing.T) {
	bin, tmp := buildDoctorBinary(t)
	workspacePath := writeDoctorFixWorkspaceYAML(t, tmp, "https://app.example.com/api", "", []awconfig.WorktreeMembership{{
		TeamID:      "backend:example.com",
		Alias:       "mia",
		WorkspaceID: "ws-1",
		CertPath:    "team-certs/backend__example.com.pem",
	}})
	before, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatalf("read workspace before dry-run: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--fix", "--dry-run", doctorCheckTeamsActiveTeam, "--json")
	if err != nil {
		t.Fatalf("doctor active_team dry-run failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, "doctor.fix.planned", doctorStatusInfo)
	plan := requireDoctorFixStatus(t, got, doctorFixStatusPlanned)
	if !plan.DryRun || len(plan.PlannedMutations) != 1 || plan.PlannedMutations[0].Resource != "active_team" {
		t.Fatalf("unexpected dry-run plan: %#v", plan)
	}
	if plan.PlannedMutations[0].Operation != "rewrite_teams_metadata" || plan.PlannedMutations[0].Path != awconfig.DefaultTeamStateRelativePath() {
		t.Fatalf("active_team fix should target teams.yaml, got mutation: %#v", plan.PlannedMutations[0])
	}
	afterDryRun, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatalf("read workspace after dry-run: %v", err)
	}
	if !bytes.Equal(before, afterDryRun) {
		t.Fatalf("dry-run mutated workspace.yaml\nbefore:\n%s\nafter:\n%s", string(before), string(afterDryRun))
	}

	out, err = runDoctorCLI(t, bin, tmp, "doctor", "--fix", doctorCheckTeamsActiveTeam, "--json")
	if err != nil {
		t.Fatalf("doctor active_team apply failed: %v\n%s", err, string(out))
	}
	got = decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, "doctor.fix.applied", doctorStatusOK)
	teamState, err := awconfig.LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state after apply: %v", err)
	}
	if teamState.ActiveTeam != "backend:example.com" {
		t.Fatalf("active_team=%q", teamState.ActiveTeam)
	}

	handler, ok := doctorFixHandlers[doctorCheckTeamsActiveTeam]
	if !ok {
		t.Fatalf("active_team handler is not registered")
	}
	check := advertisedDoctorFixCheck(doctorCheckTeamsActiveTeam, true)
	planned, err := handler.Plan(context.Background(), doctorFixContext{WorkingDir: tmp}, check)
	if err != nil {
		t.Fatalf("plan active_team after apply: %v", err)
	}
	if planned.Status != doctorFixStatusNoop {
		t.Fatalf("rerun plan status=%q, want noop: %#v", planned.Status, planned)
	}
}

func TestAwDoctorLocalFixActiveTeamRefusesChangedAndAmbiguousState(t *testing.T) {
	tmp := t.TempDir()
	workspacePath := writeDoctorFixWorkspaceYAML(t, tmp, "https://app.example.com/api", "", []awconfig.WorktreeMembership{{
		TeamID:      "backend:example.com",
		Alias:       "mia",
		WorkspaceID: "ws-1",
		CertPath:    "team-certs/backend__example.com.pem",
	}})
	handler := doctorFixHandlers[doctorCheckTeamsActiveTeam]
	check := advertisedDoctorFixCheck(doctorCheckTeamsActiveTeam, true)
	plan, err := handler.Plan(context.Background(), doctorFixContext{WorkingDir: tmp}, check)
	if err != nil {
		t.Fatalf("plan active_team: %v", err)
	}
	if plan.Status != doctorFixStatusPlanned {
		t.Fatalf("plan status=%q: %#v", plan.Status, plan)
	}
	if err := os.WriteFile(workspacePath, []byte(`aweb_url: https://app.example.com/api
memberships:
  - team_id: other:example.com
    alias: mia
    workspace_id: ws-2
    cert_path: team-certs/other__example.com.pem
`), 0o600); err != nil {
		t.Fatalf("mutate workspace: %v", err)
	}
	applied, err := handler.Apply(context.Background(), doctorFixContext{WorkingDir: tmp}, plan)
	if err != nil {
		t.Fatalf("apply active_team changed file: %v", err)
	}
	if applied.Status != doctorFixStatusRefused || applied.RefusalReason != localFixReasonStateChanged {
		t.Fatalf("changed-file apply=%#v", applied)
	}

	bin, ambiguousDir := buildDoctorBinary(t)
	writeDoctorFixWorkspaceYAML(t, ambiguousDir, "https://app.example.com/api", "", []awconfig.WorktreeMembership{
		{TeamID: "backend:example.com", Alias: "mia", WorkspaceID: "ws-1", CertPath: "team-certs/backend__example.com.pem"},
		{TeamID: "frontend:example.com", Alias: "mia", WorkspaceID: "ws-2", CertPath: "team-certs/frontend__example.com.pem"},
	})
	out, err := runDoctorCLI(t, bin, ambiguousDir, "doctor", "--fix", doctorCheckTeamsActiveTeam, "--json")
	if err != nil {
		t.Fatalf("doctor ambiguous active_team failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	checkResult := requireDoctorCheckStatus(t, got, "doctor.fix."+localFixReasonAmbiguousState, doctorStatusBlocked)
	if checkResult.Detail["reason"] != localFixReasonAmbiguousState {
		t.Fatalf("reason=%v", checkResult.Detail["reason"])
	}
	fix := requireDoctorFixStatus(t, got, doctorFixStatusRefused)
	if fix.RefusalDetail != "multiple_memberships" {
		t.Fatalf("refusal_detail=%q", fix.RefusalDetail)
	}
}

func TestAwDoctorLocalFixWorkspaceURLNormalizeRedactsAndApplies(t *testing.T) {
	bin, tmp := buildDoctorBinary(t)
	workspacePath := writeDoctorFixWorkspaceYAML(t, tmp, "https://user:pass@app.example.com/api?token=secret-query#secret-fragment", "backend:example.com", []awconfig.WorktreeMembership{{
		TeamID:      "backend:example.com",
		Alias:       "mia",
		WorkspaceID: "ws-1",
		CertPath:    "team-certs/backend__example.com.pem",
	}})
	before, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatalf("read workspace before dry-run: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--json")
	if err != nil {
		t.Fatalf("plain doctor failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	if len(got.Fixes) != 0 || strings.Contains(string(out), `"fixes"`) {
		t.Fatalf("plain doctor output included top-level fixes:\n%s", string(out))
	}
	urlCheck := requireDoctorCheckStatus(t, got, doctorCheckWorkspaceAwebURL, doctorStatusOK)
	if urlCheck.Fix == nil || !urlCheck.Fix.Available || !urlCheck.Fix.Safe {
		t.Fatalf("credential-bearing aweb_url did not advertise safe fix: %#v", urlCheck.Fix)
	}
	if urlCheck.Detail["removed_userinfo"] != true || urlCheck.Detail["removed_query"] != true || urlCheck.Detail["removed_fragment"] != true {
		t.Fatalf("missing redaction booleans: %#v", urlCheck.Detail)
	}
	requireNoDoctorOutputLeak(t, out, "user:pass", "token=secret-query", "secret-fragment")

	out, err = runDoctorCLI(t, bin, tmp, "doctor", "--fix", "--dry-run", doctorCheckWorkspaceAwebURL, "--json")
	if err != nil {
		t.Fatalf("doctor aweb_url dry-run failed: %v\n%s", err, string(out))
	}
	got = decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, "doctor.fix.planned", doctorStatusInfo)
	requireNoDoctorOutputLeak(t, out, "user:pass", "token=secret-query", "secret-fragment")
	afterDryRun, err := os.ReadFile(workspacePath)
	if err != nil {
		t.Fatalf("read workspace after dry-run: %v", err)
	}
	if !bytes.Equal(before, afterDryRun) {
		t.Fatalf("dry-run mutated workspace URL\nbefore:\n%s\nafter:\n%s", string(before), string(afterDryRun))
	}

	out, err = runDoctorCLI(t, bin, tmp, "doctor", "--fix", doctorCheckWorkspaceAwebURL, "--json")
	if err != nil {
		t.Fatalf("doctor aweb_url apply failed: %v\n%s", err, string(out))
	}
	got = decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, "doctor.fix.applied", doctorStatusOK)
	workspace, err := loadDoctorWorkspaceFrom(workspacePath)
	if err != nil {
		t.Fatalf("load workspace after URL apply: %v", err)
	}
	if workspace.AwebURL != "https://app.example.com/api" {
		t.Fatalf("aweb_url=%q", workspace.AwebURL)
	}
}

func TestAwDoctorLocalFixRegistryURLNormalizeOnlyMutatesRegistryURL(t *testing.T) {
	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	identityPath := filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())
	signingKeyPath := awconfig.WorktreeSigningKeyPath(tmp)
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	beforeIdentity := *identity
	beforeIdentity.RegistryURL = "https://reguser:regpass@registry.example.com/base?registry_token=secret-registry#registry-fragment"
	if err := awconfig.SaveWorktreeIdentityTo(identityPath, &beforeIdentity); err != nil {
		t.Fatalf("save identity with credential-bearing registry URL: %v", err)
	}
	signingKeyBefore, err := os.ReadFile(signingKeyPath)
	if err != nil {
		t.Fatalf("read signing key before: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--fix", "--dry-run", doctorCheckIdentityRegistryURL, "--json")
	if err != nil {
		t.Fatalf("doctor registry_url dry-run failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, "doctor.fix.planned", doctorStatusInfo)
	requireNoDoctorOutputLeak(t, out, "reguser:regpass", "registry_token=secret-registry", "registry-fragment")
	dryRunIdentity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatalf("load identity after dry-run: %v", err)
	}
	if dryRunIdentity.RegistryURL != beforeIdentity.RegistryURL {
		t.Fatalf("dry-run mutated registry_url=%q", dryRunIdentity.RegistryURL)
	}

	out, err = runDoctorCLI(t, bin, tmp, "doctor", "--fix", doctorCheckIdentityRegistryURL, "--json")
	if err != nil {
		t.Fatalf("doctor registry_url apply failed: %v\n%s", err, string(out))
	}
	got = decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, "doctor.fix.applied", doctorStatusOK)
	afterIdentity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatalf("load identity after apply: %v", err)
	}
	if afterIdentity.RegistryURL != "https://registry.example.com/base" {
		t.Fatalf("registry_url=%q", afterIdentity.RegistryURL)
	}
	beforeIdentity.RegistryURL = afterIdentity.RegistryURL
	if *afterIdentity != beforeIdentity {
		beforeJSON, _ := json.Marshal(beforeIdentity)
		afterJSON, _ := json.Marshal(afterIdentity)
		t.Fatalf("identity fields other than registry_url changed\nbefore:%s\nafter:%s", beforeJSON, afterJSON)
	}
	signingKeyAfter, err := os.ReadFile(signingKeyPath)
	if err != nil {
		t.Fatalf("read signing key after: %v", err)
	}
	if !bytes.Equal(signingKeyBefore, signingKeyAfter) {
		t.Fatalf("signing.key changed during registry_url normalization")
	}
}
