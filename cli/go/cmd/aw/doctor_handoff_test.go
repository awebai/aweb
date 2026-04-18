package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func requireDoctorHandoff(t *testing.T, out doctorOutput, id string) *doctorHandoff {
	t.Helper()
	check := requireDoctorCheckStatus(t, out, id, doctorStatusFail)
	if check.Handoff == nil {
		t.Fatalf("%s missing handoff: %#v", id, check)
	}
	return check.Handoff
}

func TestAwDoctorHandoffJSONContractCategories(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		input  *doctorHandoff
		action string
		auth   doctorAuthority
	}{
		{
			name:   "persistent lifecycle review",
			input:  persistentLifecycleReviewHandoff(),
			action: "persistent_lifecycle_review",
			auth:   doctorAuthorityTeamAdmin,
		},
		{
			name:   "persistent replacement review",
			input:  persistentReplacementReviewHandoff(doctorAuthorityStatusNotDetected, nil),
			action: "persistent_replacement_review",
			auth:   doctorAuthorityTeamAdmin,
		},
		{
			name:   "persistent identity registry repair review",
			input:  persistentIdentityRegistryRepairReviewHandoff(doctorAuthorityStatusPresent, []string{"local signing key matches identity did"}),
			action: "persistent_identity_registry_repair_review",
			auth:   doctorAuthorityCaller,
		},
		{
			name:   "managed address repair review",
			input:  managedAddressRepairReviewHandoff(doctorAuthorityStatusNotDetected, nil),
			action: "managed_address_repair_review",
			auth:   doctorAuthorityNamespaceController,
		},
		{
			name:   "namespace controller recovery review",
			input:  namespaceControllerRecoveryReviewHandoff(),
			action: "namespace_controller_recovery_review",
			auth:   doctorAuthorityNamespaceController,
		},
		{
			name:   "suspected key mismatch review",
			input:  suspectedKeyMismatchReviewHandoff(doctorAuthorityStatusNotDetected, nil),
			action: "suspected_key_mismatch_review",
			auth:   doctorAuthorityCaller,
		},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("marshal handoff: %v", err)
			}
			var got map[string]any
			if err := json.Unmarshal(data, &got); err != nil {
				t.Fatalf("unmarshal handoff: %v", err)
			}
			if got["action"] != tc.action {
				t.Fatalf("action=%v, want %s\n%s", got["action"], tc.action, data)
			}
			if got["required_authority"] != string(tc.auth) {
				t.Fatalf("required_authority=%v, want %s\n%s", got["required_authority"], tc.auth, data)
			}
			if got["doctor_refusal_reason"] == "" {
				t.Fatalf("missing doctor_refusal_reason:\n%s", data)
			}
			if strings.Contains(string(data), "private key") || strings.Contains(string(data), "Authorization") {
				t.Fatalf("handoff contract included secret-like implementation text:\n%s", data)
			}
		})
	}
}

func TestAwDoctorHandoffPresentAuthorityMustMatchRequiredAuthority(t *testing.T) {
	t.Parallel()

	handoffs := []*doctorHandoff{
		persistentReplacementReviewHandoff(doctorAuthorityStatusNotDetected, nil),
		managedAddressRepairReviewHandoff(doctorAuthorityStatusNotDetected, nil),
		namespaceControllerRecoveryReviewHandoff(),
		persistentIdentityRegistryRepairReviewHandoff(doctorAuthorityStatusPresent, []string{"local signing key matches identity did"}),
	}
	for _, handoff := range handoffs {
		if handoff.RequiredAuthority != doctorAuthorityCaller && handoff.CallerAuthorityStatus == doctorAuthorityStatusPresent {
			t.Fatalf("handoff %s reported present caller authority for privileged authority %s: %#v", handoff.Action, handoff.RequiredAuthority, handoff)
		}
		if handoff.RequiredAuthority != doctorAuthorityCaller && len(handoff.CallerAuthorityEvidence) > 0 {
			t.Fatalf("handoff %s carried local evidence for privileged authority %s: %#v", handoff.Action, handoff.RequiredAuthority, handoff)
		}
	}
}

func TestAwDoctorHandoffCallerRepairCommandRequiresPresentAuthority(t *testing.T) {
	t.Parallel()

	notDetected := persistentIdentityRegistryRepairReviewHandoff(doctorAuthorityStatusNotDetected, nil)
	if notDetected.ExplicitCommand != "" {
		t.Fatalf("not_detected caller authority exposed command: %#v", notDetected)
	}
	if notDetected.DryRunCommand == "" {
		t.Fatalf("not_detected caller authority should keep diagnostic dry-run command: %#v", notDetected)
	}

	present := persistentIdentityRegistryRepairReviewHandoff(doctorAuthorityStatusPresent, []string{"local signing key matches identity did"})
	if present.ExplicitCommand != "aw id register" {
		t.Fatalf("present caller authority command=%q", present.ExplicitCommand)
	}
}

func TestAwDoctorHandoffMissingPersistentStateNeedsExternalReview(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://user:pass@app.example.com/api?token=secret-query#secret-fragment")
	workspace, workspacePath, err := awconfig.LoadWorktreeWorkspaceFromDir(tmp)
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	workspace.APIKey = "secret-api-token"
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		t.Fatalf("save workspace: %v", err)
	}
	if err := os.Remove(filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())); err != nil {
		t.Fatalf("remove identity: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor local failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	handoff := requireDoctorHandoff(t, got, doctorCheckIdentityPersistent)
	if handoff.Action != "persistent_lifecycle_review" {
		t.Fatalf("action=%q", handoff.Action)
	}
	if !strings.Contains(handoff.ExpectedAction, "missing local state alone is not enough") {
		t.Fatalf("expected_action did not guard missing local state: %#v", handoff)
	}
	if handoff.ExplicitCommand != "" {
		t.Fatalf("missing local state exposed runnable command: %#v", handoff)
	}
	for _, text := range []string{handoff.ExpectedAction, handoff.DashboardAction, handoff.ReplacementGuidance} {
		if strings.Contains(text, "run archive") || strings.Contains(text, "run replace") {
			t.Fatalf("handoff recommended lifecycle action from missing local state: %#v", handoff)
		}
	}
	requireNoDoctorOutputLeak(t, out, "user:pass", "token=secret-query", "secret-fragment", "secret-api-token")
}

func TestAwDoctorHandoffDIDNotFoundUsesCallerRepairAuthority(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"did": "not_found"})
	t.Cleanup(server.Close)
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(fixture.Dir, awconfig.DefaultWorktreeIdentityRelativePath()))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	identity.RegistryURL = server.URL
	writeIdentityForTest(t, fixture.Dir, *identity)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDDIDResolve, doctorStatusFail)
	if check.Handoff == nil {
		t.Fatalf("did not found missing handoff: %#v", check)
	}
	if check.Handoff.Action != "persistent_identity_registry_repair_review" {
		t.Fatalf("action=%q", check.Handoff.Action)
	}
	if check.Handoff.RequiredAuthority != doctorAuthorityCaller || check.Handoff.CallerAuthorityStatus != doctorAuthorityStatusPresent {
		t.Fatalf("unexpected authority fields: %#v", check.Handoff)
	}
	if !strings.Contains(check.Handoff.ReplacementGuidance, "preferred before replacement") {
		t.Fatalf("replacement guidance does not prefer repair: %#v", check.Handoff)
	}
}

func TestAwDoctorHandoffHumanDefaultAndVerboseOutput(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	if err := os.Remove(filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())); err != nil {
		t.Fatalf("remove identity: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local")
	if err != nil {
		t.Fatalf("doctor local human failed: %v\n%s", err, string(out))
	}
	text := string(out)
	if got := strings.Count(text, "handoff:"); got != 1 {
		t.Fatalf("default human handoff lines=%d, want 1:\n%s", got, text)
	}
	if strings.Contains(text, "authority:") || strings.Contains(text, "consequences:") || strings.Contains(text, "dashboard:") {
		t.Fatalf("default human output included verbose handoff detail:\n%s", text)
	}

	out, err = runDoctorCLI(t, bin, tmp, "doctor", "--verbose", "local")
	if err != nil {
		t.Fatalf("doctor local verbose failed: %v\n%s", err, string(out))
	}
	text = string(out)
	for _, want := range []string{"handoff:", "authority:", "dashboard:", "consequences:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("verbose human output missing %q:\n%s", want, text)
		}
	}
}

func TestAwDoctorHandoffOKChecksOmitHandoff(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor local failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	for _, id := range []string{
		doctorCheckIdentityPersistent,
		doctorCheckSigningKeyMatchesCert,
		doctorCheckIdentityDID,
	} {
		check := requireDoctorCheckStatus(t, got, id, doctorStatusOK)
		if check.Handoff != nil {
			t.Fatalf("%s unexpectedly had handoff: %#v", id, check.Handoff)
		}
	}
}

func TestAwDoctorHandoffAddressMismatchPrefersAddressRepair(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"address": "different_stable", "list": "different_address"})
	t.Cleanup(server.Close)
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(fixture.Dir, awconfig.DefaultWorktreeIdentityRelativePath()))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	identity.RegistryURL = server.URL
	writeIdentityForTest(t, fixture.Dir, *identity)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressStableID, doctorStatusWarn)
	if check.Handoff == nil {
		t.Fatalf("address mismatch missing handoff: %#v", check)
	}
	if check.Handoff.Action != "managed_address_repair_review" {
		t.Fatalf("action=%q", check.Handoff.Action)
	}
	if !strings.Contains(check.Handoff.ReplacementGuidance, "Address repair is first-line") {
		t.Fatalf("replacement guidance does not prefer address repair: %#v", check.Handoff)
	}
	if check.Handoff.ExplicitCommand != "" {
		t.Fatalf("address repair handoff exposed unconditional command: %#v", check.Handoff)
	}
	if !strings.Contains(check.Handoff.DashboardAction, "only when") {
		t.Fatalf("dashboard action is not conditional: %#v", check.Handoff)
	}
}

func TestAwDoctorHandoffNamespaceRecoveryUsesConditionalDashboardText(t *testing.T) {
	t.Parallel()

	fixture := writeDoctorIdentityFixture(t, "")
	server, _ := newDoctorAWIDServer(t, &fixture, map[string]string{"address": "not_found", "list": "empty"})
	t.Cleanup(server.Close)
	identity, err := awconfig.LoadWorktreeIdentityFrom(filepath.Join(fixture.Dir, awconfig.DefaultWorktreeIdentityRelativePath()))
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	identity.RegistryURL = server.URL
	writeIdentityForTest(t, fixture.Dir, *identity)

	out, err := runDoctorCLI(t, fixture.Bin, fixture.Dir, "doctor", "registry", "--online", "--json")
	if err != nil {
		t.Fatalf("doctor registry failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckAWIDAddressReverseListing, doctorStatusWarn)
	if check.Handoff == nil {
		t.Fatalf("namespace recovery missing handoff: %#v", check)
	}
	if check.Handoff.Action != "namespace_controller_recovery_review" {
		t.Fatalf("action=%q", check.Handoff.Action)
	}
	if check.Handoff.RequiredAuthority != doctorAuthorityNamespaceController || check.Handoff.CallerAuthorityStatus != doctorAuthorityStatusNotDetected {
		t.Fatalf("unexpected authority fields: %#v", check.Handoff)
	}
	if check.Handoff.ExplicitCommand != "" {
		t.Fatalf("namespace recovery exposed unconditional command: %#v", check.Handoff)
	}
	if !strings.Contains(check.Handoff.DashboardAction, "only when") {
		t.Fatalf("dashboard action is not conditional: %#v", check.Handoff)
	}
}
