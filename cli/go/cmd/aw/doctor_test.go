package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func buildDoctorBinary(t *testing.T) (string, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	tmp := t.TempDir()
	bin := filepath.Join(tmp, "aw")
	buildAwBinary(t, ctx, bin)
	return bin, tmp
}

func runDoctorCLI(t *testing.T, bin, dir string, args ...string) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	run := exec.CommandContext(ctx, bin, args...)
	run.Dir = dir
	run.Env = testCommandEnv(dir)
	return run.CombinedOutput()
}

func decodeDoctorOutput(t *testing.T, out []byte) doctorOutput {
	t.Helper()
	var got doctorOutput
	if err := json.Unmarshal(extractJSON(t, out), &got); err != nil {
		t.Fatalf("invalid doctor json: %v\n%s", err, string(out))
	}
	return got
}

func doctorCheckByID(out doctorOutput, id string) (doctorCheck, bool) {
	for _, check := range out.Checks {
		if check.ID == id {
			return check, true
		}
	}
	return doctorCheck{}, false
}

func requireDoctorCheckStatus(t *testing.T, out doctorOutput, id string, status doctorStatus) doctorCheck {
	t.Helper()
	check, ok := doctorCheckByID(out, id)
	if !ok {
		t.Fatalf("missing check %s: %#v", id, out.Checks)
	}
	if check.Status != status {
		t.Fatalf("%s status=%q, want %q: %#v", id, check.Status, status, check)
	}
	return check
}

func writeDoctorEphemeralFixture(t *testing.T, workingDir, awebURL string) {
	t.Helper()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	writeSelectionFixtureForTest(t, workingDir, testSelectionFixture{
		AwebURL:     awebURL,
		TeamID:      "backend:example.com",
		Alias:       "mia",
		WorkspaceID: "ws-ephemeral",
		DID:         awid.ComputeDIDKey(pub),
		Address:     "example.com/mia",
		Lifetime:    awid.LifetimeEphemeral,
		SigningKey:  priv,
		CreatedAt:   "2026-04-04T00:00:00Z",
	})
	if err := os.Remove(filepath.Join(workingDir, awconfig.DefaultWorktreeIdentityRelativePath())); err != nil && !os.IsNotExist(err) {
		t.Fatalf("remove ephemeral identity: %v", err)
	}
}

func writeDoctorPersistentFixture(t *testing.T, workingDir, awebURL string) ed25519.PrivateKey {
	t.Helper()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate keypair: %v", err)
	}
	did := awid.ComputeDIDKey(pub)
	stableID := awid.ComputeStableID(pub)
	writeSelectionFixtureForTest(t, workingDir, testSelectionFixture{
		AwebURL:     awebURL,
		TeamID:      "backend:example.com",
		Alias:       "mia",
		WorkspaceID: "ws-persistent",
		DID:         did,
		StableID:    stableID,
		Address:     "example.com/mia",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		SigningKey:  priv,
		CreatedAt:   "2026-04-04T00:00:00Z",
	})
	writeIdentityForTest(t, workingDir, awconfig.WorktreeIdentity{
		DID:         did,
		StableID:    stableID,
		Address:     "example.com/mia",
		Custody:     awid.CustodySelf,
		Lifetime:    awid.LifetimePersistent,
		RegistryURL: "https://registry.example.com",
		CreatedAt:   "2026-04-04T00:00:00Z",
	})
	return priv
}

func writeDoctorWorkspaceYAML(t *testing.T, workingDir, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Join(workingDir, ".aw"), 0o700); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workingDir, awconfig.DefaultWorktreeWorkspaceRelativePath()), []byte(body), 0o600); err != nil {
		t.Fatalf("write workspace.yaml: %v", err)
	}
}

func TestAwDoctorJSONWorksWithoutWorkspaceConfig(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--json")
	if err != nil {
		t.Fatalf("doctor failed: %v\n%s", err, string(out))
	}

	got := decodeDoctorOutput(t, out)
	if got.Version != doctorVersion {
		t.Fatalf("version=%q", got.Version)
	}
	if got.Status != doctorStatusInfo {
		t.Fatalf("status=%q", got.Status)
	}
	if got.SupportBundle != nil {
		t.Fatalf("plain doctor output unexpectedly included support_bundle")
	}
	if len(got.Fixes) != 0 {
		t.Fatalf("plain doctor output unexpectedly included fixes: %#v", got.Fixes)
	}
	if strings.Contains(string(out), "support_bundle") {
		t.Fatalf("plain doctor JSON included support_bundle:\n%s", string(out))
	}
	if strings.Contains(string(out), `"fixes"`) {
		t.Fatalf("plain doctor JSON included fixes:\n%s", string(out))
	}
	if got.Mode != doctorModeAuto {
		t.Fatalf("mode=%q", got.Mode)
	}
	wantWorkingDir, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		t.Fatalf("eval temp dir: %v", err)
	}
	if got.Subject.WorkingDir != wantWorkingDir {
		t.Fatalf("working_dir=%q, want %q", got.Subject.WorkingDir, wantWorkingDir)
	}
	check := requireDoctorCheckStatus(t, got, doctorCheckWorkspaceExists, doctorStatusInfo)
	if check.Detail["state"] != "missing" {
		t.Fatalf("local detail state=%v", check.Detail["state"])
	}
}

func TestAwDoctorHumanOutput(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	out, err := runDoctorCLI(t, bin, tmp, "doctor")
	if err != nil {
		t.Fatalf("doctor failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, want := range []string{
		"Doctor: info",
		"Mode:   auto",
		"doctor.contract.v1",
		doctorCheckWorkspaceExists,
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("human output missing %q:\n%s", want, text)
		}
	}
}

func TestAwDoctorRejectsMutuallyExclusiveModes(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--offline", "--online")
	if err == nil {
		t.Fatalf("expected mutually exclusive flags to fail:\n%s", string(out))
	}
	if !strings.Contains(string(out), "--offline and --online are mutually exclusive") {
		t.Fatalf("unexpected error:\n%s", string(out))
	}
}

func TestAwDoctorScopedRegistryCategory(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	for _, args := range [][]string{
		{"doctor", "registry", "--offline", "--json"},
		{"doctor", "--offline", "registry", "--json"},
	} {
		out, err := runDoctorCLI(t, bin, tmp, args...)
		if err != nil {
			t.Fatalf("%s failed: %v\n%s", strings.Join(args, " "), err, string(out))
		}
		got := decodeDoctorOutput(t, out)
		if got.Mode != doctorModeOffline {
			t.Fatalf("%s mode=%q", strings.Join(args, " "), got.Mode)
		}
		if _, ok := doctorCheckByID(got, doctorCheckAWIDDIDResolve); !ok {
			t.Fatalf("missing registry awid check: %#v", got.Checks)
		}
		if _, ok := doctorCheckByID(got, doctorCheckWorkspaceExists); ok {
			t.Fatalf("scoped registry output unexpectedly included local check: %#v", got.Checks)
		}
	}
}

func TestAwDoctorSupportBundleWritesDoctorJSON(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	outputPath := filepath.Join(tmp, "doctor.json")
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "support-bundle", "--offline", "--output", outputPath)
	if err != nil {
		t.Fatalf("doctor support-bundle failed: %v\n%s", err, string(out))
	}
	if !strings.Contains(string(out), "Wrote doctor support bundle") {
		t.Fatalf("unexpected support-bundle output:\n%s", string(out))
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("read support bundle: %v", err)
	}
	got := decodeDoctorOutput(t, data)
	if got.Version != doctorVersion {
		t.Fatalf("version=%q", got.Version)
	}
	if got.Mode != doctorModeOffline {
		t.Fatalf("mode=%q", got.Mode)
	}
	if len(got.Redactions) == 0 {
		t.Fatalf("expected redaction metadata in support bundle")
	}
	if got.SupportBundle == nil {
		t.Fatalf("expected support_bundle metadata")
	}
	if got.SupportBundle.Platform.OS == "" || got.SupportBundle.Platform.Arch == "" {
		t.Fatalf("expected os/arch platform metadata: %#v", got.SupportBundle.Platform)
	}
}

func TestAwDoctorSupportBundleJSONPrintsRedactedBundle(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	workspace, workspacePath, err := awconfig.LoadWorktreeWorkspaceFromDir(tmp)
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	workspace.APIKey = "secret-api-token"
	workspace.AwebURL = "https://user:pass@app.example.com/api?token=secret-query#secret-fragment"
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		t.Fatalf("save workspace: %v", err)
	}
	identityPath := filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	identity.RegistryURL = "https://reguser:regpass@registry.example.com/path?registry_token=secret-registry#registry-fragment"
	writeIdentityForTest(t, tmp, *identity)
	certPath := awconfig.TeamCertificatePath(tmp, resolvedTeamIDForTest("backend:example.com"))
	rawCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	cert, err := awid.LoadTeamCertificate(certPath)
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}

	outputPath := filepath.Join(tmp, "doctor.json")
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "support-bundle", "--offline", "--output", outputPath, "--json")
	if err != nil {
		t.Fatalf("doctor support-bundle --json failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	if got.SupportBundle == nil {
		t.Fatalf("printed support bundle JSON omitted support_bundle")
	}
	text := string(out)
	for _, secret := range []string{
		"secret-api-token",
		"BEGIN ED25519 PRIVATE KEY",
		cert.Signature,
		"user:pass",
		"token=secret-query",
		"secret-fragment",
		"reguser:regpass",
		"registry_token=secret-registry",
		"registry-fragment",
		strings.TrimSpace(string(rawCert)),
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("support bundle output leaked secret %q:\n%s", secret, text)
		}
	}
	if got.SupportBundle.LocalMetadata.Certificate == nil {
		t.Fatalf("support bundle missing parsed certificate metadata")
	}
	if got.SupportBundle.LocalMetadata.Certificate.TeamID != "backend:example.com" {
		t.Fatalf("certificate team_id=%q", got.SupportBundle.LocalMetadata.Certificate.TeamID)
	}
	if got.SupportBundle.LocalMetadata.Certificate.MemberDIDKey == "" {
		t.Fatalf("certificate member did:key missing")
	}
	if !strings.Contains(text, `"support_bundle"`) || !strings.Contains(text, "https://app.example.com/api") || !strings.Contains(text, "https://registry.example.com/path") {
		t.Fatalf("support bundle output missing expected sanitized metadata:\n%s", text)
	}
}

func TestAwDoctorSupportBundleFinalScanFailsBeforeWrite(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	outputPath := filepath.Join(tmp, "unsafe.json")
	out := doctorOutput{
		Version:     doctorVersion,
		GeneratedAt: "2026-04-18T00:00:00Z",
		Status:      doctorStatusInfo,
		Mode:        doctorModeOffline,
		Checks: []doctorCheck{{
			ID:        "synthetic.check",
			Status:    doctorStatusInfo,
			Source:    doctorSourceLocal,
			Authority: doctorAuthorityCaller,
			Message:   "synthetic secret-survived",
		}},
		SupportBundle: &doctorSupportBundleInfo{Schema: doctorSupportBundleSchema},
	}
	err := writeDoctorSupportBundleFile(outputPath, out, []doctorKnownSecret{{Value: "secret-survived", Reason: "synthetic"}})
	if err == nil {
		t.Fatalf("expected final scan failure")
	}
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsafe bundle file was written, statErr=%v", statErr)
	}
}

func TestAwDoctorSupportBundleFinalScanRejectsRawTeamCertificate(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	certPath := awconfig.TeamCertificatePath(tmp, resolvedTeamIDForTest("backend:example.com"))
	rawCert, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	rawCertText := strings.TrimSpace(string(rawCert))
	secrets := collectDoctorKnownSecrets(tmp)
	foundRawCert := false
	for _, secret := range secrets {
		if secret.Value == rawCertText && secret.Reason == "raw_team_certificate" {
			foundRawCert = true
			break
		}
	}
	if !foundRawCert {
		t.Fatalf("known secrets did not include raw team certificate")
	}
	outputPath := filepath.Join(tmp, "unsafe-cert.json")
	out := doctorOutput{
		Version:     doctorVersion,
		GeneratedAt: "2026-04-18T00:00:00Z",
		Status:      doctorStatusInfo,
		Mode:        doctorModeOffline,
		Checks: []doctorCheck{{
			ID:        "synthetic.raw_cert",
			Status:    doctorStatusInfo,
			Source:    doctorSourceLocal,
			Authority: doctorAuthorityCaller,
			Message:   "synthetic",
			Detail:    map[string]any{"unexpected_blob": rawCertText},
		}},
		SupportBundle: &doctorSupportBundleInfo{Schema: doctorSupportBundleSchema},
	}
	err = writeDoctorSupportBundleFile(outputPath, out, secrets)
	if err == nil {
		t.Fatalf("expected raw team certificate final scan failure")
	}
	if _, statErr := os.Stat(outputPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("unsafe raw cert bundle file was written, statErr=%v", statErr)
	}
}

func TestAwDoctorSupportBundleRequestIDExtractionIgnoresSecretSiblings(t *testing.T) {
	t.Parallel()

	body := `{"detail":{"request_id":"req-123","secret":"do-not-include"}}`
	got, ok := extractDoctorRequestID(body)
	if !ok || got != "req-123" {
		t.Fatalf("request id=%q ok=%v", got, ok)
	}
	if strings.Contains(got, "do-not-include") {
		t.Fatalf("request id included sibling data: %q", got)
	}
	if got, ok := extractDoctorRequestID(`{"detail":{"request_id":{"nested":"bad"}},"correlation_id":42}`); !ok || got != "42" {
		t.Fatalf("numeric correlation id=%q ok=%v", got, ok)
	}
	longID := strings.Repeat("é", 140)
	got, ok = extractDoctorRequestID(`{"request_id":"` + longID + `"}`)
	if !ok {
		t.Fatalf("expected unicode request id")
	}
	if !utf8.ValidString(got) {
		t.Fatalf("request id is not valid utf-8")
	}
	if got != strings.Repeat("é", 128) {
		t.Fatalf("request id length/content mismatch: %q", got)
	}
}

func TestAwDoctorSupportBundleOfflineDoesNotContactNetwork(t *testing.T) {
	t.Parallel()

	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "doctor support-bundle should not call network", http.StatusTeapot)
	}))
	t.Cleanup(server.Close)
	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, server.URL)
	outputPath := filepath.Join(tmp, "doctor.json")

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "support-bundle", "--offline", "--output", outputPath)
	if err != nil {
		t.Fatalf("doctor support-bundle offline failed: %v\n%s", err, string(out))
	}
	if hits.Load() != 0 {
		t.Fatalf("offline support-bundle contacted network %d times", hits.Load())
	}
	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("support bundle was not written: %v", err)
	}
}

func TestAwDoctorFixReportsBlockedWithoutMutation(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--fix", "--dry-run", "local.workspace_yaml.exists", "--json")
	if err != nil {
		t.Fatalf("doctor fix skeleton failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	if got.Status != doctorStatusBlocked {
		t.Fatalf("status=%q", got.Status)
	}
	check, ok := doctorCheckByID(got, "doctor.fix.fix_not_advertised")
	if !ok {
		t.Fatalf("missing fix blocked check: %#v", got.Checks)
	}
	if check.Status != doctorStatusBlocked {
		t.Fatalf("fix check status=%q", check.Status)
	}
	if check.Fix == nil || check.Fix.Available || check.Fix.Safe || !check.Fix.DryRun {
		t.Fatalf("unexpected fix payload: %#v", check.Fix)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".aw")); !os.IsNotExist(err) {
		t.Fatalf("doctor --fix skeleton mutated workspace; .aw stat err=%v", err)
	}
}

func TestAwDoctorFixRootNoCandidatesBlocked(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--fix", "--json")
	if err != nil {
		t.Fatalf("doctor fix failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	if got.Status != doctorStatusBlocked {
		t.Fatalf("status=%q", got.Status)
	}
	check := requireDoctorCheckStatus(t, got, "doctor.fix.fix_not_advertised", doctorStatusBlocked)
	if check.Detail["reason"] != "fix_not_advertised" {
		t.Fatalf("reason=%v", check.Detail["reason"])
	}
	if len(got.Fixes) != 1 || got.Fixes[0].RefusalReason != "fix_not_advertised" {
		t.Fatalf("fixes=%#v", got.Fixes)
	}
}

func TestAwDoctorFixTargetNotFound(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--fix", "missing.check", "--json")
	if err != nil {
		t.Fatalf("doctor fix failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, "doctor.fix.target_not_found", doctorStatusBlocked)
	if check.Detail["reason"] != "target_not_found" {
		t.Fatalf("reason=%v", check.Detail["reason"])
	}
}

type fakeDoctorFixHandler struct {
	id          string
	plan        doctorFixPlan
	planErr     error
	applyErr    error
	applyCalled int
}

func (h *fakeDoctorFixHandler) CheckID() string {
	return h.id
}

func (h *fakeDoctorFixHandler) Plan(context.Context, doctorFixContext, doctorCheck) (doctorFixPlan, error) {
	if h.planErr != nil {
		return doctorFixPlan{}, h.planErr
	}
	return h.plan, nil
}

func (h *fakeDoctorFixHandler) Apply(context.Context, doctorFixContext, doctorFixPlan) (doctorFixPlan, error) {
	h.applyCalled++
	if h.applyErr != nil {
		return doctorFixPlan{}, h.applyErr
	}
	out := h.plan
	out.Status = doctorFixStatusApplied
	return out, nil
}

func setDoctorFixHandlersForTest(t *testing.T, handlers map[string]doctorFixHandler) func() {
	t.Helper()
	old := doctorFixHandlers
	restored := false
	restore := func() {
		if restored {
			return
		}
		doctorFixHandlers = old
		restored = true
	}
	doctorFixHandlers = handlers
	t.Cleanup(restore)
	return restore
}

func advertisedDoctorFixCheck(id string, safe bool) doctorCheck {
	return doctorCheck{
		ID:        id,
		Status:    doctorStatusFail,
		Source:    doctorSourceLocal,
		Authority: doctorAuthorityCaller,
		Target:    &doctorTarget{Type: "check", ID: id},
		Message:   "fake check",
		Fix: &doctorFixInfo{
			Available: true,
			Safe:      safe,
		},
	}
}

func runDoctorFixFrameworkForTest(check doctorCheck, opts doctorRunOptions) doctorOutput {
	runner := doctorRunner{
		opts:       opts,
		workingDir: ".",
		output: doctorOutput{
			Version: doctorVersion,
			Status:  doctorStatusInfo,
			Mode:    opts.Mode,
			Checks:  []doctorCheck{check},
		},
	}
	runner.runFixFramework()
	runner.output.Status = aggregateDoctorStatus(runner.output.Checks)
	return runner.output
}

func TestAwDoctorFixAdvertisedNoHandler(t *testing.T) {
	setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{})

	got := runDoctorFixFrameworkForTest(advertisedDoctorFixCheck("fake.safe", true), doctorRunOptions{Fix: true, DryRun: true})
	check := requireDoctorCheckStatus(t, got, "doctor.fix.no_fix_registered", doctorStatusBlocked)
	if check.Detail["reason"] != "no_fix_registered" {
		t.Fatalf("reason=%v", check.Detail["reason"])
	}
	if len(got.Fixes) != 1 || got.Fixes[0].RefusalReason != "no_fix_registered" {
		t.Fatalf("fixes=%#v", got.Fixes)
	}
}

func TestAwDoctorFixFakeSafeDryRunDoesNotApply(t *testing.T) {
	handler := &fakeDoctorFixHandler{
		id: "fake.safe",
		plan: doctorFixPlan{
			CheckID:   "fake.safe",
			Safe:      true,
			Authority: doctorAuthorityCaller,
			Target:    &doctorTarget{Type: "local_path", ID: ".aw/workspace.yaml"},
			PlannedMutations: []doctorFixMutation{{
				Operation:   "write_metadata",
				Description: "write non-secret metadata",
				Path:        ".aw/workspace.yaml",
			}},
		},
	}
	setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{handler.id: handler})

	got := runDoctorFixFrameworkForTest(advertisedDoctorFixCheck(handler.id, true), doctorRunOptions{Fix: true, DryRun: true})
	requireDoctorCheckStatus(t, got, "doctor.fix.planned", doctorStatusInfo)
	if handler.applyCalled != 0 {
		t.Fatalf("dry-run called Apply %d times", handler.applyCalled)
	}
	if len(got.Fixes) != 1 || got.Fixes[0].Status != doctorFixStatusPlanned || !got.Fixes[0].DryRun {
		t.Fatalf("fixes=%#v", got.Fixes)
	}
}

func TestAwDoctorFixApplyRequiresAdvertisedSafe(t *testing.T) {
	handler := &fakeDoctorFixHandler{
		id: "fake.safe",
		plan: doctorFixPlan{
			CheckID:   "fake.safe",
			Safe:      true,
			Authority: doctorAuthorityCaller,
			PlannedMutations: []doctorFixMutation{{
				Operation:   "write_metadata",
				Description: "write non-secret metadata",
				Path:        ".aw/workspace.yaml",
			}},
		},
	}
	setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{handler.id: handler})

	got := runDoctorFixFrameworkForTest(advertisedDoctorFixCheck(handler.id, false), doctorRunOptions{Fix: true})
	check := requireDoctorCheckStatus(t, got, "doctor.fix.safety_refused", doctorStatusBlocked)
	if check.Detail["safety_reason"] != "unsafe" {
		t.Fatalf("safety_reason=%v", check.Detail["safety_reason"])
	}
	if handler.applyCalled != 0 {
		t.Fatalf("unsafe advertised fix called Apply")
	}

	got = runDoctorFixFrameworkForTest(advertisedDoctorFixCheck(handler.id, true), doctorRunOptions{Fix: true})
	requireDoctorCheckStatus(t, got, "doctor.fix.applied", doctorStatusOK)
	if handler.applyCalled != 1 {
		t.Fatalf("applyCalled=%d, want 1", handler.applyCalled)
	}
}

func TestAwDoctorFixSafetyValidatorRefusesSensitivePlans(t *testing.T) {
	cases := []struct {
		name string
		plan doctorFixPlan
		want string
	}{
		{name: "unsafe", plan: doctorFixPlan{Safe: false, Authority: doctorAuthorityCaller}, want: "unsafe"},
		{name: "high-impact", plan: doctorFixPlan{Safe: true, HighImpact: true, Authority: doctorAuthorityCaller}, want: "high_impact"},
		{name: "authority", plan: doctorFixPlan{Safe: true, Authority: doctorAuthoritySupport}, want: "authority"},
		{name: "precondition", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, Preconditions: []doctorFixPrecondition{{ID: "fresh_state", Passed: false}}}, want: "precondition"},
		{name: "persistent lifecycle", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "delete persistent identity lifecycle"}}}, want: "persistent_identity_lifecycle"},
		{name: "did aw delete", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "delete", Target: &doctorTarget{Type: "did", ID: "did:aw:example"}}}}, want: "persistent_identity_lifecycle"},
		{name: "identity reassign", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "reassign identity binding"}}}, want: "persistent_identity_lifecycle"},
		{name: "managed address reassign", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "reassign managed address"}}}, want: "persistent_identity_lifecycle"},
		{name: "private key", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "write", Path: ".aw/signing.key"}}}, want: "private_key_material"},
		{name: "signing key underscore", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "rotate signing_key"}}}, want: "private_key_material"},
		{name: "private key hyphen", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "write private-key material"}}}, want: "private_key_material"},
		{name: "task unclaim", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "task unclaim"}}}, want: "coordination_cleanup"},
		{name: "presence cleanup", plan: doctorFixPlan{Safe: true, Authority: doctorAuthorityCaller, PlannedMutations: []doctorFixMutation{{Operation: "clear presence"}}}, want: "coordination_cleanup"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			handler := &fakeDoctorFixHandler{id: "fake.sensitive", plan: tc.plan}
			setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{handler.id: handler})
			got := runDoctorFixFrameworkForTest(advertisedDoctorFixCheck(handler.id, true), doctorRunOptions{Fix: true})
			check := requireDoctorCheckStatus(t, got, "doctor.fix.safety_refused", doctorStatusBlocked)
			if check.Detail["safety_reason"] != tc.want {
				t.Fatalf("safety_reason=%v, want %s", check.Detail["safety_reason"], tc.want)
			}
			if handler.applyCalled != 0 {
				t.Fatalf("refused plan called Apply")
			}
		})
	}
}

func TestAwDoctorFixPlanErrorDoesNotLeakHandlerError(t *testing.T) {
	handler := &fakeDoctorFixHandler{
		id:      "fake.plan_error",
		planErr: errors.New("synthetic-secret-plan-body"),
	}
	setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{handler.id: handler})

	got := runDoctorFixFrameworkForTest(advertisedDoctorFixCheck(handler.id, true), doctorRunOptions{Fix: true})
	check := requireDoctorCheckStatus(t, got, "doctor.fix.safety_refused", doctorStatusBlocked)
	if check.Detail["safety_reason"] != "precondition" {
		t.Fatalf("safety_reason=%v", check.Detail["safety_reason"])
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	if strings.Contains(string(data), "synthetic-secret-plan-body") {
		t.Fatalf("plan error leaked into output:\n%s", string(data))
	}
}

func TestAwDoctorFixApplyErrorDoesNotLeakHandlerError(t *testing.T) {
	handler := &fakeDoctorFixHandler{
		id: "fake.apply_error",
		plan: doctorFixPlan{
			CheckID:   "fake.apply_error",
			Safe:      true,
			Authority: doctorAuthorityCaller,
			PlannedMutations: []doctorFixMutation{{
				Operation:   "write_metadata",
				Description: "write non-secret metadata",
				Path:        ".aw/workspace.yaml",
			}},
		},
		applyErr: errors.New("synthetic-secret-apply-body"),
	}
	setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{handler.id: handler})

	got := runDoctorFixFrameworkForTest(advertisedDoctorFixCheck(handler.id, true), doctorRunOptions{Fix: true})
	check := requireDoctorCheckStatus(t, got, "doctor.fix.failed", doctorStatusFail)
	if check.Detail["reason"] != "apply_failed" {
		t.Fatalf("reason=%v", check.Detail["reason"])
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("marshal output: %v", err)
	}
	if strings.Contains(string(data), "synthetic-secret-apply-body") {
		t.Fatalf("apply error leaked into output:\n%s", string(data))
	}
}

func TestAwDoctorFixHandlerRegistryCleanup(t *testing.T) {
	restore := setDoctorFixHandlersForTest(t, map[string]doctorFixHandler{
		"fake.cleanup": &fakeDoctorFixHandler{id: "fake.cleanup"},
	})
	if _, ok := doctorFixHandlers["fake.cleanup"]; !ok {
		t.Fatalf("fake handler was not installed")
	}
	restore()
	if _, ok := doctorFixHandlers["fake.cleanup"]; ok {
		t.Fatalf("fake handler leaked after cleanup")
	}
}

func TestAwDoctorLocalChecksValidEphemeralWorkspace(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, "https://app.example.com/api")

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--offline", "--json")
	if err != nil {
		t.Fatalf("doctor local failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceExists, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckCertificateSignature, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckSigningKeyMatchesCert, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityEphemeral, doctorStatusOK)
	if _, ok := doctorCheckByID(got, doctorCheckIdentityPersistent); ok {
		t.Fatalf("ephemeral workspace unexpectedly required persistent identity: %#v", got.Checks)
	}
}

func TestAwDoctorLocalChecksValidPersistentWorkspace(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor local failed: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceAwebURL, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceWorkspaceID, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckCertificateSignature, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityPersistent, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityDID, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityAddress, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityStableID, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityCustody, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityRegistryURL, doctorStatusOK)
	requireDoctorCheckStatus(t, got, doctorCheckRegistryCoherence, doctorStatusOK)
}

func TestAwDoctorLocalChecksCorruptWorkspaceYAML(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorWorkspaceYAML(t, tmp, "aweb_url: [\n")

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "--json")
	if err != nil {
		t.Fatalf("doctor should report corrupt workspace as checks: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	if got.Status != doctorStatusFail {
		t.Fatalf("status=%q", got.Status)
	}
	requireDoctorCheckStatus(t, got, doctorCheckWorkspaceParse, doctorStatusFail)
	requireDoctorCheckStatus(t, got, doctorCheckCertificateParse, doctorStatusBlocked)
}

func TestAwDoctorLocalChecksWorkspaceSemanticFailures(t *testing.T) {
	t.Parallel()

	bin, buildTmp := buildDoctorBinary(t)
	tests := []struct {
		name   string
		body   string
		checks map[string]doctorStatus
	}{
		{
			name: "missing active team",
			body: `aweb_url: https://app.example.com/api
memberships:
  - team_id: backend:example.com
    alias: mia
    workspace_id: ws-1
    cert_path: team-certs/backend__example.com.pem
`,
			checks: map[string]doctorStatus{
				doctorCheckWorkspaceParse:       doctorStatusOK,
				doctorCheckWorkspaceActiveTeam:  doctorStatusFail,
				doctorCheckWorkspaceMembership:  doctorStatusFail,
				doctorCheckWorkspaceWorkspaceID: doctorStatusBlocked,
				doctorCheckWorkspaceCertPath:    doctorStatusBlocked,
			},
		},
		{
			name: "active team not in memberships",
			body: `aweb_url: https://app.example.com/api
active_team: backend:missing.example.com
memberships:
  - team_id: backend:example.com
    alias: mia
    workspace_id: ws-1
    cert_path: team-certs/backend__example.com.pem
`,
			checks: map[string]doctorStatus{
				doctorCheckWorkspaceParse:      doctorStatusOK,
				doctorCheckWorkspaceActiveTeam: doctorStatusOK,
				doctorCheckWorkspaceMembership: doctorStatusFail,
				doctorCheckWorkspaceCertPath:   doctorStatusBlocked,
			},
		},
		{
			name: "missing cert path and workspace id",
			body: `aweb_url: https://app.example.com/api
active_team: backend:example.com
memberships:
  - team_id: backend:example.com
    alias: mia
`,
			checks: map[string]doctorStatus{
				doctorCheckWorkspaceParse:       doctorStatusOK,
				doctorCheckWorkspaceMembership:  doctorStatusOK,
				doctorCheckWorkspaceWorkspaceID: doctorStatusFail,
				doctorCheckWorkspaceCertPath:    doctorStatusFail,
				doctorCheckCertificateExists:    doctorStatusBlocked,
			},
		},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			tmp := filepath.Join(buildTmp, strings.ReplaceAll(tc.name, " ", "-"))
			if err := os.MkdirAll(tmp, 0o700); err != nil {
				t.Fatalf("mkdir case dir: %v", err)
			}
			writeDoctorWorkspaceYAML(t, tmp, tc.body)
			out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
			if err != nil {
				t.Fatalf("doctor should report workspace semantic issue as checks: %v\n%s", err, string(out))
			}
			got := decodeDoctorOutput(t, out)
			for id, status := range tc.checks {
				requireDoctorCheckStatus(t, got, id, status)
			}
		})
	}
}

func TestAwDoctorLocalChecksCorruptSigningKey(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	if err := os.WriteFile(awconfig.WorktreeSigningKeyPath(tmp), []byte("not a pem key\n"), 0o600); err != nil {
		t.Fatalf("write corrupt signing key: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor should report corrupt signing key as checks: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckSigningKeyParse, doctorStatusFail)
	requireDoctorCheckStatus(t, got, doctorCheckSigningKeyMatchesCert, doctorStatusBlocked)
}

func TestAwDoctorLocalChecksMissingCertificate(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	certPath := awconfig.TeamCertificatePath(tmp, resolvedTeamIDForTest("backend:example.com"))
	if err := os.Remove(certPath); err != nil {
		t.Fatalf("remove certificate: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor should report missing cert as checks: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckCertificateExists, doctorStatusFail)
	requireDoctorCheckStatus(t, got, doctorCheckCertificateParse, doctorStatusBlocked)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityPersistent, doctorStatusBlocked)
}

func TestAwDoctorLocalChecksSigningKeyCertificateDIDMismatch(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	wrongPub, wrongPriv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatalf("generate wrong key: %v", err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), wrongPriv); err != nil {
		t.Fatalf("overwrite signing key: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor should report did mismatch as checks: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	check := requireDoctorCheckStatus(t, got, doctorCheckSigningKeyMatchesCert, doctorStatusFail)
	if check.Detail["signing_key_did"] != awid.ComputeDIDKey(wrongPub) {
		t.Fatalf("mismatch detail did=%v", check.Detail["signing_key_did"])
	}
}

func TestAwDoctorLocalChecksPersistentMissingIdentity(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")
	if err := os.Remove(filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())); err != nil {
		t.Fatalf("remove identity: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor should report missing persistent identity as checks: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityPersistent, doctorStatusFail)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityParse, doctorStatusBlocked)
}

func TestAwDoctorLocalChecksCorruptEphemeralIdentityFails(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorEphemeralFixture(t, tmp, "https://app.example.com/api")
	if err := os.WriteFile(filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath()), []byte("did: [\n"), 0o600); err != nil {
		t.Fatalf("write corrupt identity: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor should report corrupt ephemeral identity as checks: %v\n%s", err, string(out))
	}
	got := decodeDoctorOutput(t, out)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityEphemeral, doctorStatusInfo)
	requireDoctorCheckStatus(t, got, doctorCheckIdentityParse, doctorStatusFail)
}

func TestAwDoctorOfflineLocalChecksDoNotContactNetwork(t *testing.T) {
	t.Parallel()

	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		http.Error(w, "doctor should not call network", http.StatusTeapot)
	}))
	t.Cleanup(server.Close)

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, server.URL)

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--offline", "--json")
	if err != nil {
		t.Fatalf("doctor local failed: %v\n%s", err, string(out))
	}
	if requests.Load() != 0 {
		t.Fatalf("offline local doctor contacted network %d times", requests.Load())
	}
}

func TestAwDoctorLocalOutputDoesNotLeakSecrets(t *testing.T) {
	t.Parallel()

	bin, tmp := buildDoctorBinary(t)
	writeDoctorPersistentFixture(t, tmp, "https://app.example.com/api")

	workspace, workspacePath, err := awconfig.LoadWorktreeWorkspaceFromDir(tmp)
	if err != nil {
		t.Fatalf("load workspace: %v", err)
	}
	workspace.APIKey = "secret-api-token"
	workspace.AwebURL = "https://user:pass@app.example.com/api?token=secret-query#secret-fragment"
	if err := awconfig.SaveWorktreeWorkspaceTo(workspacePath, workspace); err != nil {
		t.Fatalf("save workspace: %v", err)
	}
	identityPath := filepath.Join(tmp, awconfig.DefaultWorktreeIdentityRelativePath())
	identity, err := awconfig.LoadWorktreeIdentityFrom(identityPath)
	if err != nil {
		t.Fatalf("load identity: %v", err)
	}
	identity.RegistryURL = "https://reguser:regpass@registry.example.com/path?registry_token=secret-registry#registry-fragment"
	writeIdentityForTest(t, tmp, *identity)
	cert, err := awid.LoadTeamCertificate(awconfig.TeamCertificatePath(tmp, resolvedTeamIDForTest("backend:example.com")))
	if err != nil {
		t.Fatalf("load cert: %v", err)
	}

	out, err := runDoctorCLI(t, bin, tmp, "doctor", "local", "--json")
	if err != nil {
		t.Fatalf("doctor local failed: %v\n%s", err, string(out))
	}
	text := string(out)
	for _, secret := range []string{
		"secret-api-token",
		"BEGIN ED25519 PRIVATE KEY",
		cert.Signature,
		"user:pass",
		"token=secret-query",
		"secret-fragment",
		"reguser:regpass",
		"registry_token=secret-registry",
		"registry-fragment",
	} {
		if strings.Contains(text, secret) {
			t.Fatalf("doctor output leaked secret %q:\n%s", secret, text)
		}
	}
	if !strings.Contains(text, "https://app.example.com/api") || !strings.Contains(text, "https://registry.example.com/path") {
		t.Fatalf("doctor output did not include sanitized URL forms:\n%s", text)
	}
}
