package main

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
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
	check, ok := doctorCheckByID(got, "local.workspace_binding.contract")
	if !ok {
		t.Fatalf("missing local workspace placeholder check: %#v", got.Checks)
	}
	if check.Status != doctorStatusInfo {
		t.Fatalf("local status=%q", check.Status)
	}
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
		"local.workspace_binding.contract",
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

func TestAwDoctorScopedCategoryPlaceholder(t *testing.T) {
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
		if _, ok := doctorCheckByID(got, "registry.contract.v1"); !ok {
			t.Fatalf("missing registry placeholder: %#v", got.Checks)
		}
		if _, ok := doctorCheckByID(got, "local.workspace_binding.contract"); ok {
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
	check, ok := doctorCheckByID(got, "doctor.fix.not_implemented")
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
