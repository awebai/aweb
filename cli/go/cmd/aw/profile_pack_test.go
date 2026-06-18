package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeProfilePackFixture(t *testing.T, root string) {
	t.Helper()
	writeCmdTestFile(t, filepath.Join(root, "pack.yaml"), `id: aweb.engineering-pack
name: Engineering AI Team Starter Pack
version: 0.1.0
summary: Coordinator, developer, and reviewer profiles for repo work.
description: A starter profile pack for engineering teams.
profiles:
  - id: coordinator
    default_count: 1
    min: 1
    max: 1
runtime_hints: [claude-code]
expected_apps: [library, tasks]
first_mission_examples:
  - Review this repo and propose a first implementation plan.
`)
	writeCmdTestFile(t, filepath.Join(root, "README.md"), "# Engineering AI Team Starter Pack\n")
	writeCmdTestFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml"), `id: coordinator
name: Coordinator
version: 0.1.0
mission: Coordinate the team.
accepted_work: [coordination]
instructions: instructions.md
runtime_assumptions: [local shell]
memory_policy:
  mode: reviewed-learning
expected_apps: [tasks]
event_subscriptions:
  - app: tasks
    event: task.assigned
artifacts:
  - path: artifacts/status.sh
    kind: helper_script
`)
	writeCmdTestFile(t, filepath.Join(root, "profiles/coordinator/instructions.md"), "Coordinate work.\n")
	writeCmdTestFile(t, filepath.Join(root, "profiles/coordinator/artifacts/status.sh"), "#!/bin/sh\necho ok\n")
}

func writeCmdTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestProfilePackInspectJSONLocalDir(t *testing.T) {
	root := t.TempDir()
	writeProfilePackFixture(t, root)
	var out bytes.Buffer
	if err := runProfilePackInspect(&out, root, true); err != nil {
		t.Fatalf("inspect returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	pack := got["profile_pack"].(map[string]any)
	if pack["id"] != "aweb.engineering-pack" || pack["expected_apps_semantics"] != "setup_hints_not_grants" {
		t.Fatalf("profile_pack=%v", pack)
	}
	profiles := got["profiles"].([]any)
	if len(profiles) != 1 || profiles[0].(map[string]any)["id"] != "coordinator" {
		t.Fatalf("profiles=%v", profiles)
	}
	importPreview := got["import_preview"].(map[string]any)
	if importPreview["would_upload_on_import"] != true || importPreview["separate_future_step"] != true || importPreview["optional_layer"] != true || importPreview["requires_library_subscription"] != true {
		t.Fatalf("import_preview=%v", importPreview)
	}
	if required, ok := got["required_human_decisions"].([]any); !ok || len(required) != 0 {
		t.Fatalf("required_human_decisions=%v", got["required_human_decisions"])
	}
	optional := got["optional_next_steps"].([]any)
	if len(optional) == 0 || !strings.Contains(out.String(), "empty profiles") {
		t.Fatalf("optional_next_steps=%v", optional)
	}
	if !strings.Contains(out.String(), "sha256:") {
		t.Fatalf("expected digest in output: %s", out.String())
	}
}

func TestProfilePackInspectHumanPlan(t *testing.T) {
	root := t.TempDir()
	writeProfilePackFixture(t, root)
	var out bytes.Buffer
	if err := runProfilePackInspect(&out, root, false); err != nil {
		t.Fatalf("inspect returned error: %v", err)
	}
	text := out.String()
	for _, want := range []string{"Profile pack: Engineering AI Team Starter Pack", "Expected apps (setup hints, not grants):", "Profiles:", "Optional Library import preview (separate future step; inspect uploads nothing):", "Optional materialization preview (separate future step; inspect writes nothing):", "Files that would be written by inspect: none", "Commands that would run: none", "Required human decisions for inspect: none", "Optional next steps:", "continue with empty profiles"} {
		if !strings.Contains(text, want) {
			t.Fatalf("human output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Requested apps") || strings.Contains(text, "grants") && !strings.Contains(text, "not grants") {
		t.Fatalf("human output reintroduced grant language:\n%s", text)
	}
}

func TestProfilePackInspectRejectsUnsafePack(t *testing.T) {
	root := t.TempDir()
	writeProfilePackFixture(t, root)
	writeCmdTestFile(t, filepath.Join(root, ".aw/workspace.yaml"), "team: default\n")
	var out bytes.Buffer
	err := runProfilePackInspect(&out, root, true)
	if err == nil || !strings.Contains(err.Error(), ".aw runtime state") {
		t.Fatalf("error=%v", err)
	}
}

func TestProfilePackInspectRejectsFutureSourcesForNow(t *testing.T) {
	for _, source := range []string{"https://github.com/awebai/example", "github.com/awebai/foo", "aweb/engineering-pack", "git@example.com:awebai/foo", "library:aweb.engineering-pack"} {
		t.Run(source, func(t *testing.T) {
			var out bytes.Buffer
			err := runProfilePackInspect(&out, source, true)
			if err == nil || !strings.Contains(err.Error(), "profile-pack sources are not supported yet") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestProfilePackInspectMissingExplicitLocalDir(t *testing.T) {
	var out bytes.Buffer
	err := runProfilePackInspect(&out, filepath.Join(t.TempDir(), "missing"), true)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error=%v", err)
	}
}

func TestProfilePackInspectHumanOutputMatchesEngineeringFixture(t *testing.T) {
	fixture := engineeringProfilePackFixtureRoot(t)
	source := filepath.Join(fixture, "source")
	var out bytes.Buffer
	if err := runProfilePackInspect(&out, source, false); err != nil {
		t.Fatalf("inspect returned error: %v", err)
	}
	actual := strings.ReplaceAll(out.String(), source, "FIXTURE/source")
	expected, err := os.ReadFile(filepath.Join(fixture, "expected/inspect.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if actual != string(expected) {
		t.Fatalf("human inspect mismatch\nactual:\n%s\nexpected:\n%s", actual, string(expected))
	}
}

func engineeringProfilePackFixtureRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../test-vectors/profile-packs/engineering"))
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root: %v", err)
	}
	return root
}
