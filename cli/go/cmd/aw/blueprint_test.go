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

func writeBlueprintFixture(t *testing.T, root string) {
	t.Helper()
	writeCmdTestFile(t, filepath.Join(root, "blueprint.yaml"), `id: aweb.engineering
name: Engineering AI Team Starter Blueprint
version: 0.1.0
summary: Coordinator, developer, and reviewer profiles for repo work.
description: A starter blueprint for engineering teams.
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
	writeCmdTestFile(t, filepath.Join(root, "README.md"), "# Engineering AI Team Starter Blueprint\n")
	writeCmdTestFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml"), `id: coordinator
name: Coordinator
version: 0.1.0
mission: Coordinate the team.
accepted_work: [coordination]
instructions: instructions.md
runtime_assumptions: [local shell]
memory_policy:
  mode: reviewed-learning
  proposal_target: library
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

func TestBlueprintInspectJSONLocalDir(t *testing.T) {
	root := t.TempDir()
	writeBlueprintFixture(t, root)
	var out bytes.Buffer
	if err := runBlueprintInspect(&out, root, true); err != nil {
		t.Fatalf("inspect returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	bp := got["blueprint"].(map[string]any)
	if bp["id"] != "aweb.engineering" || bp["expected_apps_semantics"] != "setup_hints_not_grants" {
		t.Fatalf("blueprint=%v", bp)
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

func TestBlueprintInspectHumanPlan(t *testing.T) {
	root := t.TempDir()
	writeBlueprintFixture(t, root)
	var out bytes.Buffer
	if err := runBlueprintInspect(&out, root, false); err != nil {
		t.Fatalf("inspect returned error: %v", err)
	}
	text := out.String()
	for _, want := range []string{"Blueprint: Engineering AI Team Starter Blueprint", "Expected apps (setup hints, not grants):", "Profiles:", "Optional Library import preview (separate future step; inspect uploads nothing):", "Optional materialization preview (separate future step; inspect writes nothing):", "Files that would be written by inspect: none", "Commands that would run: none", "Required human decisions for inspect: none", "Optional next steps:", "continue with empty profiles"} {
		if !strings.Contains(text, want) {
			t.Fatalf("human output missing %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Requested apps") || strings.Contains(text, "grants") && !strings.Contains(text, "not grants") {
		t.Fatalf("human output reintroduced grant language:\n%s", text)
	}
}

func TestBlueprintInspectRejectsUnsafePack(t *testing.T) {
	root := t.TempDir()
	writeBlueprintFixture(t, root)
	writeCmdTestFile(t, filepath.Join(root, ".aw/workspace.yaml"), "team: default\n")
	var out bytes.Buffer
	err := runBlueprintInspect(&out, root, true)
	if err == nil || !strings.Contains(err.Error(), ".aw runtime state") {
		t.Fatalf("error=%v", err)
	}
}

func TestBlueprintInspectRejectsFutureSourcesForNow(t *testing.T) {
	for _, source := range []string{"https://github.com/awebai/example", "github.com/awebai/foo", "aweb/engineering", "git@example.com:awebai/foo", "library:aweb.engineering"} {
		t.Run(source, func(t *testing.T) {
			var out bytes.Buffer
			err := runBlueprintInspect(&out, source, true)
			if err == nil || !strings.Contains(err.Error(), "blueprint sources are not supported yet") {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestBlueprintInspectMissingExplicitLocalDir(t *testing.T) {
	var out bytes.Buffer
	err := runBlueprintInspect(&out, filepath.Join(t.TempDir(), "missing"), true)
	if err == nil || !strings.Contains(err.Error(), "not found") {
		t.Fatalf("error=%v", err)
	}
}

func TestBlueprintMaterializeWritesExpectedHome(t *testing.T) {
	fixture := engineeringBlueprintFixtureRoot(t)
	target := t.TempDir()
	var out bytes.Buffer
	if err := runBlueprintMaterialize(&out, filepath.Join(fixture, "source"), "reviewer", target, false, false); err != nil {
		t.Fatalf("materialize returned error: %v", err)
	}
	text := out.String()
	for _, want := range []string{"Materialized profile reviewer@0.1.0", "Profile digest: sha256:", "Files written:", ".aw/profile/ref.json", "instructions.md", "skills/review/SKILL.md", "artifacts/review-template.md"} {
		if !strings.Contains(text, want) {
			t.Fatalf("materialize output missing %q:\n%s", want, text)
		}
	}
}

func TestBlueprintMaterializeJSON(t *testing.T) {
	fixture := engineeringBlueprintFixtureRoot(t)
	target := t.TempDir()
	var out bytes.Buffer
	if err := runBlueprintMaterialize(&out, filepath.Join(fixture, "source"), "coordinator", target, false, true); err != nil {
		t.Fatalf("materialize returned error: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(out.Bytes(), &got); err != nil {
		t.Fatalf("invalid json: %v\n%s", err, out.String())
	}
	if got["profile_ref"] != "coordinator" || got["source_blueprint_ref"] != "aweb.engineering" {
		t.Fatalf("json=%v", got)
	}
}

func TestBlueprintInspectHumanOutputMatchesEngineeringFixture(t *testing.T) {
	fixture := engineeringBlueprintFixtureRoot(t)
	source := filepath.Join(fixture, "source")
	var out bytes.Buffer
	if err := runBlueprintInspect(&out, source, false); err != nil {
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

func engineeringBlueprintFixtureRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "../../../../test-vectors/blueprints/engineering"))
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("fixture root: %v", err)
	}
	return root
}
