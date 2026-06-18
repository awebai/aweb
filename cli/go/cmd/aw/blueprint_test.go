package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeBlueprintFixture(t *testing.T, root string) {
	t.Helper()
	writeCmdTestFile(t, filepath.Join(root, "blueprint.yaml"), `schema_version: 1
id: engineering-dev-team
version: 0.1.0
display:
  name: Engineering AI Team
  summary: Coordinate AI agents to ship code changes with review and audit.
slots:
  - role: coordinator
    display:
      name: Coordinator
      summary: Coordinates work.
    profile_ref:
      id: coordinator
      version: 0.1.0
    default_agent_name: coordinator
    default_count: 1
    min: 1
    max: 1
    app_request_refs: [tasks.basic]
app_requests:
  tasks.basic:
    scopes: [task.read]
recommended_apps: [messages]
approval_policy:
  require_human_approval: [secrets.read]
runtime_options:
  local: [claude-code]
`)
	writeCmdTestFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml"), `schema_version: 1
id: coordinator
version: 0.1.0
display:
  name: Coordinator
  summary: Keeps the team moving.
runtime_hints:
  preferred: [claude-code]
required_apps:
  tasks:
    scopes: [task:read, task:update]
subscriptions:
  - app: tasks
    event: task.assigned
artifacts:
  - path: artifacts/scripts/status.sh
    kind: helper_script
`)
	writeCmdTestFile(t, filepath.Join(root, "profiles/coordinator/instructions.md"), "Coordinate work.\n")
	writeCmdTestFile(t, filepath.Join(root, "profiles/coordinator/artifacts/scripts/status.sh"), "#!/bin/sh\necho ok\n")
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
	blueprint := got["blueprint"].(map[string]any)
	if blueprint["id"] != "engineering-dev-team" {
		t.Fatalf("blueprint=%v", blueprint)
	}
	agents := got["agents"].([]any)
	if len(agents) != 1 || agents[0].(map[string]any)["default_agent_name"] != "coordinator" {
		t.Fatalf("agents=%v", agents)
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
	for _, want := range []string{"Blueprint: Engineering AI Team", "Agents:", "Requested apps/scopes:", "Event subscriptions:", "Files that would be written:", "Commands that would run: none", "Required human decisions:"} {
		if !strings.Contains(text, want) {
			t.Fatalf("human output missing %q:\n%s", want, text)
		}
	}
}

func TestBlueprintInspectRejectsUnsafeBlueprint(t *testing.T) {
	root := t.TempDir()
	writeBlueprintFixture(t, root)
	writeCmdTestFile(t, filepath.Join(root, ".aw/workspace.yaml"), "team: default\n")
	var out bytes.Buffer
	err := runBlueprintInspect(&out, root, true)
	if err == nil || !strings.Contains(err.Error(), ".aw runtime state") {
		t.Fatalf("error=%v", err)
	}
}

func TestBlueprintInspectRejectsRemoteSourcesForNow(t *testing.T) {
	for _, source := range []string{"https://github.com/awebai/example", "github.com/awebai/foo", "aweb/engineering-dev-team", "git@example.com:awebai/foo"} {
		t.Run(source, func(t *testing.T) {
			var out bytes.Buffer
			err := runBlueprintInspect(&out, source, true)
			if err == nil || !strings.Contains(err.Error(), "remote blueprint sources are not supported") {
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
