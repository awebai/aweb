package teamblueprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeValidBlueprint(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "blueprint.yaml"), `schema_version: 1
id: engineering-dev-team
name: Engineering AI Team
version: 0.1.0
summary: Coordinate AI agents to ship code changes with review and audit.
profiles:
  - id: coordinator
    path: profiles/coordinator
    default_agent_name: coordinator
    role: coordinator
    purpose: Coordinates the team.
    default_count: 1
    min: 1
    max: 1
    runtime_options: [claude-code, codex]
recommended_apps: [messages, tasks]
approval_policy:
  require_human_approval: [github.merge_pr, secrets.read]
runtime_options:
  local: [claude-code, codex]
`)
	writeFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml"), `schema_version: 1
id: coordinator
name: Coordinator
version: 0.1.0
summary: Keeps the team moving.
runtime_hints:
  preferred: [claude-code]
accepts_work: [coordinate]
required_apps:
  tasks:
    scopes: [task:read, task:update]
  messages:
    scopes: [chat:send, mail:send]
subscriptions:
  - app: tasks
    event: task.assigned
approval_required: [secrets.read]
artifacts:
  - path: artifacts/scripts/status.sh
    kind: helper_script
`)
	writeFile(t, filepath.Join(root, "profiles/coordinator/instructions.md"), "Coordinate work.\n")
	writeFile(t, filepath.Join(root, "profiles/coordinator/artifacts/scripts/status.sh"), "#!/bin/sh\necho ok\n")
}

func TestLoadLocalDirValidatesAndPlansBlueprint(t *testing.T) {
	root := t.TempDir()
	writeValidBlueprint(t, root)

	bp, err := LoadLocalDir(root)
	if err != nil {
		t.Fatalf("LoadLocalDir returned error: %v", err)
	}
	if bp.Source.Kind != "local_dir" || !strings.HasPrefix(bp.Source.Digest, "sha256:") {
		t.Fatalf("unexpected source: %+v", bp.Source)
	}
	if len(bp.LoadedProfiles) != 1 || bp.LoadedProfiles[0].InstructionsPath != "profiles/coordinator/instructions.md" {
		t.Fatalf("profile not loaded: %+v", bp.LoadedProfiles)
	}

	plan := InspectPlan(bp)
	if plan.Blueprint.ID != "engineering-dev-team" {
		t.Fatalf("plan blueprint=%+v", plan.Blueprint)
	}
	if len(plan.Agents) != 1 || plan.Agents[0].DefaultAgentName != "coordinator" || plan.Agents[0].DefaultCount != 1 {
		t.Fatalf("unexpected agents: %+v", plan.Agents)
	}
	if len(plan.RequestedApps) != 2 {
		t.Fatalf("expected tasks/messages app requests, got %+v", plan.RequestedApps)
	}
	if len(plan.EventSubscriptions) != 1 || plan.EventSubscriptions[0].Event != "task.assigned" {
		t.Fatalf("unexpected subscriptions: %+v", plan.EventSubscriptions)
	}
	if len(plan.CodeArtifacts) != 1 || plan.CodeArtifacts[0].Path != "artifacts/scripts/status.sh" {
		t.Fatalf("unexpected artifacts: %+v", plan.CodeArtifacts)
	}
}

func TestLoadLocalDirRejectsRuntimeStateAndIdentityMaterial(t *testing.T) {
	cases := []struct {
		name string
		path string
		body string
		want string
	}{
		{name: "aw-state", path: ".aw/workspace.yaml", body: "team: default", want: ".aw runtime state"},
		{name: "private-key-file", path: "profiles/coordinator/id_ed25519", body: "x", want: "identity material"},
		{name: "secret-file", path: "profiles/coordinator/.env", body: "TOKEN=x", want: "identity material"},
		{name: "did-content", path: "profiles/coordinator/docs/identity.md", body: "did:key:z6Mkabc", want: "unexpected identity material"},
		{name: "generated-worktree", path: "agents/instances/dev/work/file.txt", body: "x", want: "generated worktrees"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeValidBlueprint(t, root)
			writeFile(t, filepath.Join(root, tc.path), tc.body)
			_, err := LoadLocalDir(root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadLocalDirRejectsUnsafePaths(t *testing.T) {
	cases := []struct {
		name string
		path string
		want string
	}{
		{name: "absolute", path: "/tmp/profile", want: "absolute paths"},
		{name: "traversal", path: "../profile", want: "path traversal"},
		{name: "scheme", path: "https://evil.example/profile", want: "host or scheme"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeValidBlueprint(t, root)
			writeFile(t, filepath.Join(root, "blueprint.yaml"), strings.ReplaceAll(`schema_version: 1
id: engineering-dev-team
name: Engineering AI Team
version: 0.1.0
summary: Coordinate AI agents.
profiles:
  - id: coordinator
    path: PROFILE_PATH
`, "PROFILE_PATH", tc.path))
			_, err := LoadLocalDir(root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadLocalDirRequiresProfileInstructions(t *testing.T) {
	root := t.TempDir()
	writeValidBlueprint(t, root)
	if err := os.Remove(filepath.Join(root, "profiles/coordinator/instructions.md")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadLocalDir(root)
	if err == nil || !strings.Contains(err.Error(), "instructions.md: required") {
		t.Fatalf("error=%v", err)
	}
}
