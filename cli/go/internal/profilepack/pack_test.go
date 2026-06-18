package profilepack

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

func writeValidPack(t *testing.T, root string) {
	t.Helper()
	writeFile(t, filepath.Join(root, "pack.yaml"), `id: aweb.engineering-pack
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
runtime_hints: [claude-code, codex, pi]
expected_apps: [library, tasks, secrets, audit, github]
first_mission_examples:
  - Review this repo and propose a first implementation plan.
`)
	writeFile(t, filepath.Join(root, "README.md"), "# Engineering AI Team Starter Pack\n")
	writeFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml"), `id: coordinator
name: Coordinator
version: 0.1.0
mission: Coordinate the agent team and keep delivery unblocked.
accepted_work: [planning, coordination]
instructions: instructions.md
runtime_assumptions: [local shell, git checkout]
memory_policy:
  mode: reviewed-learning
expected_apps: [library, tasks]
event_subscriptions:
  - app: tasks
    event: task.assigned
approval_required: [secrets.read]
artifacts:
  - path: artifacts/status.sh
    kind: helper_script
skills:
  - path: skills/coordinate/SKILL.md
    kind: skill
`)
	writeFile(t, filepath.Join(root, "profiles/coordinator/instructions.md"), "Coordinate work.\n")
	writeFile(t, filepath.Join(root, "profiles/coordinator/artifacts/status.sh"), "#!/bin/sh\necho ok\n")
	writeFile(t, filepath.Join(root, "profiles/coordinator/skills/coordinate/SKILL.md"), "# Coordinate\n")
	writeFile(t, filepath.Join(root, "missions.yaml"), `missions:
  - id: first-plan
    title: First implementation plan
    summary: Review the repo and propose a plan.
`)
}

func TestLoadLocalDirValidatesAndPlansProfilePack(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)

	pack, err := LoadLocalDir(root)
	if err != nil {
		t.Fatalf("LoadLocalDir returned error: %v", err)
	}
	if pack.Source.Kind != "local_dir" || pack.Source.DigestScope != DigestScopeLocalImportPayload || !strings.HasPrefix(pack.Source.Digest, "sha256:") {
		t.Fatalf("unexpected source: %+v", pack.Source)
	}
	if len(pack.LoadedProfiles) != 1 || pack.LoadedProfiles[0].InstructionPath != "profiles/coordinator/instructions.md" {
		t.Fatalf("profile not loaded: %+v", pack.LoadedProfiles)
	}
	plan := InspectPlan(pack)
	if plan.ProfilePack.ID != "aweb.engineering-pack" || plan.ProfilePack.ExpectedAppsSemantics != "setup_hints_not_grants" {
		t.Fatalf("profile_pack=%+v", plan.ProfilePack)
	}
	if len(plan.Profiles) != 1 || plan.Profiles[0].Version != "0.1.0" || plan.Profiles[0].ExpectedAppsSemantics != "setup_hints_not_grants" {
		t.Fatalf("profiles=%+v", plan.Profiles)
	}
	if got := plan.Profiles[0].MaterializationPreview.InstructionsPath; got != "profiles/coordinator/instructions.md" {
		t.Fatalf("instructions path=%s", got)
	}
	if len(plan.Profiles[0].MaterializationPreview.Artifacts) != 1 || plan.Profiles[0].MaterializationPreview.Artifacts[0].ProfileID != "coordinator" {
		t.Fatalf("artifacts=%+v", plan.Profiles[0].MaterializationPreview.Artifacts)
	}
	if !plan.ImportPreview.OptionalLayer || !plan.ImportPreview.RequiresLibrarySubscription || !plan.ImportPreview.SeparateFutureStep || !plan.ImportPreview.WouldUploadOnImport || len(plan.ImportPreview.PayloadFiles) == 0 {
		t.Fatalf("import preview=%+v", plan.ImportPreview)
	}
	if len(plan.RequiredHumanDecisions) != 0 || len(plan.OptionalNextSteps) == 0 || !strings.Contains(strings.Join(plan.OptionalNextSteps, "\n"), "empty profiles") {
		t.Fatalf("Library/profile packs must be optional: required=%v optional=%v", plan.RequiredHumanDecisions, plan.OptionalNextSteps)
	}
	if len(plan.FilesWouldWrite) != 0 || len(plan.CommandsWouldRun) != 0 {
		t.Fatalf("inspect must not write/run: files=%v commands=%v", plan.FilesWouldWrite, plan.CommandsWouldRun)
	}
}

func TestLoadLocalDirRejectsRuntimeStateAndIdentityMaterial(t *testing.T) {
	cases := []struct{ name, path, body, want string }{
		{name: "aw-state", path: ".aw/workspace.yaml", body: "team: default", want: ".aw runtime state"},
		{name: "private-key", path: "profiles/coordinator/id_ed25519", body: "secret", want: "identity material"},
		{name: "token-file", path: "profiles/coordinator/token.txt", body: "secret", want: "identity material"},
		{name: "did-content", path: "profiles/coordinator/docs/identity.md", body: "did:key:z6Mkabc", want: "unexpected identity material"},
		{name: "generated-worktree", path: "generated-worktrees/coordinator/README.md", body: "generated", want: "generated worktrees"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeValidPack(t, root)
			writeFile(t, filepath.Join(root, tc.path), tc.body)
			_, err := LoadLocalDir(root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadLocalDirRejectsSymlink(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	outside := filepath.Join(t.TempDir(), "secret.txt")
	writeFile(t, outside, "secret")
	if err := os.Symlink(outside, filepath.Join(root, "profiles/coordinator/symlink")); err != nil {
		t.Fatal(err)
	}
	_, err := LoadLocalDir(root)
	if err == nil || !strings.Contains(err.Error(), "symlinks are not allowed") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadLocalDirRejectsUnsafeProfileIDsAndPaths(t *testing.T) {
	t.Run("unsafe profile id", func(t *testing.T) {
		root := t.TempDir()
		writeValidPack(t, root)
		writeFile(t, filepath.Join(root, "pack.yaml"), `id: aweb.engineering-pack
name: Engineering AI Team Starter Pack
version: 0.1.0
summary: Summary
description: Description
profiles:
  - id: ../evil
    default_count: 1
    min: 1
    max: 1
`)
		_, err := LoadLocalDir(root)
		if err == nil || !strings.Contains(err.Error(), "safe single path segment") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("unsafe instructions path", func(t *testing.T) {
		root := t.TempDir()
		writeValidPack(t, root)
		writeFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml"), strings.ReplaceAll(readFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml")), "instructions: instructions.md", "instructions: ../instructions.md"))
		_, err := LoadLocalDir(root)
		if err == nil || !strings.Contains(err.Error(), "path traversal") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestLoadLocalDirRejectsUnknownYAMLFieldsAndInvalidRanges(t *testing.T) {
	t.Run("unknown pack field", func(t *testing.T) {
		root := t.TempDir()
		writeValidPack(t, root)
		writeFile(t, filepath.Join(root, "pack.yaml"), `id: aweb.engineering-pack
name: Engineering AI Team Starter Pack
version: 0.1.0
summary: Summary
description: Description
profiles: []
app_grants: []
`)
		_, err := LoadLocalDir(root)
		if err == nil || !strings.Contains(err.Error(), "field app_grants not found") {
			t.Fatalf("error=%v", err)
		}
	})

	t.Run("invalid range", func(t *testing.T) {
		root := t.TempDir()
		writeValidPack(t, root)
		writeFile(t, filepath.Join(root, "pack.yaml"), `id: aweb.engineering-pack
name: Engineering AI Team Starter Pack
version: 0.1.0
summary: Summary
description: Description
profiles:
  - id: coordinator
    default_count: 3
    min: 1
    max: 2
`)
		_, err := LoadLocalDir(root)
		if err == nil || !strings.Contains(err.Error(), "min <= default_count <= max") {
			t.Fatalf("error=%v", err)
		}
	})
}

func TestLoadLocalDirExcludesVCSMetadataFromDigest(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	pack1, err := LoadLocalDir(root)
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(root, ".git/HEAD"), "ref: refs/heads/main\n")
	writeFile(t, filepath.Join(root, "node_modules/pkg/index.js"), "console.log('host local')\n")
	pack2, err := LoadLocalDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if pack1.Source.Digest != pack2.Source.Digest {
		t.Fatalf("digest should exclude VCS/dependency metadata: %s != %s", pack1.Source.Digest, pack2.Source.Digest)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
