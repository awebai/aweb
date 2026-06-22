package blueprint

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
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
	writeFile(t, filepath.Join(root, "blueprint.yaml"), `id: aweb.engineering
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
runtime_hints: [claude-code, codex, pi]
expected_apps: [library, tasks, secrets, audit, github]
first_mission_examples:
  - Review this repo and propose a first implementation plan.
`)
	writeFile(t, filepath.Join(root, "README.md"), "# Engineering AI Team Starter Blueprint\n")
	writeFile(t, filepath.Join(root, "profiles/coordinator/profile.yaml"), `id: coordinator
name: Coordinator
version: 0.1.0
mission: Coordinate the agent team and keep delivery unblocked.
accepted_work: [planning, coordination]
instructions: instructions.md
runtime_assumptions: [local shell, git checkout]
memory_policy:
  mode: reviewed-learning
  proposal_target: library
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

func TestLoadLocalDirAllowsFoldedBlockFreeText(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	profilePath := filepath.Join(root, "profiles/coordinator/profile.yaml")
	body := readFile(t, profilePath)
	body = strings.Replace(body, "mission: Coordinate the agent team and keep delivery unblocked.", "mission: >\n  Coordinate the agent team across multiple lines\n  and keep delivery unblocked.", 1)
	body = strings.Replace(body, "accepted_work: [planning, coordination]", "accepted_work:\n  - >\n    planning work across multiple lines\n    with a trailing folded newline\n  - coordination", 1)
	writeFile(t, profilePath, body)

	bp, err := LoadLocalDir(root)
	if err != nil {
		t.Fatalf("LoadLocalDir: %v", err)
	}
	if got := bp.LoadedProfiles[0].Mission; !strings.Contains(got, "multiple lines") || !strings.HasSuffix(got, "\n") {
		t.Fatalf("mission=%q, want folded block scalar with trailing LF", got)
	}
}

func TestLoadLocalDirAllowsIdentityConceptDocumentation(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	writeFile(t, filepath.Join(root, "profiles/coordinator/docs/identity.md"), `# Identity concepts

The operations profile explains awid, did:key:, did:aw:, did:key:<value>,
did:aw:<stable-id>, private key custody, the api_key field, access_token
and team_certificate field names, and the X-AWID-Team-Certificate header
without embedding live identity material.
Example placeholders: api_key: <value>, {"access_token":"<token>"},
{"api_key":""}, 'api_key': '', "X-AWID-Team-Certificate": "",
'X-AWID-Team-Certificate': '', and {"X-AWID-Team-Certificate":"<certificate>"}.
`)

	if _, err := LoadLocalDir(root); err != nil {
		t.Fatalf("identity concept documentation should load: %v", err)
	}
}

func TestLoadLocalDirRejectsGenuineControlsInFreeText(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	profilePath := filepath.Join(root, "profiles/coordinator/profile.yaml")
	body := strings.Replace(readFile(t, profilePath), "mission: Coordinate the agent team and keep delivery unblocked.", `mission: "Coordinate \x80 team"`, 1)
	writeFile(t, profilePath, body)

	_, err := LoadLocalDir(root)
	if err == nil || !strings.Contains(err.Error(), "profile.yaml:mission: control characters are not allowed") {
		t.Fatalf("error=%v", err)
	}
}

func TestLoadLocalDirValidatesAndPlansBlueprint(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)

	bp, err := LoadLocalDir(root)
	if err != nil {
		t.Fatalf("LoadLocalDir returned error: %v", err)
	}
	if bp.Source.Kind != "local_dir" || bp.Source.DigestScope != DigestScopeLocalImportPayload || !strings.HasPrefix(bp.Source.Digest, "sha256:") {
		t.Fatalf("unexpected source: %+v", bp.Source)
	}
	if len(bp.LoadedProfiles) != 1 || bp.LoadedProfiles[0].InstructionPath != "profiles/coordinator/instructions.md" {
		t.Fatalf("profile not loaded: %+v", bp.LoadedProfiles)
	}
	plan := InspectPlan(bp)
	if plan.Blueprint.ID != "aweb.engineering" || plan.Blueprint.ExpectedAppsSemantics != "setup_hints_not_grants" {
		t.Fatalf("blueprint=%+v", plan.Blueprint)
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
		t.Fatalf("Library/blueprints must be optional: required=%v optional=%v", plan.RequiredHumanDecisions, plan.OptionalNextSteps)
	}
	if len(plan.FilesWouldWrite) != 0 || len(plan.CommandsWouldRun) != 0 {
		t.Fatalf("inspect must not write/run: files=%v commands=%v", plan.FilesWouldWrite, plan.CommandsWouldRun)
	}
}

func TestLoadLocalDirRejectsRuntimeStateAndIdentityMaterial(t *testing.T) {
	pub, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	didKey := awid.ComputeDIDKey(pub)
	cases := []struct{ name, path, body, want string }{
		{name: "aw-state", path: ".aw/workspace.yaml", body: "team: default", want: ".aw runtime state"},
		{name: "private-key", path: "profiles/coordinator/id_ed25519", body: "secret", want: "identity material"},
		{name: "token-file", path: "profiles/coordinator/token.txt", body: "secret", want: "identity material"},
		{name: "real-pem-content", path: "profiles/coordinator/docs/pem-example.md", body: "-----BEGIN ED25519 PRIVATE KEY-----\nsecret\n-----END ED25519 PRIVATE KEY-----\n", want: "unexpected identity material"},
		{name: "real-did-key-content", path: "profiles/coordinator/docs/identity.md", body: didKey, want: "unexpected identity material"},
		{name: "real-did-aw-content", path: "profiles/coordinator/docs/stable.md", body: "did:aw:2TdFnyW1MyzkH5x8Q3hM7Pgx98Mn", want: "unexpected identity material"},
		{name: "api-key-assignment", path: "profiles/coordinator/docs/api.md", body: "api_key=aw_sk_secret_value", want: "unexpected identity material"},
		{name: "quoted-api-key-assignment", path: "profiles/coordinator/docs/api-json.md", body: `{"api_key":"aw_sk_secret_value"}`, want: "unexpected identity material"},
		{name: "quoted-api-key-spaced-assignment", path: "profiles/coordinator/docs/api-json-spaced.md", body: `"api_key" : "aw_sk_secret_value"`, want: "unexpected identity material"},
		{name: "single-quoted-api-key-assignment", path: "profiles/coordinator/docs/api-yaml-single.md", body: `'api_key': aw_sk_secret_value`, want: "unexpected identity material"},
		{name: "yaml-quoted-api-key-assignment", path: "profiles/coordinator/docs/api-yaml-double.md", body: `"api_key": aw_sk_secret_value`, want: "unexpected identity material"},
		{name: "quoted-access-token-assignment", path: "profiles/coordinator/docs/oauth-json.md", body: `{"access_token":"secret_token_value"}`, want: "unexpected identity material"},
		{name: "team-certificate-header", path: "profiles/coordinator/docs/header.md", body: "X-AWID-Team-Certificate: abcdefghijklmnop", want: "unexpected identity material"},
		{name: "quoted-team-certificate-header", path: "profiles/coordinator/docs/header-json.md", body: `{"X-AWID-Team-Certificate":"abcdefghijklmnop"}`, want: "unexpected identity material"},
		{name: "quoted-team-certificate-header-spaced", path: "profiles/coordinator/docs/header-json-spaced.md", body: `"X-AWID-Team-Certificate" : "abcdefghijklmnop"`, want: "unexpected identity material"},
		{name: "single-quoted-team-certificate-header", path: "profiles/coordinator/docs/header-yaml-single.md", body: `'X-AWID-Team-Certificate': abcdefghijklmnop`, want: "unexpected identity material"},
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

func TestLoadLocalDirRejectsInvalidMemoryPolicy(t *testing.T) {
	cases := []struct {
		name string
		old  string
		new  string
		want string
	}{
		{
			name: "missing mode",
			old:  "memory_policy:\n  mode: reviewed-learning\n  proposal_target: library",
			new:  "memory_policy:\n  proposal_target: library",
			want: "memory_policy.mode: required",
		},
		{
			name: "missing proposal target",
			old:  "memory_policy:\n  mode: reviewed-learning\n  proposal_target: library",
			new:  "memory_policy:\n  mode: reviewed-learning",
			want: "memory_policy.proposal_target: required",
		},
		{
			name: "non-string mode",
			old:  "mode: reviewed-learning",
			new:  "mode: [reviewed-learning]",
			want: "memory_policy.mode: must be a string",
		},
		{
			name: "non-string proposal target",
			old:  "proposal_target: library",
			new:  "proposal_target: [library]",
			want: "memory_policy.proposal_target: must be a string",
		},
		{
			name: "control char mode",
			old:  "mode: reviewed-learning",
			new:  "mode: \"reviewed-learning\\n## Inject\"",
			want: "memory_policy.mode: control characters are not allowed",
		},
		{
			name: "control char proposal target",
			old:  "proposal_target: library",
			new:  "proposal_target: \"library\\n## Inject\"",
			want: "memory_policy.proposal_target: control characters are not allowed",
		},
		{
			name: "host proposal target",
			old:  "proposal_target: library",
			new:  "proposal_target: https://library.example/profile",
			want: "memory_policy.proposal_target: host or scheme refs are not allowed",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeValidPack(t, root)
			path := filepath.Join(root, "profiles/coordinator/profile.yaml")
			body := readFile(t, path)
			if !strings.Contains(body, tc.old) {
				t.Fatalf("test setup: profile.yaml does not contain %q", tc.old)
			}
			writeFile(t, path, strings.Replace(body, tc.old, tc.new, 1))
			_, err := LoadLocalDir(root)
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error=%v, want %q", err, tc.want)
			}
		})
	}
}

func TestLoadLocalDirRejectsUnsafeProfileIDsAndPaths(t *testing.T) {
	t.Run("unsafe profile id", func(t *testing.T) {
		root := t.TempDir()
		writeValidPack(t, root)
		writeFile(t, filepath.Join(root, "blueprint.yaml"), `id: aweb.engineering
name: Engineering AI Team Starter Blueprint
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
	t.Run("unknown blueprint field", func(t *testing.T) {
		root := t.TempDir()
		writeValidPack(t, root)
		writeFile(t, filepath.Join(root, "blueprint.yaml"), `id: aweb.engineering
name: Engineering AI Team Starter Blueprint
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
		writeFile(t, filepath.Join(root, "blueprint.yaml"), `id: aweb.engineering
name: Engineering AI Team Starter Blueprint
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
