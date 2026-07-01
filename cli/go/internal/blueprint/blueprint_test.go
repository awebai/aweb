package blueprint

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
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
Example placeholders: api_key: <value>, token=<value>, secret=<redacted>,
client_secret: <secret>, {"access_token":"<token>"}, {"api_key":""},
'api_key': '', "X-AWID-Team-Certificate": "", 'X-AWID-Team-Certificate': '',
and {"X-AWID-Team-Certificate":"<certificate>"}.

In prose, operators rotate the api_key when a teammate leaves, watch the
access_token and refresh_token expire, keep the client_secret and password in a
vault, and never paste a token or secret into chat - none of these keyword
mentions is a credential assignment, so the doc must load.
`)

	if _, err := LoadLocalDir(root); err != nil {
		t.Fatalf("identity concept documentation should load: %v", err)
	}
}

func TestLoadLocalDirAllowsCredentialKeywordProse(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	// Documentation prose that mentions the bare token/secret keywords must load:
	// the value is an English word, not a secret. Before aabq.28 the bare keyword
	// plus a 4+-char value rejected all of these, including the ones with terminal
	// prose punctuation. (aabq.28) (High-confidence keys like password are not
	// prose-exempt - see the reject coverage.)
	writeFile(t, filepath.Join(root, "profiles/coordinator/docs/auth-notes.md"), `# Auth notes

token: bearer authentication is required for the API.
secret: none is needed for the public read endpoints.
token: false disables the optional auth header.
secret: none.
token: false,
`)

	if _, err := LoadLocalDir(root); err != nil {
		t.Fatalf("credential-keyword documentation prose should load: %v", err)
	}
}

func TestLoadLocalDirRejectsBlockScalarCredential(t *testing.T) {
	// A credential smuggled into a YAML block scalar (key: | or key: > with the
	// value on the indented next line) must be caught: the inline-only scanner
	// missed it entirely because the value match stopped at the | indicator and
	// the indented value carried no keyword. (aabq.34, found probing aabq.32)
	cases := []struct{ name, path, body string }{
		{"literal-api-key", "profiles/coordinator/docs/bs-one.md", "api_key: |\n  aw_sk_live_secret_value\n"},
		{"folded-access-token", "profiles/coordinator/docs/bs-two.md", "access_token: >\n  ghp_realToken_AbC123\n"},
		{"literal-lowercase-password", "profiles/coordinator/docs/bs-three.md", "password: |\n  hunter2example\n"},
		{"chomped-bare-token-entropy", "profiles/coordinator/docs/bs-four.md", "token: |-\n  ghp_AbC123def\n"},
		{"nested-api-key", "profiles/coordinator/docs/bs-five.md", "config:\n  api_key: |\n    aw_sk_nested_value\n"},
		// The secret hides behind a placeholder/comment/prose first line - the
		// scanner must walk every block line, not just the first. (grace, aabq.34)
		{"placeholder-then-secret", "profiles/coordinator/docs/bs-six.md", "api_key: |\n  <placeholder>\n  aw_sk_real_secret_value\n"},
		{"comment-then-secret", "profiles/coordinator/docs/bs-seven.md", "api_key: |\n  # fill this in\n  aw_sk_real_secret_value\n"},
		{"prose-then-entropy-bare-token", "profiles/coordinator/docs/bs-eight.md", "token: |\n  bearer\n  ghp_AbC123def\n"},
		{"crlf-line-endings", "profiles/coordinator/docs/bs-nine.md", "api_key: |\r\n  aw_sk_crlf_secret_value\r\n"},
		// Quoted values and a leading secret with trailing text - the block value
		// extraction must match the inline path (strip quotes, first token even
		// with trailing text). (grace, aabq.34)
		{"double-quoted-api-key", "profiles/coordinator/docs/bs-ten.md", "api_key: |\n  \"aw_sk_real_secret_value\"\n"},
		{"single-quoted-api-key", "profiles/coordinator/docs/bs-eleven.md", "api_key: |\n  'aw_sk_real_secret_value'\n"},
		{"quoted-bare-token", "profiles/coordinator/docs/bs-twelve.md", "token: |\n  \"ghp_AbC123def\"\n"},
		{"secret-then-trailing-text", "profiles/coordinator/docs/bs-thirteen.md", "api_key: |\n  aw_sk_real_secret_value # copied from prod\n"},
		{"entropy-bare-token-trailing-text", "profiles/coordinator/docs/bs-fourteen.md", "token: |\n  ghp_AbC123def # from the vault\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeValidPack(t, root)
			writeFile(t, filepath.Join(root, tc.path), tc.body)
			if _, err := LoadLocalDir(root); err == nil || !strings.Contains(err.Error(), "unexpected identity material") {
				t.Fatalf("block-scalar credential should be rejected: err=%v", err)
			}
		})
	}
}

func TestLoadLocalDirRejectsBlockScalarLaterTokenSecret(t *testing.T) {
	// A known-shape secret as a NON-leading token on a block line (bullet/comment
	// style) must be caught: the prose-safe leading-token rule does not reach it,
	// so a narrow secret-shape predicate (known prefixes) covers it. (aabq.36)
	cases := []struct{ name, path, body string }{
		{"aw-sk-mid-line", "profiles/coordinator/docs/bs-lt-one.md", "api_key: |\n  use this aw_sk_real_secret_value\n"},
		{"ghp-bullet", "profiles/coordinator/docs/bs-lt-two.md", "token: |\n  - ghp_AbC123def456\n"},
		{"github-pat-mid-line", "profiles/coordinator/docs/bs-lt-three.md", "secret: |\n  rotate to github_pat_AbC123def456 today\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeValidPack(t, root)
			writeFile(t, filepath.Join(root, tc.path), tc.body)
			if _, err := LoadLocalDir(root); err == nil || !strings.Contains(err.Error(), "unexpected identity material") {
				t.Fatalf("later-token block-scalar secret should be rejected: err=%v", err)
			}
		})
	}
}

func TestLoadLocalDirAllowsBlockScalarPlaceholderAndProse(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	// Block-scalar placeholders, comments, and bare-keyword prose must still load:
	// a <...> placeholder is not material, a comment/prose line is multi-word
	// documentation, and a bare token/secret block whose value is an English word
	// is documentation, not a secret - including when several such lines stack in
	// one block (the shape that, with a real secret line, must be caught). (aabq.34)
	writeFile(t, filepath.Join(root, "profiles/coordinator/docs/bs-doc.md"), `# Block-scalar examples

api_key: |
  # fill this in with your key, e.g. from the dashboard
  <your-key-here>
token: |
  bearer authentication is required for the API
  see RFC7519 and version 1.2.3 for the token format
secret: >
  none is needed for the public read endpoints
`)

	if _, err := LoadLocalDir(root); err != nil {
		t.Fatalf("block-scalar placeholders/prose should load: %v", err)
	}
}

func TestLoadLocalDirAllowsPublicCryptoVectors(t *testing.T) {
	root := t.TempDir()
	writeValidPack(t, root)
	signature := "0YI14/N2Hjt+lgvKPAhIFsjgLxUEY5DuZWXycnTmyB5bWafvOFgXZe6XRzOzdLfPE+XUgX5Izo1IzwfsU9gpAQ"
	ciphertext := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("public ciphertext fixture bytes ", 3)))
	signedPayload := base64.URLEncoding.WithPadding(base64.NoPadding).EncodeToString([]byte(strings.Repeat("signed payload fixture bytes ", 3)))
	writeFile(t, filepath.Join(root, "profiles/coordinator/docs/signature-vector.md"), "signature_b64: "+signature+"\n")
	writeFile(t, filepath.Join(root, "profiles/coordinator/docs/ciphertext-vector.md"), "ciphertext_b64: "+ciphertext+"\n")
	writeFile(t, filepath.Join(root, "profiles/coordinator/docs/signed-payload-vector.md"), "signed_payload_b64url: "+signedPayload+"\n")

	if _, err := LoadLocalDir(root); err != nil {
		t.Fatalf("public crypto vectors should load: %v", err)
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
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	headerlessPrivateKey := base64.StdEncoding.EncodeToString(x509.MarshalPKCS1PrivateKey(privateKey))
	jwt := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZ2VudCIsImV4cCI6OTk5OTk5OTk5OX0.c2lnbmF0dXJlX3NlY3JldF9ibG9i"
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
		{name: "bare-token-assignment", path: "profiles/coordinator/docs/oauth-assignment.md", body: `token=secret_token_value`, want: "unexpected identity material"},
		{name: "bare-secret-assignment", path: "profiles/coordinator/docs/value-assignment.md", body: `secret=secret_value`, want: "unexpected identity material"},
		{name: "all-lowercase-api-key", path: "profiles/coordinator/docs/lc-one.md", body: `api_key=abcdefghijklmnop`, want: "unexpected identity material"},
		{name: "all-lowercase-access-token", path: "profiles/coordinator/docs/lc-two.md", body: `access_token=abcdefghijklmnop`, want: "unexpected identity material"},
		{name: "all-lowercase-client-secret", path: "profiles/coordinator/docs/lc-three.md", body: `client_secret=abcdefghijklmnop`, want: "unexpected identity material"},
		{name: "all-lowercase-password", path: "profiles/coordinator/docs/lc-four.md", body: `password=huntertwo`, want: "unexpected identity material"},
		{name: "client-secret-assignment", path: "profiles/coordinator/docs/client-oauth.md", body: `client_secret=secret_value`, want: "unexpected identity material"},
		{name: "team-certificate-header", path: "profiles/coordinator/docs/header.md", body: "X-AWID-Team-Certificate: abcdefghijklmnop", want: "unexpected identity material"},
		{name: "quoted-team-certificate-header", path: "profiles/coordinator/docs/header-json.md", body: `{"X-AWID-Team-Certificate":"abcdefghijklmnop"}`, want: "unexpected identity material"},
		{name: "quoted-team-certificate-header-spaced", path: "profiles/coordinator/docs/header-json-spaced.md", body: `"X-AWID-Team-Certificate" : "abcdefghijklmnop"`, want: "unexpected identity material"},
		{name: "single-quoted-team-certificate-header", path: "profiles/coordinator/docs/header-yaml-single.md", body: `'X-AWID-Team-Certificate': abcdefghijklmnop`, want: "unexpected identity material"},
		{name: "jwt-content", path: "profiles/coordinator/docs/jwt.md", body: jwt, want: "unexpected identity material"},
		{name: "headerless-private-key-blob", path: "profiles/coordinator/docs/blob.md", body: headerlessPrivateKey, want: "unexpected identity material"},
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

func TestLoadLocalDirRejectsNakedEd25519KeyBlobUnderEightyChars(t *testing.T) {
	// A 48-byte Ed25519 PKCS8 key base64-encodes to 64 chars, under the old
	// 80-char blob threshold. A naked headerless key on one line must still be
	// caught - the DER-parse gate keeps this from false-positiving. (aabq.28)
	seed := []byte{
		0x06, 0x46, 0x46, 0x09, 0x5f, 0xf3, 0xed, 0xcd,
		0x83, 0xfe, 0x49, 0x3d, 0xcb, 0x98, 0x6d, 0xc5,
		0x77, 0x71, 0x04, 0x2c, 0x31, 0x1a, 0x22, 0x2f,
		0x6d, 0x6f, 0x41, 0x2b, 0xce, 0xd8, 0x41, 0x3f,
	}
	priv := ed25519.NewKeyFromSeed(seed)
	pkcs8, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	blob := base64.StdEncoding.EncodeToString(pkcs8)
	if len(blob) >= 80 {
		t.Fatalf("expected a sub-80-char blob to exercise the lowered threshold, got %d chars", len(blob))
	}
	if !strings.HasSuffix(blob, "/") {
		t.Fatalf("test fixture must exercise a non-word base64 edge, got %q", blob)
	}

	root := t.TempDir()
	writeValidPack(t, root)
	writeFile(t, filepath.Join(root, "profiles/coordinator/docs/naked-key.md"), blob+"\n")
	if _, err := LoadLocalDir(root); err == nil || !strings.Contains(err.Error(), "unexpected identity material") {
		t.Fatalf("a naked Ed25519 PKCS8 key blob should be rejected: err=%v", err)
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
