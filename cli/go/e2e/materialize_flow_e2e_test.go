//go:build e2e

// Tight regression net for the three Library materialize bugs (default-aabq.3),
// driven by the real aw binary against the real seeded Library + awid:
//
//	.3.22  shelf-adopt idempotency  - re-adopting an already-shelved profile
//	       succeeds and is a no-op (created:false), never a conflict.
//	.3.24  folded-block-scalar mission - the reviewer profile, whose mission is
//	       a YAML folded block scalar, round-trips through Library intact and
//	       materializes into a valid home (the compose joins the folded lines).
//	.3.23  materialize atomicity - a materialize that fails leaves no partial
//	       home on disk.
//
// SCOPE NOTE (see the escalation on default-aabq.3): the four bugs live in
// applyLibraryProfileToHome -> MaterializeLibraryProfilePayload, but no aw
// command invokes that path and stops before the aweb "configure" step
// (InjectAgentDocs), which hard-requires an aweb-server connection the
// self-hosted stack does not have - that coupling is filed as default-aabq.21.
// So each bug is driven at the finest real-binary granularity that exercises
// the same behavior without the aweb step:
//   - .3.22 via `aw library import-to-shelf` (the real Library adopt path);
//   - .3.24 via `aw library get-profile` (Library round-trip) + `aw blueprint
//     materialize` (the local compose, which shares the folded-scalar parsing);
//   - .3.23 via `aw blueprint materialize` of a broken blueprint.
//
// The server-side member-cert dimension of .3.23 is coupled to the same aweb
// step (the roster path configures each member as it goes) and is left to
// default-aabq.21; documented here, not silently dropped.
//
// Reaching Library at all needs the library plugin pointed at the stack origin.
// The committed Library manifest hardcodes origin https://library.aweb.ai and
// `aw plugin install` enforces origin/fetch-URL self-consistency, so a
// self-hosted Library cannot be installed normally (filed as default-aabq.20).
// installLibraryPluginFixture works around that for the test only by writing the
// served manifest with its origin rewritten to the stack URL. When aabq.20 is
// fixed (Library serves origin = its public origin), this fixture is deleted and
// the test installs the manifest the real way.
package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// httpGet fetches a URL and returns the body, failing the test on error.
func httpGet(t *testing.T, url string) ([]byte, error) {
	t.Helper()
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

// teamHome returns the HOME the throwaway team runs under (where its aw state,
// including the library plugin, lives).
func teamHome(t *testing.T, tm *e2eTeam) string {
	t.Helper()
	// The team env is os.Environ()+overrides, so HOME appears twice (the outer
	// home, then the team's). The aw subprocess sees the last one win; match it.
	home := ""
	for _, kv := range tm.env {
		if strings.HasPrefix(kv, "HOME=") {
			home = strings.TrimPrefix(kv, "HOME=")
		}
	}
	if home == "" {
		t.Fatal("team env has no HOME")
	}
	return home
}

// installLibraryPluginFixture makes the library app dispatch to the stack.
//
// FIXTURE for default-aabq.20: it fetches the manifest the stack actually
// serves, rewrites app.origin to the stack URL (so dispatch and the install
// self-consistency rule agree), and writes it straight into the plugin dir -
// bypassing `aw plugin install`, which would reject the hardcoded production
// origin. Delete this once aabq.20 lets Library serve a self-hosted origin.
func installLibraryPluginFixture(t *testing.T, tm *e2eTeam) {
	t.Helper()
	resp, err := httpGet(t, libraryURL()+"/aweb-app.json")
	if err != nil {
		t.Fatalf("fetch library manifest: %v", err)
	}
	var manifest map[string]any
	if err := json.Unmarshal(resp, &manifest); err != nil {
		t.Fatalf("decode library manifest: %v\n%s", err, resp)
	}
	app, ok := manifest["app"].(map[string]any)
	if !ok {
		t.Fatalf("library manifest has no app object: %s", resp)
	}
	app["origin"] = libraryURL()
	rewritten, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("re-encode library manifest: %v", err)
	}
	dir := filepath.Join(teamHome(t, tm), ".aw", "plugins", "library")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir plugin dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), rewritten, 0o644); err != nil {
		t.Fatalf("write plugin manifest: %v", err)
	}
}

// library runs an installed-manifest library verb through the real binary and
// returns stdout (the JSON response body). `--json` is a global flag and must
// precede the dispatched app name, or it would be read as the verb.
func (tm *e2eTeam) library(t *testing.T, args ...string) string {
	t.Helper()
	return tm.run(t, append([]string{"--json", "library"}, args...)...)
}

// resolvePackDir resolves the engineering blueprint source (../blueprints/
// engineering), preferring LIBRARY_E2E_BLUEPRINT_SRC, then the sibling of the
// repo (resolving the main repo from a worktree via git --git-common-dir).
func resolvePackDir(t *testing.T) string {
	t.Helper()
	if v := strings.TrimSpace(os.Getenv("LIBRARY_E2E_BLUEPRINT_SRC")); v != "" {
		return v
	}
	// The test package lives at <repo>/cli/go/e2e; the repo root is three up.
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatalf("resolve repo root: %v", err)
	}
	if dir := filepath.Join(repoRoot, "..", "blueprints", "engineering"); isDir(dir) {
		return dir
	}
	if common, err := exec.Command("git", "-C", repoRoot, "rev-parse", "--git-common-dir").Output(); err == nil {
		mainRepo := filepath.Dir(strings.TrimSpace(string(common)))
		if !filepath.IsAbs(mainRepo) {
			mainRepo = filepath.Join(repoRoot, mainRepo)
		}
		if dir := filepath.Join(mainRepo, "..", "blueprints", "engineering"); isDir(dir) {
			return dir
		}
	}
	t.Skip("blueprint pack source not found; set LIBRARY_E2E_BLUEPRINT_SRC")
	return ""
}

func isDir(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.IsDir()
}

// realDir resolves symlinks; `aw blueprint materialize` refuses a target whose
// parent is a symlink (e.g. /tmp on macOS).
func realDir(t *testing.T, path string) string {
	t.Helper()
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatalf("eval symlinks %s: %v", path, err)
	}
	return resolved
}

// TestRealStackShelfAdoptIsIdempotent regresses .3.22: importing the reviewer
// profile to the team shelf is created the first time and a no-op the second,
// driven through the real binary against the real Library.
func TestRealStackShelfAdoptIsIdempotent(t *testing.T) {
	requireE2E(t)
	tm := newThrowawayTeam(t)
	installLibraryPluginFixture(t, tm)

	first := tm.library(t, "import-to-shelf",
		"--source_blueprint_ref", "aweb.engineering", "--profile_ref", "reviewer")
	firstShelf := decodeShelf(t, first)
	if !firstShelf.Created {
		t.Fatalf("first import-to-shelf created=false, want true: %s", first)
	}

	second := tm.library(t, "import-to-shelf",
		"--source_blueprint_ref", "aweb.engineering", "--profile_ref", "reviewer")
	secondShelf := decodeShelf(t, second)
	if secondShelf.Created {
		t.Fatalf("re-import created=true, want false (idempotent no-op): %s", second)
	}
	if secondShelf.Digest != firstShelf.Digest {
		t.Fatalf("re-import digest changed: %q -> %q", firstShelf.Digest, secondShelf.Digest)
	}
}

type shelfResponse struct {
	ProfileRef string `json:"profile_ref"`
	Digest     string `json:"digest"`
	Created    bool   `json:"created"`
}

func decodeShelf(t *testing.T, body string) shelfResponse {
	t.Helper()
	var out shelfResponse
	if err := json.Unmarshal([]byte(strings.TrimSpace(body)), &out); err != nil {
		t.Fatalf("decode import-to-shelf response: %v\n%s", err, body)
	}
	if out.ProfileRef == "" || out.Digest == "" {
		t.Fatalf("import-to-shelf response missing profile_ref/digest: %s", body)
	}
	return out
}

// The reviewer mission is a YAML folded block scalar (`mission: >-`); these are
// the joined first words the materialized prose must contain.
const reviewerMissionText = "Give independent, fresh-eyes review of a change before it merges"

// TestRealStackFoldedScalarMissionMaterializes regresses .3.24: the reviewer
// profile's folded-block-scalar mission round-trips through the real Library and
// materializes into a valid home with the mission composed into AGENTS.md.
func TestRealStackFoldedScalarMissionMaterializes(t *testing.T) {
	requireE2E(t)
	tm := newThrowawayTeam(t)
	installLibraryPluginFixture(t, tm)

	// Library round-trip: the served profile carries the folded mission intact.
	profile := tm.library(t, "get-profile",
		"--blueprint_ref", "aweb.engineering", "--profile_ref", "reviewer")
	if !strings.Contains(profile, reviewerMissionText) {
		t.Fatalf("library get-profile reviewer missing folded mission text %q; got:\n%s",
			reviewerMissionText, profile)
	}

	// Compose: materializing the reviewer joins the folded mission into AGENTS.md.
	pack := resolvePackDir(t)
	target := filepath.Join(realDir(t, t.TempDir()), "reviewer")
	tm.run(t, "blueprint", "materialize", pack, "--profile", "reviewer", "--target", target)

	agents, err := os.ReadFile(filepath.Join(target, "AGENTS.md"))
	if err != nil {
		t.Fatalf("materialized reviewer AGENTS.md missing: %v", err)
	}
	if !strings.Contains(string(agents), reviewerMissionText) {
		t.Fatalf("materialized AGENTS.md missing folded mission text %q", reviewerMissionText)
	}
}

// TestRealStackMaterializeFailureLeavesNoPartialState regresses .3.23: a
// materialize that fails leaves no partial home behind. (The server-side
// member-cert dimension of .3.23 is coupled to the aweb configure step and is
// filed as default-aabq.21; see the file header.)
func TestRealStackMaterializeFailureLeavesNoPartialState(t *testing.T) {
	requireE2E(t)
	tm := newThrowawayTeam(t)

	// A structurally invalid blueprint: materialize must reject it and write
	// nothing. (Missing required top-level fields; aw validates before writing.)
	broken := filepath.Join(realDir(t, t.TempDir()), "broken-blueprint")
	if err := os.MkdirAll(filepath.Join(broken, "profiles", "dev"), 0o755); err != nil {
		t.Fatalf("mkdir broken blueprint: %v", err)
	}
	writeFile(t, filepath.Join(broken, "blueprint.yaml"),
		"id: broken.test\nname: Broken\nversion: 0.0.1\n")
	writeFile(t, filepath.Join(broken, "profiles", "dev", "profile.yaml"),
		"id: dev\nname: dev\nversion: 0.0.1\nmission: A mission.\naccepted_work: [x]\ninstructions: instructions.md\n")

	target := filepath.Join(realDir(t, t.TempDir()), "out")
	_, stderr, err := tm.exec("blueprint", "materialize", broken, "--profile", "dev", "--target", target)
	if err == nil {
		t.Fatalf("materialize of a broken blueprint unexpectedly succeeded")
	}
	if _, statErr := os.Stat(target); !os.IsNotExist(statErr) {
		t.Fatalf("materialize failure left partial state at %s (stat err=%v); stderr:\n%s",
			target, statErr, stderr)
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}
