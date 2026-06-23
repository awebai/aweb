//go:build e2e

// Full consumer learning-loop refresh against the real stack (default-aaas.14.8).
// A profile is adopted + materialized from the Library; a NEW version is minted on
// the team's PRIVATE shelf; `aw team refresh` re-materializes the member home from
// that new shelf version and `aw agent profile show` reflects it. The new shelf
// version stands in for the propose->approve outcome (the changeset's per-asset
// base digests make a full propose fiddly to build here; the refresh logic - read
// the latest shelf version via get-shelf-profile and re-materialize - is identical
// regardless of how the version was minted).
//
// This exercises Layers 1-3 end to end: the get-shelf-profile ?include=files
// endpoint, the manifest tool aw dispatches, and the aw-side refresh + ref-inspect.
package e2e

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealStackLibraryProfileRefreshPicksUpNewShelfVersion(t *testing.T) {
	requireE2E(t)
	bin := awBinary(t)

	root := realDir(t, t.TempDir())
	home := filepath.Join(root, "home")
	repo := filepath.Join(root, "repo")
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatalf("mkdir repo: %v", err)
	}
	installLibraryPlugin(t, home)
	gitInit(t, repo)

	// The get-shelf-profile call in mintNewShelfVersion below is the implicit
	// fail-fast: a stale/pre-deploy manifest lacking the verb errors there, before
	// the refresh, with a clear "unknown library verb".

	env := append(os.Environ(),
		"HOME="+home,
		"AWEB_URL="+awebURL(),
		"AWID_REGISTRY_URL="+awidURL(),
		"AWID_SKIP_DNS_VERIFY=1",
		"NO_COLOR=1",
	)
	awInRepo := func(args ...string) (string, error) {
		cmd := exec.Command(bin, args...)
		cmd.Dir = repo
		cmd.Env = env
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	// select + materialize: adopt profiles and materialize roster homes under
	// agents/instances/<name> (the proven roster shape; coordinator is the one we
	// refresh).
	if out, err := awInRepo("team", "create", "eng",
		"--profile", "aweb.engineering/coordinator=claude-code",
		"--profile", "aweb.engineering/reviewer=pi"); err != nil {
		t.Fatalf("aw team create --profile failed: %v\n%s", err, out)
	}

	// ref-inspect: the recorded profile ref before refresh.
	before := profileRefShow(t, awInRepo, "coordinator")
	if before.SourceBlueprintRef != "aweb.engineering" || before.ProfileRef != "coordinator" || before.ProfileVersion == "" {
		t.Fatalf("unexpected recorded ref before refresh: %+v", before)
	}

	// Mint a NEW shelf version (the approve outcome): re-use the current shelf
	// content, bump profile.yaml's version, and POST it as a new version. The shelf
	// content comes from the new get-shelf-profile content endpoint itself.
	newVersion := bumpProfileVersion(t, before.ProfileVersion)
	mintNewShelfVersion(t, awInRepo, "coordinator", newVersion)

	// refresh: re-materialize from the latest shelf version.
	if out, err := awInRepo("team", "refresh", "coordinator"); err != nil {
		t.Fatalf("aw team refresh failed: %v\n%s", err, out)
	}

	// ref-inspect again: the recorded ref now reflects the new shelf version.
	after := profileRefShow(t, awInRepo, "coordinator")
	if after.ProfileVersion == before.ProfileVersion {
		t.Fatalf("refresh did not pick up a new shelf version (still %s)", after.ProfileVersion)
	}
	if after.ProfileDigest == before.ProfileDigest {
		t.Fatalf("refresh kept the old profile digest %s; the new shelf version should change the content", after.ProfileDigest)
	}
	t.Logf("refresh picked up the new shelf version: %s@%s -> @%s", after.ProfileRef, before.ProfileVersion, after.ProfileVersion)
}

type e2eRecordedRef struct {
	ProfileDigest          string `json:"profile_digest"`
	ProfileRef             string `json:"profile_ref"`
	ProfileVersion         string `json:"profile_version"`
	SourceBlueprintRef     string `json:"source_blueprint_ref"`
	SourceBlueprintVersion string `json:"source_blueprint_version"`
}

func profileRefShow(t *testing.T, awInRepo func(...string) (string, error), name string) e2eRecordedRef {
	t.Helper()
	out, err := awInRepo("--json", "agent", "profile", "show", name)
	if err != nil {
		t.Fatalf("aw agent profile show %s failed: %v\n%s", name, err, out)
	}
	var ref e2eRecordedRef
	if err := json.Unmarshal([]byte(out), &ref); err != nil {
		t.Fatalf("aw agent profile show --json not an object: %v\n%s", err, out)
	}
	return ref
}

// mintNewShelfVersion reads the current shelf content (get-shelf-profile content),
// bumps the profile.yaml version, and posts it as a new shelf version via a signed
// team-auth request - the real path an approved proposal's mint takes.
func mintNewShelfVersion(t *testing.T, awInRepo func(...string) (string, error), profileRef, newVersion string) {
	t.Helper()
	out, err := awInRepo("library", "get-shelf-profile", "--profile_ref", profileRef, "--include", "files")
	if err != nil {
		t.Fatalf("aw library get-shelf-profile failed: %v\n%s", err, out)
	}
	var shelf struct {
		Files []map[string]any `json:"files"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &shelf); err != nil {
		t.Fatalf("get-shelf-profile response not JSON: %v\n%s", err, out)
	}
	if len(shelf.Files) == 0 {
		t.Fatalf("get-shelf-profile returned no files (Layer 1 ?include=files not serving?): %s", out)
	}
	swapped := false
	for _, f := range shelf.Files {
		if f["path"] == "profile.yaml" {
			content, _ := f["content_utf8"].(string)
			updated := swapYAMLVersion(content, newVersion)
			f["content_utf8"] = updated
			// The content changed, so its sha256 must be recomputed - the
			// materialize verifies each file's content against this hash.
			sum := sha256.Sum256([]byte(updated))
			f["sha256"] = "sha256:" + hex.EncodeToString(sum[:])
			swapped = true
		}
	}
	if !swapped {
		t.Fatalf("shelf content has no profile.yaml to bump: %v", shelf.Files)
	}

	bodyPath := filepath.Join(t.TempDir(), "shelf-version.json")
	body, _ := json.Marshal(map[string]any{"files": shelf.Files})
	if err := os.WriteFile(bodyPath, body, 0o644); err != nil {
		t.Fatal(err)
	}
	if out, err := awInRepo("id", "request", "POST",
		libraryURL()+"/v1/profiles/"+profileRef+"/versions", "--team-auth", "--raw", "--body-file", bodyPath); err != nil {
		t.Fatalf("mint shelf version failed: %v\n%s", err, out)
	}
}

func bumpProfileVersion(t *testing.T, v string) string {
	t.Helper()
	parts := strings.Split(strings.TrimSpace(v), ".")
	if len(parts) != 3 {
		return v + ".1"
	}
	// bump the patch deterministically without arithmetic edge cases
	return parts[0] + "." + parts[1] + ".99"
}

func swapYAMLVersion(content, newVersion string) string {
	lines := strings.Split(content, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "version:") {
			lines[i] = "version: " + newVersion
		}
	}
	return strings.Join(lines, "\n")
}
