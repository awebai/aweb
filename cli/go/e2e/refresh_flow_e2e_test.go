//go:build e2e

// Full consumer learning-loop refresh against the real stack (default-aaas.14.8).
// The real demo chain: a profile is adopted + materialized; the team improves it
// via an APPROVED proposal (a new shelf version is minted); `aw team refresh`
// re-materializes the member home from that new shelf version and `aw agent
// profile show` reflects it - so an agent picks up the team's own learning.
//
// This exercises Layers 1-3 end to end: refresh dispatches the get-shelf-profile
// manifest tool (Layer 2) against the ?include=files endpoint (Layer 1) and
// re-materializes (Layer 3).
//
// The proposal is submitted through the published Library plugin surface. The
// changeset body uses aweb.library.profile-asset-changeset.v1 and is carried by
// aw library propose --body-file, then approved before refresh.
package e2e

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestRealStackLibraryProfileRefreshPicksUpApprovedProposal(t *testing.T) {
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

	env := append(os.Environ(),
		"HOME="+home,
		"AWEB_URL="+awebURL(),
		"AWID_REGISTRY_URL="+awidURL(),
		"AWEB_LIBRARY_URL="+libraryURL(),
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
	// create + public materialize, then adopt the first agent's public pin onto
	// the private shelf so proposed/approved shelf mints compose with refresh.
	if out, err := awInRepo("team", "create", "eng",
		"--agent", "coordinator@"+seededBlueprintRef+"/coordinator=claude-code",
		"--agent", "reviewer@"+seededBlueprintRef+"/reviewer=pi"); err != nil {
		t.Fatalf("aw team create --agent failed: %v\n%s", err, out)
	}
	coordinatorHome := filepath.Join(repo, "agents", "instances", "coordinator")
	if out, err := awInRepo("team", "adopt", "coordinator", "--home", coordinatorHome); err != nil {
		t.Fatalf("aw team adopt failed: %v\n%s", err, out)
	}

	before := profileRefShow(t, awInRepo, "coordinator", "--home", coordinatorHome)
	if before.SourceBlueprintRef != seededBlueprintRef || before.ProfileRef != "coordinator" || before.ProfileVersion == "" {
		t.Fatalf("unexpected recorded ref before refresh: %+v", before)
	}

	// The team improves its profile: propose a new file asset, then approve it,
	// minting a new private-shelf version.
	marker := proposeApproveInstructionsChange(t, awInRepo)

	// refresh: re-materialize from the latest shelf version (the approved one).
	if out, err := awInRepo("team", "refresh", "coordinator", "--home", coordinatorHome); err != nil {
		t.Fatalf("aw team refresh failed: %v\n%s", err, out)
	}

	after := profileRefShow(t, awInRepo, "coordinator", "--home", coordinatorHome)
	if after.ProfileVersion == before.ProfileVersion {
		t.Fatalf("refresh did not pick up the approved version (still %s)", after.ProfileVersion)
	}
	if after.ProfileDigest == before.ProfileDigest {
		t.Fatalf("refresh kept the old profile digest %s; the approved proposal changed the content", after.ProfileDigest)
	}
	// The approved change is visible in the re-materialized instructions.
	instr, err := os.ReadFile(filepath.Join(coordinatorHome, ".aw", "profile", "instructions.md"))
	if err != nil {
		t.Fatalf("re-materialized instructions.md missing: %v", err)
	}
	if !strings.Contains(string(instr), marker) {
		t.Fatalf("refresh did not propagate the approved instructions change (marker %q absent):\n%s", marker, instr)
	}
	t.Logf("refresh picked up the approved proposal: %s@%s -> @%s", after.ProfileRef, before.ProfileVersion, after.ProfileVersion)
}

type e2eRecordedRef struct {
	ProfileDigest          string `json:"profile_digest"`
	ProfileRef             string `json:"profile_ref"`
	ProfileVersion         string `json:"profile_version"`
	SourceBlueprintRef     string `json:"source_blueprint_ref"`
	SourceBlueprintVersion string `json:"source_blueprint_version"`
}

func profileRefShow(t *testing.T, awInRepo func(...string) (string, error), name string, extraArgs ...string) e2eRecordedRef {
	t.Helper()
	args := append([]string{"--json", "agent", "profile", "show", name}, extraArgs...)
	out, err := awInRepo(args...)
	if err != nil {
		t.Fatalf("aw agent profile show %s failed: %v\n%s", name, err, out)
	}
	var ref e2eRecordedRef
	if err := json.Unmarshal([]byte(out), &ref); err != nil {
		t.Fatalf("aw agent profile show --json not an object: %v\n%s", err, out)
	}
	return ref
}

// proposeApproveInstructionsChange mints a new shelf version via the real
// propose->approve chain: a proposal that MODIFIES instructions.md (a materialized
// asset, so the change is visible in the home). A file asset's base_asset_digest
// is just its sha256, which get-shelf-profile --include files returns - so the
// changeset is self-contained without reimplementing the canonical asset hash.
// Returns the marker text the approved instructions must contain.
func proposeApproveInstructionsChange(t *testing.T, awInRepo func(...string) (string, error)) string {
	t.Helper()
	out, err := awInRepo("library", "get-shelf-profile", "--profile_ref", "coordinator", "--include", "files")
	if err != nil {
		t.Fatalf("aw library get-shelf-profile failed: %v\n%s", err, out)
	}
	var shelf struct {
		Files []map[string]string `json:"files"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &shelf); err != nil {
		t.Fatalf("get-shelf-profile response not JSON: %v\n%s", err, out)
	}
	var content, baseDigest string
	for _, f := range shelf.Files {
		if f["path"] == "instructions.md" {
			content, baseDigest = f["content_utf8"], f["sha256"]
		}
	}
	if baseDigest == "" {
		t.Fatalf("shelf content has no instructions.md to evolve: %v", shelf.Files)
	}

	marker := "Remember to re-test the refresh path after a proposal."
	changeset := map[string]any{
		"schema": "aweb.library.profile-asset-changeset.v1",
		"assets": []map[string]any{
			{"path": "instructions.md", "content_utf8": content + "\n\n" + marker + "\n", "base_asset_digest": baseDigest},
		},
	}
	bodyPath := filepath.Join(t.TempDir(), "proposal.json")
	data, _ := json.Marshal(map[string]any{
		"content":   changeset,
		"summary":   "sharpen coordinator instructions",
		"rationale": "exercise the documented profile evolution loop through the Library verb",
	})
	if err := os.WriteFile(bodyPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	out, err = awInRepo("library", "propose", "--target", "profile", "--profile_ref", "coordinator", "--body-file", bodyPath)
	if err != nil {
		t.Fatalf("aw library propose failed: %v\n%s", err, out)
	}
	var resp map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(out)), &resp); err != nil {
		t.Fatalf("aw library propose response not JSON: %v\n%s", err, out)
	}
	pid, _ := resp["proposal_id"].(string)
	if pid == "" {
		t.Fatal("propose returned no proposal_id")
	}
	if out, err := awInRepo("library", "approve", "--proposal_id", pid); err != nil {
		t.Fatalf("aw library approve failed: %v\n%s", err, out)
	}
	return marker
}
