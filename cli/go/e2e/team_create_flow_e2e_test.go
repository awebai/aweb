//go:build e2e

// Full self-hosted team-create-with-profile flow against the real stack
// (default-aabq.21). This is the flow aabq.3 had to scope around (Wall 2): on a
// self-hosted stack, `aw team create --profile` materialized homes but then
// aborted in the configure step (InjectAgentDocs) with aweb 403 "agent not
// connected", because roster members were given an awid certificate but never
// connected to the aweb server. With the aabq.21 fix (members connect to the
// service before configure), the whole flow works end to end.
//
// Like the materialize suite, this drives the REAL aw binary and uses the
// library-manifest fixture to reach the self-hosted Library (aabq.20).
//
// NOTE: `aw team create` uses the shared awid namespace "local", so this test
// needs a freshly-seeded stack (which `make -C cli e2e` provides). Re-running it
// against a stack that already has a "local" team conflicts by design.
package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestRealStackTeamCreateRosterMaterializesAndConnects regresses aabq.21: a
// self-hosted `aw team create` adopting two profiles materializes both homes -
// which only completes if each roster member is connected to the aweb server
// before its coordination-docs are injected.
func TestRealStackTeamCreateRosterMaterializesAndConnects(t *testing.T) {
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
		"AWID_SKIP_DNS_VERIFY=1",
		"NO_COLOR=1",
	)
	cmd := exec.Command(bin, "team", "create", "eng",
		"--profile", "aweb.engineering/coordinator=claude-code",
		"--profile", "aweb.engineering/reviewer=pi")
	cmd.Dir = repo
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("aw team create --profile roster failed: %v\noutput:\n%s", err, out)
	}

	// Both homes materialize under agents/instances/<profile_ref>.
	for _, agent := range []string{"coordinator", "reviewer"} {
		base := filepath.Join(repo, "agents", "instances", agent)
		for _, rel := range []string{"AGENTS.md", ".aw/profile/profile.yaml", ".aw/profile/ref.json"} {
			if _, err := os.Lstat(filepath.Join(base, filepath.FromSlash(rel))); err != nil {
				t.Fatalf("%s home missing %s: %v", agent, rel, err)
			}
		}
	}

	// Runtime selection: claude-code gets a CLAUDE.md symlink, pi does not.
	if _, err := os.Readlink(filepath.Join(repo, "agents", "instances", "coordinator", "CLAUDE.md")); err != nil {
		t.Errorf("coordinator (claude-code) missing CLAUDE.md symlink: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(repo, "agents", "instances", "reviewer", "CLAUDE.md")); !os.IsNotExist(err) {
		t.Errorf("reviewer (pi) unexpectedly has CLAUDE.md (stat err=%v)", err)
	}
}

func gitInit(t *testing.T, dir string) {
	t.Helper()
	for _, args := range [][]string{
		{"init", "-q"},
		{"-c", "user.email=e2e@example.com", "-c", "user.name=e2e", "commit", "-q", "--allow-empty", "-m", "init"},
	} {
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
}
