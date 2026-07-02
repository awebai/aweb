//go:build e2e

// Full self-hosted team-create-with-profile flow against the real stack
// (default-aabq.21). This is the flow aabq.3 had to scope around (Wall 2): on a
// self-hosted stack, `aw team create --profile` materialized homes but then
// aborted in the configure step (InjectAgentDocs) with aweb 403 "agent not
// connected", because roster members were given an awid certificate but never
// connected to the aweb server. With the aabq.21 fix (members connect to the
// service before configure), the whole flow works end to end.
//
// This drives the REAL aw binary and reaches the self-hosted Library through
// the public catalog URL directly. The Library plugin is deliberately not
// installed: default team materialization must not depend on shelf/plugin state.
//
// NOTE: `aw team create` uses the shared awid namespace "local", so this test
// needs a freshly-seeded stack (which `make -C cli e2e` provides). Re-running it
// against a stack that already has a "local" team conflicts by design.
package e2e

import (
	"bytes"
	"encoding/json"
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
	for _, dir := range []string{home, repo} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
	}
	gitInit(t, repo)

	env := append(os.Environ(),
		"HOME="+home,
		"AWEB_URL="+awebURL(),
		"AWID_REGISTRY_URL="+awidURL(),
		"AWEB_LIBRARY_URL="+libraryURL(),
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

	// Profile-only team add uses --blueprint + --library-url directly (no plugin)
	// and proves provider selection is a client-side URL, not shelf state.
	addCmd := exec.Command(bin, "team", "add", "developer@developer", "--blueprint", "aweb.engineering", "--library-url", libraryURL(), "--runtime", "local-shell")
	addCmd.Dir = repo
	addCmd.Env = env
	if out, err := addCmd.CombinedOutput(); err != nil {
		t.Fatalf("aw team add profile-only from public catalog failed: %v\noutput:\n%s", err, out)
	}

	// Homes materialize under agents/instances/<profile_ref or name>.
	for _, agent := range []string{"coordinator", "reviewer", "developer"} {
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

	// Server-side roster: aweb must actually hold the team, not just files on
	// disk. `aw workspace status` reads live coordination state from aweb; a
	// connect-but-not-configured bug (the Wall 2 failure this regresses) would
	// leave a member unregistered, so file existence alone is not enough.
	var statusOut, statusErr bytes.Buffer
	statusCmd := exec.Command(bin, "--json", "workspace", "status")
	statusCmd.Dir = filepath.Join(repo, "agents", "instances", "coordinator")
	statusCmd.Env = env
	statusCmd.Stdout = &statusOut
	statusCmd.Stderr = &statusErr
	if err := statusCmd.Run(); err != nil {
		t.Fatalf("aw workspace status from coordinator home failed: %v\nstdout:\n%s\nstderr:\n%s",
			err, statusOut.String(), statusErr.String())
	}
	var status struct {
		Workspace struct {
			Alias       string `json:"alias"`
			WorkspaceID string `json:"workspace_id"`
		} `json:"workspace"`
		Team []struct {
			Alias       string `json:"alias"`
			Role        string `json:"role"`
			WorkspaceID string `json:"workspace_id"`
		} `json:"team"`
	}
	if err := json.Unmarshal(statusOut.Bytes(), &status); err != nil {
		t.Fatalf("decode workspace status JSON: %v\noutput:\n%s", err, statusOut.String())
	}
	// Self (coordinator) carries an aweb-assigned workspace_id - it is connected.
	if status.Workspace.Alias != "coordinator" || status.Workspace.WorkspaceID == "" {
		t.Fatalf("coordinator not registered with aweb: workspace=%+v\noutput:\n%s",
			status.Workspace, statusOut.String())
	}
	// The reviewer is in aweb's team roster with its own workspace_id and role -
	// connected and configured, not merely materialized.
	reviewerConnected := false
	for _, w := range status.Team {
		if w.Alias == "reviewer" && w.Role == "reviewer" && w.WorkspaceID != "" {
			reviewerConnected = true
		}
	}
	if !reviewerConnected {
		t.Fatalf("reviewer missing/misconfigured in aweb team roster (connect-but-not-configured?); team=%+v\noutput:\n%s",
			status.Team, statusOut.String())
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
