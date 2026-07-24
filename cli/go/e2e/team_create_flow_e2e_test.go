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
// This test bootstraps a unique BYOT namespace, so it does not contend with the
// refresh-flow test that exercises first-team creation in the shared "local"
// namespace.
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
	// Give this create flow its own BYOT namespace. Another e2e test exercises
	// local first-team creation in the same real stack; a unique namespace keeps
	// the tests independent instead of racing for the singleton `local` domain.
	namespace := "team-create-" + randSuffix(t) + ".test"
	bootstrap := filepath.Join(root, "bootstrap")
	if err := os.MkdirAll(bootstrap, 0o755); err != nil {
		t.Fatalf("mkdir bootstrap: %v", err)
	}
	idCreate := exec.Command(bin, "id", "create", "--domain", namespace, "--name", "owner", "--registry", awidURL(), "--skip-dns-verify")
	idCreate.Dir = bootstrap
	idCreate.Env = env
	if out, err := idCreate.CombinedOutput(); err != nil {
		t.Fatalf("bootstrap BYOT namespace controller failed: %v\noutput:\n%s", err, out)
	}

	cmd := exec.Command(bin, "team", "create", "eng", "--byot", "--namespace", namespace, "--registry", awidURL(),
		"--profile", seededBlueprintRef+"/coordinator=claude-code",
		"--profile", seededBlueprintRef+"/reviewer=pi")
	cmd.Dir = repo
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("aw team create --profile roster failed: %v\noutput:\n%s", err, out)
	}

	// Profile-only team add uses --blueprint + --library-url directly (no plugin)
	// and proves provider selection is a client-side URL, not shelf state.
	addCmd := exec.Command(bin, "team", "add", "developer@developer", "--blueprint", seededBlueprintRef, "--library-url", libraryURL(), "--runtime", "local-shell")
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

	// A forced local-key replacement must operate on the real home produced by
	// team add. Local homes intentionally have no identity.yaml; losing
	// signing.key must not make the recovery flow depend on a fixture-only file.
	developerHome := filepath.Join(repo, "agents", "instances", "developer")
	oldIdentityCmd := exec.Command(bin, "--json", "id", "show")
	oldIdentityCmd.Dir = developerHome
	oldIdentityCmd.Env = env
	oldIdentityOut, err := oldIdentityCmd.Output()
	if err != nil {
		t.Fatalf("show developer identity before replacement: %v", err)
	}
	var oldIdentity struct {
		DIDKey string `json:"did_key"`
	}
	if err := json.Unmarshal(oldIdentityOut, &oldIdentity); err != nil || oldIdentity.DIDKey == "" {
		t.Fatalf("decode old developer identity: %v\n%s", err, oldIdentityOut)
	}
	if _, err := os.Stat(filepath.Join(developerHome, ".aw", "identity.yaml")); !os.IsNotExist(err) {
		t.Fatalf("real local home unexpectedly has identity.yaml: %v", err)
	}
	oldEncryptionCmd := exec.Command(bin, "--json", "id", "encryption-key", "show")
	oldEncryptionCmd.Dir = developerHome
	oldEncryptionCmd.Env = env
	oldEncryptionOut, err := oldEncryptionCmd.Output()
	if err != nil {
		t.Fatalf("show developer E2E key before replacement: %v", err)
	}
	var oldEncryption struct {
		KeyID string `json:"key_id"`
	}
	if err := json.Unmarshal(oldEncryptionOut, &oldEncryption); err != nil || oldEncryption.KeyID == "" {
		t.Fatalf("decode old developer E2E key: %v\n%s", err, oldEncryptionOut)
	}
	if err := os.Remove(filepath.Join(developerHome, ".aw", "signing.key")); err != nil {
		t.Fatalf("simulate lost developer signing key: %v", err)
	}

	replaceCmd := exec.Command(bin, "--json", "team", "replace-key", "developer",
		"--old-did-key", oldIdentity.DIDKey,
		"--home", developerHome,
		"--generate-new-key",
		"--aweb-url", awebURL(),
		"--registry", awidURL())
	replaceCmd.Dir = repo
	replaceCmd.Env = env
	replaceOut, err := replaceCmd.CombinedOutput()
	if err != nil {
		t.Fatalf("replace key in real materialized local home: %v\n%s", err, replaceOut)
	}
	var replaced struct {
		NewDIDKey       string `json:"new_did_key"`
		SigningKeyPath  string `json:"signing_key_path"`
		CertificatePath string `json:"certificate_path"`
		EncryptionKeyID string `json:"encryption_key_id"`
	}
	if err := json.Unmarshal(replaceOut, &replaced); err != nil {
		t.Fatalf("decode replace-key output: %v\n%s", err, replaceOut)
	}
	if replaced.NewDIDKey == "" || replaced.NewDIDKey == oldIdentity.DIDKey || replaced.SigningKeyPath == "" || replaced.CertificatePath == "" || replaced.EncryptionKeyID == "" {
		t.Fatalf("incomplete replace-key output: %+v", replaced)
	}
	if replaced.EncryptionKeyID != oldEncryption.KeyID {
		t.Fatalf("replace-key rotated E2E key: got %s want preserved %s", replaced.EncryptionKeyID, oldEncryption.KeyID)
	}

	newIdentityCmd := exec.Command(bin, "--json", "id", "show")
	newIdentityCmd.Dir = developerHome
	newIdentityCmd.Env = env
	newIdentityOut, err := newIdentityCmd.Output()
	if err != nil {
		t.Fatalf("show developer identity after replacement: %v", err)
	}
	var newIdentity struct {
		DIDKey string `json:"did_key"`
	}
	if err := json.Unmarshal(newIdentityOut, &newIdentity); err != nil || newIdentity.DIDKey != replaced.NewDIDKey {
		t.Fatalf("replacement signing identity mismatch: got=%+v err=%v\n%s", newIdentity, err, newIdentityOut)
	}
	newCertCmd := exec.Command(bin, "--json", "id", "cert", "show")
	newCertCmd.Dir = developerHome
	newCertCmd.Env = env
	newCertOut, err := newCertCmd.Output()
	if err != nil {
		t.Fatalf("show replacement certificate: %v", err)
	}
	var newCertificate struct {
		MemberDIDKey string `json:"member_did_key"`
	}
	if err := json.Unmarshal(newCertOut, &newCertificate); err != nil || newCertificate.MemberDIDKey != replaced.NewDIDKey {
		t.Fatalf("replacement certificate mismatch: got=%+v err=%v\n%s", newCertificate, err, newCertOut)
	}

	doctorCmd := exec.Command(bin, "--json", "doctor")
	doctorCmd.Dir = developerHome
	doctorCmd.Env = env
	doctorOut, err := doctorCmd.Output()
	if err != nil {
		t.Fatalf("doctor after replacement: %v", err)
	}
	var doctor struct {
		Checks []struct {
			ID     string `json:"id"`
			Status string `json:"status"`
		} `json:"checks"`
	}
	if err := json.Unmarshal(doctorOut, &doctor); err != nil {
		t.Fatalf("decode doctor output: %v\n%s", err, doctorOut)
	}
	assertionReady := false
	for _, check := range doctor.Checks {
		if check.ID == "identity.e2ee.assertion" && check.Status == "ok" {
			assertionReady = true
		}
	}
	if !assertionReady {
		t.Fatalf("doctor did not confirm refreshed E2E assertion: %+v\n%s", doctor.Checks, doctorOut)
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
