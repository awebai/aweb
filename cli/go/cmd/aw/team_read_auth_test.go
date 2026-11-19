package main

import (
	"crypto/ed25519"
	"net/http"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The registry gates reads of a private team on a path-signature
// (awid_service/routes/teams.py _require_team_read_access). These tests drive
// the commands that read team state against the real registry, through a front
// that records each answer, so what is exercised is the signature the CLI
// actually puts on the wire and the message an operator gets when it cannot
// produce one.

// readAuthWorld is a real private team with an active "retiree" member, read
// through a recording front.
func readAuthWorld(t *testing.T) (*realCommandWorld, string, *registryRecording) {
	t.Helper()
	world := newRealCommandWorld(t)
	world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: didOf(newKey(t)), Alias: "retiree", IdentityScope: awid.IdentityModeLocal})
	origin, recording := world.recordRegistry(t)
	return world, origin, recording
}

// signersAndRefusals splits recorded answers into the signers the registry
// admitted and those it turned away from the private team.
func signersAndRefusals(answers []registryAnswer) (admitted, refused []string) {
	for _, answer := range answers {
		if answer.Status == http.StatusForbidden {
			refused = append(refused, answer.Signer)
		} else {
			admitted = append(admitted, answer.Signer)
		}
	}
	return admitted, refused
}

// seedTeamReadWorkspace makes a workspace directory holding an identity signing
// key and points the status command at registryURL. It returns the working
// directory and the workspace's key.
func seedTeamReadWorkspace(t *testing.T, registryURL string) (string, ed25519.PrivateKey) {
	t.Helper()
	resetTeamRemoveMemberGlobals(t)
	teamRemoveRegistryURL = registryURL
	t.Setenv("HOME", t.TempDir())
	t.Setenv(awconfig.IdentityHomeEnv, "")

	workingDir := t.TempDir()
	key := newKey(t)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), key); err != nil {
		t.Fatal(err)
	}
	return workingDir, key
}

// The read this task exists for: a workspace that is a member of a private team
// still gets its own certificate state, because the read is signed with the
// workspace's own key.
func TestAgentStatusReadsAPrivateTeamWithTheWorkspaceMemberKey(t *testing.T) {
	world, origin, recording := readAuthWorld(t)
	workingDir, workspaceKey := seedTeamReadWorkspace(t, origin)
	world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: didOf(workspaceKey), Alias: "operator", IdentityScope: awid.IdentityModeLocal})

	out := teamAgentStatusOutput{TeamID: world.TeamID, Alias: "retiree"}
	readAgentCertificateState(world.Context, &out, world.Domain, "backend", false,
		teamReadSigners(workingDir, world.Domain, "backend"))

	if out.Certificate != agentCertificateActive {
		t.Fatalf("certificate=%q, want %q; unreadable=%v", out.Certificate, agentCertificateActive, out.Unreadable)
	}
	if len(out.Unreadable) != 0 {
		t.Fatalf("unreadable=%v, want none", out.Unreadable)
	}
	admitted, refused := signersAndRefusals(recording.Answers())
	if len(refused) != 0 {
		t.Fatalf("the member key was refused %d time(s); it should have been admitted first", len(refused))
	}
	for _, did := range admitted {
		if did != didOf(workspaceKey) {
			t.Fatalf("a read was signed with %q, want the workspace key %q", did, didOf(workspaceKey))
		}
	}
}

// A controller machine whose own workspace identity holds no certificate still
// reads its team: the workspace key is tried first, refused, and the locally
// held team controller key is tried next.
func TestAgentStatusFallsBackToTheTeamControllerKeyOnAPrivateTeam(t *testing.T) {
	world, origin, recording := readAuthWorld(t)
	workingDir, workspaceKey := seedTeamReadWorkspace(t, origin)
	if err := awconfig.SaveTeamKey(world.Domain, "backend", world.TeamKey); err != nil {
		t.Fatal(err)
	}

	signers := teamReadSigners(workingDir, world.Domain, "backend")
	if len(signers) != 2 {
		t.Fatalf("got %d candidate keys, want the workspace key and the controller key", len(signers))
	}
	out := teamAgentStatusOutput{TeamID: world.TeamID, Alias: "retiree"}
	readAgentCertificateState(world.Context, &out, world.Domain, "backend", false, signers)

	if out.Certificate != agentCertificateActive {
		t.Fatalf("certificate=%q, want %q; unreadable=%v", out.Certificate, agentCertificateActive, out.Unreadable)
	}
	admitted, refused := signersAndRefusals(recording.Answers())
	if len(refused) != 1 || refused[0] != didOf(workspaceKey) {
		t.Fatalf("refused=%v, want exactly the workspace key %q turned away once", refused, didOf(workspaceKey))
	}
	for _, did := range admitted {
		if did != didOf(world.TeamKey) {
			t.Fatalf("a read was admitted for %q, want the controller key %q", did, didOf(world.TeamKey))
		}
	}
	// The member read must reuse the key the team read was admitted with rather
	// than walking the candidates again.
	if len(admitted) != 2 {
		t.Fatalf("admitted=%v, want the team read and the member read", admitted)
	}
}

// With no usable key the refusal has to arrive as an instruction, not as an
// HTTP status the operator has to interpret.
func TestAgentStatusExplainsAPrivateTeamItCannotSignFor(t *testing.T) {
	world, origin, recording := readAuthWorld(t)
	resetTeamRemoveMemberGlobals(t)
	teamRemoveRegistryURL = origin

	out := teamAgentStatusOutput{TeamID: world.TeamID, Alias: "retiree"}
	readAgentCertificateState(world.Context, &out, world.Domain, "backend", false, nil)

	if out.Certificate != agentCertificateUnknown {
		t.Fatalf("certificate=%q, want %q", out.Certificate, agentCertificateUnknown)
	}
	said := strings.Join(out.Unreadable, " ")
	for _, want := range []string{
		world.TeamID + " is private",
		"workspace holding a certificate for this team",
		"ask the team controller",
	} {
		if !strings.Contains(said, want) {
			t.Fatalf("unreadable=%q, want it to say %q", said, want)
		}
	}
	for _, unwanted := range []string{"403", "Forbidden", "team_private"} {
		if strings.Contains(said, unwanted) {
			t.Fatalf("unreadable=%q leaks the raw HTTP failure %q", said, unwanted)
		}
	}
	if _, refused := signersAndRefusals(recording.Answers()); len(refused) != 1 || refused[0] != "" {
		t.Fatalf("refused=%v, want one unsigned attempt", refused)
	}
}

// Public teams must be untouched: the same read stays anonymous and succeeds.
func TestAgentStatusReadsAPublicTeamAnonymouslyAsBefore(t *testing.T) {
	world, origin, recording := readAuthWorld(t)
	if _, err := world.Registry.SetTeamVisibility(world.Context, world.Stack.RegistryURL, world.Domain, "backend", "public", world.TeamKey); err != nil {
		t.Fatal(err)
	}
	resetTeamRemoveMemberGlobals(t)
	teamRemoveRegistryURL = origin

	out := teamAgentStatusOutput{TeamID: world.TeamID, Alias: "retiree"}
	readAgentCertificateState(world.Context, &out, world.Domain, "backend", false, nil)

	if out.Certificate != agentCertificateActive {
		t.Fatalf("certificate=%q, want %q; unreadable=%v", out.Certificate, agentCertificateActive, out.Unreadable)
	}
	admitted, refused := signersAndRefusals(recording.Answers())
	if len(refused) != 0 {
		t.Fatalf("refused=%v on a public team", refused)
	}
	for _, did := range admitted {
		if did != "" {
			t.Fatalf("a public-team read carried a signature from %q; anonymous behavior must be unchanged", did)
		}
	}
}

// The roster read is the other command an operator runs against a team they are
// in, so it has to sign too.
func TestTeamMembersListsAPrivateTeamWithTheWorkspaceMemberKey(t *testing.T) {
	world, origin, recording := readAuthWorld(t)
	resetTeamMembersGlobals(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(awconfig.IdentityHomeEnv, "")
	root := t.TempDir()
	t.Chdir(root)
	key := newKey(t)
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), key); err != nil {
		t.Fatal(err)
	}
	world.registerMemberCertificate(t, awid.TeamCertificateFields{MemberDIDKey: didOf(key), Alias: "alice", IdentityScope: awid.IdentityModeLocal})
	teamMembersTeamID = world.TeamID
	teamMembersRegistryURL = origin

	if err := runTeamMembers(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamMembers against a private team the workspace is a member of: %v", err)
	}
	if _, refused := signersAndRefusals(recording.Answers()); len(refused) != 0 {
		t.Fatalf("refused=%v; the workspace key should have been admitted", refused)
	}
}

// And when it cannot sign, it must say what to do rather than surface a 403.
func TestTeamMembersExplainsAPrivateTeamItCannotSignFor(t *testing.T) {
	world, origin, _ := readAuthWorld(t)
	resetTeamMembersGlobals(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(awconfig.IdentityHomeEnv, "")
	t.Chdir(t.TempDir())
	teamMembersTeamID = world.TeamID
	teamMembersRegistryURL = origin

	err := runTeamMembers(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("an unsigned roster read of a private team succeeded")
	}
	for _, want := range []string{
		world.TeamID + " is private",
		"workspace holding a certificate for this team",
		"ask the team controller",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not say %q", err, want)
		}
	}
	for _, unwanted := range []string{"403", "team_private", "list team members"} {
		if strings.Contains(err.Error(), unwanted) {
			t.Fatalf("error %q leaks the raw failure %q", err, unwanted)
		}
	}
}

// Key selection is what decides whether a private read can be signed at all, so
// its precedence and its exclusions are pinned here.
func TestTeamReadSignersPrecedenceAndHostedExclusion(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv(awconfig.IdentityHomeEnv, "")
	workingDir := t.TempDir()
	_, workspaceKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), workspaceKey); err != nil {
		t.Fatal(err)
	}
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("acme.com", "backend", teamKey); err != nil {
		t.Fatal(err)
	}

	signers := teamReadSigners(workingDir, "acme.com", "backend")
	if len(signers) != 2 || !signers[0].Equal(workspaceKey) || !signers[1].Equal(teamKey) {
		t.Fatalf("got %d signers; want the workspace key first and the team controller key second", len(signers))
	}

	// A hosted namespace has no local controller custody, so no controller
	// candidate may be offered for one even if a key file happens to exist.
	if err := awconfig.SaveTeamKey("aweb.ai", "backend", teamKey); err != nil {
		t.Fatal(err)
	}
	hosted := teamReadSigners(workingDir, "aweb.ai", "backend")
	if len(hosted) != 1 || !hosted[0].Equal(workspaceKey) {
		t.Fatalf("hosted namespace offered %d signers, want only the workspace key", len(hosted))
	}

	// A directory with no identity and no team key signs nothing, which is what
	// keeps public-team reads anonymous.
	if got := teamReadSigners(t.TempDir(), "other.com", "backend"); len(got) != 0 {
		t.Fatalf("got %d signers where no key exists, want none", len(got))
	}
}

// The retry walks candidates only for the visibility refusal. Any other failure
// is one failure, reported once.
func TestReadSignedTeamStateOnlyRetriesTheVisibilityRefusal(t *testing.T) {
	_, first, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	private := &awid.RegistryError{
		StatusCode: http.StatusForbidden,
		Code:       awid.RegistryCodeTeamPrivate,
		Detail:     `{"detail": {"code": "team_private"}}`,
	}

	attempts := 0
	key, err := readSignedTeamState([]ed25519.PrivateKey{first, second}, func(k ed25519.PrivateKey) error {
		attempts++
		if k.Equal(first) {
			return private
		}
		return nil
	})
	if err != nil || attempts != 2 || !key.Equal(second) {
		t.Fatalf("attempts=%d key-is-second=%t err=%v", attempts, key.Equal(second), err)
	}

	notFound := &awid.RegistryError{StatusCode: http.StatusNotFound, Detail: "Team member not found"}
	attempts = 0
	if _, err := readSignedTeamState([]ed25519.PrivateKey{first, second}, func(ed25519.PrivateKey) error {
		attempts++
		return notFound
	}); err != notFound || attempts != 1 {
		t.Fatalf("attempts=%d err=%v; a 404 must be returned from the first candidate", attempts, err)
	}

	attempts = 0
	if key, err := readSignedTeamState(nil, func(k ed25519.PrivateKey) error {
		attempts++
		if k != nil {
			t.Fatalf("an empty signer set signed with %v", k)
		}
		return nil
	}); err != nil || attempts != 1 || key != nil {
		t.Fatalf("attempts=%d key=%v err=%v; no candidates means one unsigned read", attempts, key, err)
	}
}
