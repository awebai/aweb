package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"github.com/spf13/cobra"
)

// The registry gates reads of a private team on a path-signature
// (awid_service/routes/teams.py _require_team_read_access). These tests drive
// the commands that read team state against a fake registry enforcing that gate
// the way the service does, so what is exercised is the signature the CLI
// actually puts on the wire and the message an operator gets when it cannot
// produce one.

// privateTeamRegistry is a fake registry for backend:acme.com behind the
// visibility gate. It records every read attempt so a test can tell a read that
// was admitted from one that was refused and retried under another key.
type privateTeamRegistry struct {
	t *testing.T

	visibility string
	teamDID    string
	memberDIDs map[string]bool
	alias      string

	server *httptest.Server

	// admitted holds the did:key of every read the gate let through, refused
	// the did:key of every signed read it turned away ("" for an unsigned one).
	admitted []string
	refused  []string
}

func newPrivateTeamRegistry(t *testing.T, teamDID string, memberDIDs []string, alias string) *privateTeamRegistry {
	t.Helper()
	fake := &privateTeamRegistry{
		t:          t,
		visibility: "private",
		teamDID:    teamDID,
		memberDIDs: map[string]bool{},
		alias:      alias,
	}
	for _, did := range memberDIDs {
		fake.memberDIDs[did] = true
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serve))
	t.Cleanup(fake.server.Close)
	return fake
}

func (f *privateTeamRegistry) serve(w http.ResponseWriter, r *http.Request) {
	did, signed := f.verifyPathSignature(r)
	admit := f.visibility == "public" || (signed && (did == f.teamDID || f.memberDIDs[did]))
	if !admit {
		f.refused = append(f.refused, did)
		w.WriteHeader(http.StatusForbidden)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"detail": map[string]any{
				"code": "team_private",
				"message": "Team is private; reads require a same-team signed request " +
					"or the trusted service token",
			},
		})
		return
	}
	f.admitted = append(f.admitted, did)
	switch r.URL.Path {
	case "/v1/namespaces/acme.com/teams/backend":
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id": "backend:acme.com", "domain": "acme.com", "name": "backend",
			"team_did_key": f.teamDID, "visibility": f.visibility,
		})
	case "/v1/namespaces/acme.com/teams/backend/certificates":
		_ = json.NewEncoder(w).Encode(map[string]any{"certificates": []map[string]any{{
			"certificate_id": "cert-" + f.alias, "team_id": "backend:acme.com",
			"member_did_key": "did:key:z6MkMember", "member_address": "acme.com/" + f.alias,
			"alias": f.alias, "identity_scope": "global", "issued_at": "2026-08-01T00:00:00Z",
		}}})
	case "/v1/namespaces/acme.com/teams/backend/members/" + f.alias:
		_ = json.NewEncoder(w).Encode(map[string]any{
			"team_id": "backend:acme.com", "certificate_id": "cert-" + f.alias,
			"member_did_key": "did:key:z6MkMember", "member_address": "acme.com/" + f.alias,
			"alias": f.alias, "identity_scope": "global", "issued_at": "2026-08-01T00:00:00Z",
		})
	default:
		f.t.Errorf("unexpected registry request %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusNotFound)
	}
}

// verifyPathSignature mirrors _verify_path_signature: a DIDKey Authorization
// header, a timestamp inside the skew window, and an Ed25519 signature over
// "timestamp\nMETHOD\npath".
func (f *privateTeamRegistry) verifyPathSignature(r *http.Request) (string, bool) {
	parts := strings.Fields(r.Header.Get("Authorization"))
	if len(parts) != 3 || parts[0] != "DIDKey" {
		return "", false
	}
	timestamp := strings.TrimSpace(r.Header.Get("X-AWEB-Timestamp"))
	parsed, err := time.Parse(time.RFC3339, timestamp)
	if err != nil {
		return "", false
	}
	if delta := time.Since(parsed); delta > 5*time.Minute || delta < -5*time.Minute {
		return "", false
	}
	pub, err := awid.ExtractPublicKey(parts[1])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawStdEncoding.DecodeString(parts[2])
	if err != nil {
		return "", false
	}
	if !ed25519.Verify(pub, []byte(timestamp+"\n"+r.Method+"\n"+r.URL.Path), sig) {
		return "", false
	}
	return parts[1], true
}

// seedTeamReadWorkspace makes a workspace directory holding an identity signing
// key and points the status command at fake. It returns the working directory
// and the workspace's did:key.
func seedTeamReadWorkspace(t *testing.T, fake *privateTeamRegistry) (string, string) {
	t.Helper()
	resetTeamRemoveMemberGlobals(t)
	teamRemoveRegistryURL = fake.server.URL
	t.Setenv("HOME", t.TempDir())
	t.Setenv(awconfig.IdentityHomeEnv, "")

	workingDir := t.TempDir()
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(workingDir), priv); err != nil {
		t.Fatal(err)
	}
	return workingDir, awid.ComputeDIDKey(pub)
}

// The read this task exists for: a workspace that is a member of a private team
// still gets its own certificate state, because the read is signed with the
// workspace's own key.
func TestAgentStatusReadsAPrivateTeamWithTheWorkspaceMemberKey(t *testing.T) {
	fake := newPrivateTeamRegistry(t, "did:key:z6MkNotUsed", nil, "retiree")
	workingDir, workspaceDID := seedTeamReadWorkspace(t, fake)
	fake.memberDIDs[workspaceDID] = true

	out := teamAgentStatusOutput{TeamID: "backend:acme.com", Alias: "retiree"}
	readAgentCertificateState(context.Background(), &out, "acme.com", "backend", false,
		teamReadSigners(workingDir, "acme.com", "backend"))

	if out.Certificate != agentCertificateActive {
		t.Fatalf("certificate=%q, want %q; unreadable=%v", out.Certificate, agentCertificateActive, out.Unreadable)
	}
	if len(out.Unreadable) != 0 {
		t.Fatalf("unreadable=%v, want none", out.Unreadable)
	}
	if len(fake.refused) != 0 {
		t.Fatalf("the member key was refused %d time(s); it should have been admitted first", len(fake.refused))
	}
	for _, did := range fake.admitted {
		if did != workspaceDID {
			t.Fatalf("a read was signed with %q, want the workspace key %q", did, workspaceDID)
		}
	}
}

// A controller machine whose own workspace identity holds no certificate still
// reads its team: the workspace key is tried first, refused, and the locally
// held team controller key is tried next.
func TestAgentStatusFallsBackToTheTeamControllerKeyOnAPrivateTeam(t *testing.T) {
	_, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDID := awid.ComputeDIDKey(teamKey.Public().(ed25519.PublicKey))
	fake := newPrivateTeamRegistry(t, teamDID, nil, "retiree")
	workingDir, workspaceDID := seedTeamReadWorkspace(t, fake)
	if err := awconfig.SaveTeamKey("acme.com", "backend", teamKey); err != nil {
		t.Fatal(err)
	}

	signers := teamReadSigners(workingDir, "acme.com", "backend")
	if len(signers) != 2 {
		t.Fatalf("got %d candidate keys, want the workspace key and the controller key", len(signers))
	}
	out := teamAgentStatusOutput{TeamID: "backend:acme.com", Alias: "retiree"}
	readAgentCertificateState(context.Background(), &out, "acme.com", "backend", false, signers)

	if out.Certificate != agentCertificateActive {
		t.Fatalf("certificate=%q, want %q; unreadable=%v", out.Certificate, agentCertificateActive, out.Unreadable)
	}
	if len(fake.refused) != 1 || fake.refused[0] != workspaceDID {
		t.Fatalf("refused=%v, want exactly the workspace key %q turned away once", fake.refused, workspaceDID)
	}
	for _, did := range fake.admitted {
		if did != teamDID {
			t.Fatalf("a read was admitted for %q, want the controller key %q", did, teamDID)
		}
	}
	// The member read must reuse the key the team read was admitted with rather
	// than walking the candidates again.
	if len(fake.admitted) != 2 {
		t.Fatalf("admitted=%v, want the team read and the member read", fake.admitted)
	}
}

// With no usable key the refusal has to arrive as an instruction, not as an
// HTTP status the operator has to interpret.
func TestAgentStatusExplainsAPrivateTeamItCannotSignFor(t *testing.T) {
	fake := newPrivateTeamRegistry(t, "did:key:z6MkController", nil, "retiree")
	resetTeamRemoveMemberGlobals(t)
	teamRemoveRegistryURL = fake.server.URL

	out := teamAgentStatusOutput{TeamID: "backend:acme.com", Alias: "retiree"}
	readAgentCertificateState(context.Background(), &out, "acme.com", "backend", false, nil)

	if out.Certificate != agentCertificateUnknown {
		t.Fatalf("certificate=%q, want %q", out.Certificate, agentCertificateUnknown)
	}
	said := strings.Join(out.Unreadable, " ")
	for _, want := range []string{
		"backend:acme.com is private",
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
	if len(fake.refused) != 1 || fake.refused[0] != "" {
		t.Fatalf("refused=%v, want one unsigned attempt", fake.refused)
	}
}

// Public teams must be untouched: the same read stays anonymous and succeeds.
func TestAgentStatusReadsAPublicTeamAnonymouslyAsBefore(t *testing.T) {
	fake := newPrivateTeamRegistry(t, "did:key:z6MkController", nil, "retiree")
	fake.visibility = "public"
	resetTeamRemoveMemberGlobals(t)
	teamRemoveRegistryURL = fake.server.URL

	out := teamAgentStatusOutput{TeamID: "backend:acme.com", Alias: "retiree"}
	readAgentCertificateState(context.Background(), &out, "acme.com", "backend", false, nil)

	if out.Certificate != agentCertificateActive {
		t.Fatalf("certificate=%q, want %q; unreadable=%v", out.Certificate, agentCertificateActive, out.Unreadable)
	}
	if len(fake.refused) != 0 {
		t.Fatalf("refused=%v on a public team", fake.refused)
	}
	for _, did := range fake.admitted {
		if did != "" {
			t.Fatalf("a public-team read carried a signature from %q; anonymous behavior must be unchanged", did)
		}
	}
}

// The roster read is the other command an operator runs against a team they are
// in, so it has to sign too.
func TestTeamMembersListsAPrivateTeamWithTheWorkspaceMemberKey(t *testing.T) {
	fake := newPrivateTeamRegistry(t, "did:key:z6MkNotUsed", nil, "alice")
	resetTeamMembersGlobals(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(awconfig.IdentityHomeEnv, "")
	root := t.TempDir()
	t.Chdir(root)
	pub, priv, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(root), priv); err != nil {
		t.Fatal(err)
	}
	fake.memberDIDs[awid.ComputeDIDKey(pub)] = true
	teamMembersTeamID = "backend:acme.com"
	teamMembersRegistryURL = fake.server.URL

	if err := runTeamMembers(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runTeamMembers against a private team the workspace is a member of: %v", err)
	}
	if len(fake.refused) != 0 {
		t.Fatalf("refused=%v; the workspace key should have been admitted", fake.refused)
	}
}

// And when it cannot sign, it must say what to do rather than surface a 403.
func TestTeamMembersExplainsAPrivateTeamItCannotSignFor(t *testing.T) {
	fake := newPrivateTeamRegistry(t, "did:key:z6MkController", nil, "alice")
	resetTeamMembersGlobals(t)
	t.Setenv("HOME", t.TempDir())
	t.Setenv(awconfig.IdentityHomeEnv, "")
	t.Chdir(t.TempDir())
	teamMembersTeamID = "backend:acme.com"
	teamMembersRegistryURL = fake.server.URL

	err := runTeamMembers(&cobra.Command{}, nil)
	if err == nil {
		t.Fatal("an unsigned roster read of a private team succeeded")
	}
	for _, want := range []string{
		"backend:acme.com is private",
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
