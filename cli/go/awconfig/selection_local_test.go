package awconfig

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awid"
)

func saveWorkspaceAndTeamStateForSelectionTest(t *testing.T, root string, activeTeam string, workspace *WorktreeWorkspace) {
	t.Helper()
	if err := SaveWorktreeWorkspaceTo(filepath.Join(root, ".aw", "workspace.yaml"), workspace); err != nil {
		t.Fatal(err)
	}
	teamState := &TeamState{ActiveTeam: activeTeam}
	for _, membership := range workspace.Memberships {
		teamState.Memberships = append(teamState.Memberships, TeamMembership{
			TeamID:   membership.TeamID,
			Alias:    membership.Alias,
			CertPath: membership.CertPath,
			JoinedAt: membership.JoinedAt,
		})
	}
	if err := SaveTeamState(root, teamState); err != nil {
		t.Fatal(err)
	}
}

func TestResolveWorkspaceWithMissingTeamsYAMLDoesNotFallbackToIdentity(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "alice",
			WorkspaceID: "workspace-1",
			CertPath:    TeamCertificateRelativePath("backend:acme.com"),
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:           "did:key:z6MkAlice",
		StableID:      "did:aw:alice",
		Address:       "acme.com/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-21T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err == nil {
		t.Fatal("expected missing teams.yaml to fail")
	}
	if !strings.Contains(err.Error(), "invalid worktree workspace") || !strings.Contains(err.Error(), "teams.yaml") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolveStandaloneExternalIdentityRejectsSigningKeySymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	identityHome := filepath.Join(root, "identity")
	instance := filepath.Join(root, "instance")
	if err := os.MkdirAll(identityHome, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := SaveWorktreeIdentityTo(filepath.Join(identityHome, "identity.yaml"), &WorktreeIdentity{
		DID: "did:key:z6MkAlice", StableID: "did:aw:alice", Address: "acme.com/alice",
		Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeGlobal,
	}); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "outside.key")
	if err := os.WriteFile(outside, []byte("not a key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(identityHome, "signing.key")); err != nil {
		t.Fatal(err)
	}
	_, err = ResolveWorkspace(ResolveOptions{WorkingDir: instance, IdentityHome: identityHome, ExternalIdentityHome: true})
	if err == nil || !strings.Contains(err.Error(), "symlink") {
		t.Fatalf("standalone signing symlink error=%v", err)
	}
}

func TestResolveFallsBackToIdentityAddressWhenActiveCertMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, "backend:myteam.aweb.ai", &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      "backend:myteam.aweb.ai",
			Alias:       "support",
			WorkspaceID: "agent-1",
			CertPath:    TeamCertificateRelativePath("backend:myteam.aweb.ai"),
			JoinedAt:    "2026-04-09T00:00:00Z",
		}},
	})
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:           "did:key:z6MkBYOD",
		StableID:      "did:aw:byod-support",
		Address:       "acme.com/support",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(WorktreeSigningKeyPath(tmp), []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Address != "acme.com/support" {
		t.Fatalf("address=%q want %q", sel.Address, "acme.com/support")
	}
	if sel.Domain != "myteam.aweb.ai" {
		t.Fatalf("domain=%q", sel.Domain)
	}
}

func TestResolveSurfacesActiveCertParseError(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:myteam.aweb.ai"
	certPath := TeamCertificatePath(tmp, teamID)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(certPath, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "support",
			WorkspaceID: "agent-1",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-09T00:00:00Z",
		}},
	})
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:           "did:key:z6MkBYOD",
		StableID:      "did:aw:byod-support",
		Address:       "acme.com/support",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-04T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err == nil {
		t.Fatal("expected corrupt active certificate to fail")
	}
	if got := err.Error(); !strings.Contains(got, "load active team certificate") || !strings.Contains(got, "parse certificate") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestResolvePrefersActiveCertMemberAddressOverIdentityAddress(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:aweb.ai"
	if _, err := SaveTeamCertificateForTeam(tmp, teamID, &awid.TeamCertificate{
		Version:       1,
		CertificateID: "cert-amy",
		Team:          teamID,
		TeamDIDKey:    "did:key:z6MkTeam",
		MemberDIDKey:  "did:key:z6MkAmy",
		MemberDIDAW:   "did:aw:amy",
		MemberAddress: "aweb.ai/amy",
		Alias:         "amy",
		IdentityScope: awid.IdentityModeGlobal,
		IssuedAt:      "2026-04-21T00:00:00Z",
		Signature:     "sig",
	}); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "amy",
			WorkspaceID: "agent-amy",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:           "did:key:z6MkAmy",
		StableID:      "did:aw:amy",
		Address:       "juan.aweb.ai/amy",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-21T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Address != "aweb.ai/amy" {
		t.Fatalf("address=%q want %q", sel.Address, "aweb.ai/amy")
	}
	if sel.Domain != "aweb.ai" {
		t.Fatalf("domain=%q", sel.Domain)
	}
}

func TestResolveUsesEphemeralActiveCertIdentityOverPersistentIdentityFile(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "devteam:test.local"
	if _, err := SaveTeamCertificateForTeam(tmp, teamID, &awid.TeamCertificate{
		Version:       1,
		CertificateID: "cert-alice",
		Team:          teamID,
		TeamDIDKey:    "did:key:z6MkTeam",
		MemberDIDKey:  "did:key:z6MkAliceEphemeral",
		Alias:         "alice",
		IdentityScope: awid.IdentityModeLocal,
		IssuedAt:      "2026-04-21T00:00:00Z",
		Signature:     "sig",
	}); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "alice",
			WorkspaceID: "agent-alice",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:           "did:key:z6MkAlicePersistent",
		StableID:      "did:aw:alice",
		Address:       "test.local/alice",
		Custody:       awid.CustodySelf,
		IdentityScope: awid.IdentityModeGlobal,
		CreatedAt:     "2026-04-21T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.DID != "did:key:z6MkAliceEphemeral" {
		t.Fatalf("did=%q want active certificate did:key", sel.DID)
	}
	if sel.StableID != "" {
		t.Fatalf("stable_id=%q want empty for local active certificate", sel.StableID)
	}
	if sel.IdentityScope != awid.IdentityModeLocal {
		t.Fatalf("identity_scope=%q want %q", sel.IdentityScope, awid.IdentityModeLocal)
	}
}

func TestResolveLeavesAddressEmptyWhenIdentityAndActiveCertAddressMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:acme.com"
	if _, err := SaveTeamCertificateForTeam(tmp, teamID, &awid.TeamCertificate{
		Version:       1,
		CertificateID: "cert-empty",
		Team:          teamID,
		TeamDIDKey:    "did:key:z6MkTeam",
		MemberDIDKey:  "did:key:z6MkAlice",
		Alias:         "alice",
		IdentityScope: awid.IdentityModeGlobal,
		IssuedAt:      "2026-04-21T00:00:00Z",
		Signature:     "sig",
	}); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "alice",
			WorkspaceID: "agent-alice",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Address != "" {
		t.Fatalf("address=%q want empty", sel.Address)
	}
}

func TestResolveDerivesWorkspaceIdentityFromCanonicalBinding(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, "backend:acme.com", &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "alice",
			WorkspaceID: "workspace-1",
			CertPath:    TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt:    "2026-04-09T00:00:00Z",
		}},
	})

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Alias != "alice" {
		t.Fatalf("alias=%q", sel.Alias)
	}
	if sel.WorkspaceID != "workspace-1" {
		t.Fatalf("workspace_id=%q", sel.WorkspaceID)
	}
	if sel.Domain != "acme.com" {
		t.Fatalf("domain=%q", sel.Domain)
	}
}

func TestResolveWorkspaceRejectsUnknownTeamOverrideWithAvailableMemberships(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, "backend:acme.com", &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{
			{
				TeamID:      "backend:acme.com",
				Alias:       "alice",
				WorkspaceID: "workspace-1",
				CertPath:    TeamCertificateRelativePath("backend:acme.com"),
				JoinedAt:    "2026-04-09T00:00:00Z",
			},
			{
				TeamID:      "ops:acme.com",
				Alias:       "alice-ops",
				WorkspaceID: "workspace-2",
				CertPath:    TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt:    "2026-04-09T00:00:00Z",
			},
		},
	})

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp, TeamIDOverride: "unknown:acme.com"})
	if err == nil {
		t.Fatal("expected unknown team override error")
	}
	if got := err.Error(); got != `team "unknown:acme.com" is not present in workspace memberships; available: backend:acme.com, ops:acme.com` {
		t.Fatalf("error=%q", got)
	}
}

func teamCertificateForSelectionTest(teamID, address string) *awid.TeamCertificate {
	return &awid.TeamCertificate{
		Version:       1,
		CertificateID: "cert-" + address,
		Team:          teamID,
		TeamDIDKey:    "did:key:z6MkTeam",
		MemberDIDKey:  "did:key:z6MkMember",
		MemberDIDAW:   "did:aw:member",
		MemberAddress: address,
		Alias:         "member",
		IdentityScope: awid.IdentityModeGlobal,
		IssuedAt:      "2026-04-21T00:00:00Z",
		Signature:     "sig",
	}
}

func TestResolveRejectsTeamCertificatePathEscapingIdentityHome(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:aweb.ai"
	outside := filepath.Join(tmp, "outside", "planted.pem")
	if err := os.MkdirAll(filepath.Dir(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(outside, teamCertificateForSelectionTest(teamID, "aweb.ai/planted")); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "member",
			WorkspaceID: "agent-member",
			CertPath:    "../outside/planted.pem",
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err == nil {
		t.Fatal("expected cert_path escaping the identity home to be rejected")
	}
	if !strings.Contains(err.Error(), "escapes identity home") {
		t.Fatalf("error=%q want it to name the identity-home escape", err)
	}
}

func TestResolveRejectsSymlinkedTeamCertificate(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:aweb.ai"
	outside := filepath.Join(tmp, "outside", "planted.pem")
	if err := os.MkdirAll(filepath.Dir(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(outside, teamCertificateForSelectionTest(teamID, "aweb.ai/planted")); err != nil {
		t.Fatal(err)
	}
	certPath := TeamCertificatePath(tmp, teamID)
	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, certPath); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "member",
			WorkspaceID: "agent-member",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err == nil {
		t.Fatal("expected a symlinked team certificate to be rejected")
	}
	if !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("error=%q want it to name the symlink", err)
	}
}

// The stored cert_path is authoritative. Resolving the certificate from the
// team_id instead would read a different file whenever the two disagree.
func TestResolveReadsStoredCertPathNotTeamIDDerivedPath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:aweb.ai"
	storedRelative := "team-certs/stored.pem"
	stored := filepath.Join(tmp, ".aw", filepath.FromSlash(storedRelative))
	if err := os.MkdirAll(filepath.Dir(stored), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(stored, teamCertificateForSelectionTest(teamID, "aweb.ai/stored")); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(TeamCertificatePath(tmp, teamID), teamCertificateForSelectionTest(teamID, "aweb.ai/derived")); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "member",
			WorkspaceID: "agent-member",
			CertPath:    storedRelative,
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatal(err)
	}
	if sel.Address != "aweb.ai/stored" {
		t.Fatalf("address=%q want the certificate at the stored cert_path", sel.Address)
	}
}

// A workspace that has not fetched its certificate yet must still resolve;
// the hardened path must not turn a missing file into a hard failure.
func TestResolveToleratesMissingTeamCertificate(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:aweb.ai"
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "member",
			WorkspaceID: "agent-member",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})

	sel, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err != nil {
		t.Fatalf("missing certificate should not fail selection: %v", err)
	}
	if sel.TeamID != teamID {
		t.Fatalf("team_id=%q want %q", sel.TeamID, teamID)
	}
}

func TestResolveRejectsTeamCertificatePathEscapingBehindIdentityHomePrefix(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:aweb.ai"
	outside := filepath.Join(tmp, "outside", "planted.pem")
	if err := os.MkdirAll(filepath.Dir(outside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := awid.SaveTeamCertificate(outside, teamCertificateForSelectionTest(teamID, "aweb.ai/planted")); err != nil {
		t.Fatal(err)
	}
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "member",
			WorkspaceID: "agent-member",
			CertPath:    ".aw/../outside/planted.pem",
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err == nil {
		t.Fatal("expected an escape behind the identity-home prefix to be rejected")
	}
	if !strings.Contains(err.Error(), "escapes identity home") {
		t.Fatalf("error=%q want it to name the identity-home escape", err)
	}
}

// Selection tolerates a certificate that has not been fetched yet, but an
// unresolvable cert_path is a different condition: it designates no file, so
// which certificate the membership means cannot be determined. That fails
// closed, as the identity-home branch has always done for the same value.
func TestResolveRejectsUnusableTeamCertificatePath(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	teamID := "backend:aweb.ai"
	saveWorkspaceAndTeamStateForSelectionTest(t, tmp, teamID, &WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "member",
			WorkspaceID: "agent-member",
			CertPath:    ".aw/",
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	})

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp})
	if err == nil {
		t.Fatal("expected a cert_path designating no file to be rejected")
	}
	if !strings.Contains(err.Error(), "must be a relative forward-slash path") {
		t.Fatalf("error=%q want it to name the unusable path", err)
	}
}
