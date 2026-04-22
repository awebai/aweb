package awconfig

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awid"
)

func TestResolveFallsBackToIdentityAddressWhenActiveCertMissing(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai",
		ActiveTeam: "backend:myteam.aweb.ai",
		Memberships: []WorktreeMembership{{
			TeamID:      "backend:myteam.aweb.ai",
			Alias:       "support",
			WorkspaceID: "agent-1",
			CertPath:    TeamCertificateRelativePath("backend:myteam.aweb.ai"),
			JoinedAt:    "2026-04-09T00:00:00Z",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:       "did:key:z6MkBYOD",
		StableID:  "did:aw:byod-support",
		Address:   "acme.com/support",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-04T00:00:00Z",
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
		Lifetime:      awid.LifetimePersistent,
		IssuedAt:      "2026-04-21T00:00:00Z",
		Signature:     "sig",
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai",
		ActiveTeam: teamID,
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "amy",
			WorkspaceID: "agent-amy",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveWorktreeIdentityTo(filepath.Join(tmp, ".aw", "identity.yaml"), &WorktreeIdentity{
		DID:       "did:key:z6MkAmy",
		StableID:  "did:aw:amy",
		Address:   "juan.aweb.ai/amy",
		Custody:   awid.CustodySelf,
		Lifetime:  awid.LifetimePersistent,
		CreatedAt: "2026-04-21T00:00:00Z",
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
		Lifetime:      awid.LifetimePersistent,
		IssuedAt:      "2026-04-21T00:00:00Z",
		Signature:     "sig",
	}); err != nil {
		t.Fatal(err)
	}
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai",
		ActiveTeam: teamID,
		Memberships: []WorktreeMembership{{
			TeamID:      teamID,
			Alias:       "alice",
			WorkspaceID: "agent-alice",
			CertPath:    TeamCertificateRelativePath(teamID),
			JoinedAt:    "2026-04-21T00:00:00Z",
		}},
	}); err != nil {
		t.Fatal(err)
	}

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
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai",
		ActiveTeam: "backend:acme.com",
		Memberships: []WorktreeMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "alice",
			WorkspaceID: "workspace-1",
			CertPath:    TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt:    "2026-04-09T00:00:00Z",
		}},
	}); err != nil {
		t.Fatal(err)
	}

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
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, ".aw", "workspace.yaml"), &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai",
		ActiveTeam: "backend:acme.com",
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
	}); err != nil {
		t.Fatal(err)
	}

	_, err := ResolveWorkspace(ResolveOptions{WorkingDir: tmp, TeamIDOverride: "unknown:acme.com"})
	if err == nil {
		t.Fatal("expected unknown team override error")
	}
	if got := err.Error(); got != `team "unknown:acme.com" is not present in workspace memberships; available: backend:acme.com, ops:acme.com` {
		t.Fatalf("error=%q", got)
	}
}
