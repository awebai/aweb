package main

import (
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// TestAwebURLForTeamInviteResolvesFromTeamStateMembership pins the invariant
// that breaks maria-style provisioning (epic default-aadu).
//
// A member who runs `aw team join` has their teams.yaml populated with the
// team's aweb_url, but workspace.yaml is intentionally not written until
// `aw init` (see TestTeamInviteHostedUsesCloudAuthorityWithoutLocalTeamKey,
// which asserts no workspace.yaml before init). When that member then runs
// `aw team add`, the invite-mint URL resolver must still find the hosted aweb
// URL from teams.yaml. If it only consults workspace.yaml it returns "", the
// mint decision falls through to the local-team-key branch, and a legitimately
// entitled hosted member fails with "no team key".
func TestAwebURLForTeamInviteResolvesFromTeamStateMembership(t *testing.T) {
	dir := t.TempDir()
	teamID := "default:gracehosted.aweb.ai"
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: teamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID:   teamID,
			Alias:    "maria-alice",
			CertPath: awconfig.TeamCertificateRelativePath(teamID),
			AwebURL:  "https://app.aweb.ai",
		}},
	}); err != nil {
		t.Fatal(err)
	}

	got := awebURLForTeamInvite(dir, teamID)
	if got != "https://app.aweb.ai" {
		t.Fatalf("awebURLForTeamInvite(dir, %q) = %q, want %q (a joined hosted member must be able to mint an invite from teams.yaml before `aw init`)", teamID, got, "https://app.aweb.ai")
	}
}

// TestAwebURLForTeamInviteHostedNamespaceDefaultsToOurServer pins that a hosted
// aweb.ai team always resolves to our server even with no URL on record, while
// a BYOT/local namespace fails closed (empty) rather than assuming our server.
func TestAwebURLForTeamInviteHostedNamespaceDefaultsToOurServer(t *testing.T) {
	if got := awebURLForTeamInvite(t.TempDir(), "default:gracehosted.aweb.ai"); got != DefaultAwebURL {
		t.Fatalf("hosted namespace: awebURLForTeamInvite = %q, want %q", got, DefaultAwebURL)
	}
	if got := awebURLForTeamInvite(t.TempDir(), "alpha:alpha.test.local"); got != "" {
		t.Fatalf("BYOT namespace must fail closed: awebURLForTeamInvite = %q, want empty", got)
	}
}

// TestAwebURLForTeamInviteWorkspaceBindingWinsOverTeamState pins the headline
// precedence: the live worktree binding (workspace.yaml, post-init) wins over
// the team roster (teams.yaml).
func TestAwebURLForTeamInviteWorkspaceBindingWinsOverTeamState(t *testing.T) {
	dir := t.TempDir()
	teamID := "default:gracehosted.aweb.ai"
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: teamID,
		Memberships: []awconfig.TeamMembership{{
			TeamID: teamID, Alias: "a",
			CertPath: awconfig.TeamCertificateRelativePath(teamID),
			AwebURL:  "https://roster.example",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	writeWorkspaceBindingForTest(t, dir, awconfig.WorktreeWorkspace{
		AwebURL: "https://binding.example",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID: teamID, Alias: "a",
			CertPath: awconfig.TeamCertificateRelativePath(teamID),
			JoinedAt: "2026-01-01T00:00:00Z",
		}},
	})
	if got := awebURLForTeamInvite(dir, teamID); got != "https://binding.example" {
		t.Fatalf("awebURLForTeamInvite = %q, want the worktree binding %q", got, "https://binding.example")
	}
}

// TestAwebURLForTeamInviteDoesNotReturnOtherTeamURL pins that a workspace bound
// to team A never leaks team A's server URL when the mint targets team B: in a
// multi-team worktree the resolver must key strictly on the requested team.
func TestAwebURLForTeamInviteDoesNotReturnOtherTeamURL(t *testing.T) {
	dir := t.TempDir()
	teamA := "default:gracehosted.aweb.ai"
	teamB := "default:otherhosted.aweb.ai"
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: teamA,
		Memberships: []awconfig.TeamMembership{{
			TeamID: teamA, Alias: "a",
			CertPath: awconfig.TeamCertificateRelativePath(teamA),
			AwebURL:  "https://team-a.example",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	writeWorkspaceBindingForTest(t, dir, awconfig.WorktreeWorkspace{
		AwebURL: "https://team-a.example",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID: teamA, Alias: "a",
			CertPath: awconfig.TeamCertificateRelativePath(teamA),
			JoinedAt: "2026-01-01T00:00:00Z",
		}},
	})
	got := awebURLForTeamInvite(dir, teamB)
	if got == "https://team-a.example" {
		t.Fatalf("resolver leaked team A's URL for team B: %q", got)
	}
	if got != DefaultAwebURL {
		t.Fatalf("team B (hosted, not on record) = %q, want the hosted default %q", got, DefaultAwebURL)
	}
}

// TestRegistryURLForTeamInviteHostedNamespaceDefaultsToOurRegistry is the
// registry-side twin: a hosted aweb.ai team resolves to our registry when
// nothing else is on record; a BYOT namespace fails closed.
func TestRegistryURLForTeamInviteHostedNamespaceDefaultsToOurRegistry(t *testing.T) {
	if got := registryURLForTeamInvite(t.TempDir(), "gracehosted.aweb.ai", ""); got != awid.DefaultAWIDRegistryURL {
		t.Fatalf("hosted namespace: registryURLForTeamInvite = %q, want %q", got, awid.DefaultAWIDRegistryURL)
	}
	if got := registryURLForTeamInvite(t.TempDir(), "alpha.test.local", ""); got != "" {
		t.Fatalf("BYOT namespace must fail closed: registryURLForTeamInvite = %q, want empty", got)
	}
}
