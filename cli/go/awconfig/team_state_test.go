package awconfig

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func canonicalTeamState() *TeamState {
	return &TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []TeamMembership{
			{
				TeamID:      "backend:acme.com",
				Alias:       "alice",
				RoleName:    "developer",
				WorkspaceID: "ws-1",
				CertPath:    TeamCertificateRelativePath("backend:acme.com"),
				JoinedAt:    "2026-04-13T00:00:00Z",
			},
			{
				TeamID:      "ops:acme.com",
				Alias:       "alice-ops",
				RoleName:    "operator",
				WorkspaceID: "ws-2",
				CertPath:    TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt:    "2026-04-14T00:00:00Z",
			},
		},
	}
}

func TestSaveAndLoadTeamStateRoundTrip(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	want := canonicalTeamState()
	if err := SaveTeamState(tmp, want); err != nil {
		t.Fatalf("save team state: %v", err)
	}

	data, err := os.ReadFile(TeamStatePath(tmp))
	if err != nil {
		t.Fatalf("read teams.yaml: %v", err)
	}
	text := string(data)
	for _, needle := range []string{
		"active_team: backend:acme.com",
		"memberships:",
		"team_id: backend:acme.com",
		"role_name: developer",
	} {
		if !strings.Contains(text, needle) {
			t.Fatalf("teams.yaml missing %q:\n%s", needle, text)
		}
	}

	got, err := LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("round-trip mismatch:\n got: %#v\nwant: %#v", got, want)
	}

	info, err := os.Stat(TeamStatePath(tmp))
	if err != nil {
		t.Fatalf("stat teams.yaml: %v", err)
	}
	if gotMode := info.Mode().Perm(); gotMode != 0o600 {
		t.Fatalf("mode=%#o want %#o", gotMode, 0o600)
	}
}

func TestTeamStateHelpers(t *testing.T) {
	t.Parallel()

	state := canonicalTeamState()
	if got := state.ActiveMembership(); got == nil || got.TeamID != "backend:acme.com" {
		t.Fatalf("active membership=%#v", got)
	}
	if got := state.Membership("OPS:ACME.COM"); got == nil || got.Alias != "alice-ops" {
		t.Fatalf("membership lookup=%#v", got)
	}
	want := []string{"backend:acme.com", "ops:acme.com"}
	if got := state.AvailableTeamIDs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("available team ids=%#v want %#v", got, want)
	}
}

func TestTeamStateAddMembershipSetsActiveAndReplacesExisting(t *testing.T) {
	t.Parallel()

	var state TeamState
	state.AddMembership(TeamMembership{
		TeamID:   "backend:acme.com",
		Alias:    "alice",
		CertPath: TeamCertificateRelativePath("backend:acme.com"),
	})
	if state.ActiveTeam != "backend:acme.com" {
		t.Fatalf("active_team=%q", state.ActiveTeam)
	}
	if got := state.Membership("backend:acme.com"); got == nil || got.Alias != "alice" {
		t.Fatalf("membership after add=%#v", got)
	}

	state.AddMembership(TeamMembership{
		TeamID:      "backend:acme.com",
		Alias:       "alice-updated",
		RoleName:    "developer",
		CertPath:    TeamCertificateRelativePath("backend:acme.com"),
		WorkspaceID: "ws-1",
	})
	if len(state.Memberships) != 1 {
		t.Fatalf("memberships=%d want 1", len(state.Memberships))
	}
	if got := state.Membership("backend:acme.com"); got == nil || got.Alias != "alice-updated" || got.RoleName != "developer" {
		t.Fatalf("membership after replace=%#v", got)
	}
}

func TestTeamStateRemoveMembershipReassignsActiveAndClearsWhenEmpty(t *testing.T) {
	t.Parallel()

	state := canonicalTeamState()
	state.RemoveMembership("backend:acme.com")
	if state.ActiveTeam != "ops:acme.com" {
		t.Fatalf("active_team after remove=%q", state.ActiveTeam)
	}
	if state.Membership("backend:acme.com") != nil {
		t.Fatal("removed membership still present")
	}

	state.RemoveMembership("ops:acme.com")
	if state.ActiveTeam != "" {
		t.Fatalf("active_team after removing last membership=%q", state.ActiveTeam)
	}
	if len(state.Memberships) != 0 {
		t.Fatalf("memberships=%d want 0", len(state.Memberships))
	}
}

func TestLoadTeamStateRejectsEmptyMemberships(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(TeamStatePath(tmp)), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(TeamStatePath(tmp), []byte(strings.TrimSpace(`
active_team: backend:acme.com
memberships: []
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write teams.yaml: %v", err)
	}

	_, err := LoadTeamState(tmp)
	if err == nil {
		t.Fatal("expected empty memberships to fail")
	}
	if !strings.Contains(err.Error(), "at least one membership") {
		t.Fatalf("unexpected error: %v", err)
	}
}
