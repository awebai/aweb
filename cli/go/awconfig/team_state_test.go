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
				TeamID:   "backend:acme.com",
				Alias:    "alice",
				CertPath: TeamCertificateRelativePath("backend:acme.com"),
				JoinedAt: "2026-04-13T00:00:00Z",
			},
			{
				TeamID:   "ops:acme.com",
				Alias:    "alice-ops",
				CertPath: TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt: "2026-04-14T00:00:00Z",
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
		"alias: alice",
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
		TeamID:   "backend:acme.com",
		Alias:    "alice-updated",
		CertPath: TeamCertificateRelativePath("backend:acme.com"),
	})
	if len(state.Memberships) != 1 {
		t.Fatalf("memberships=%d want 1", len(state.Memberships))
	}
	if got := state.Membership("backend:acme.com"); got == nil || got.Alias != "alice-updated" {
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

func TestLoadTeamStateRejectsMissingActiveTeam(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(TeamStatePath(tmp)), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(TeamStatePath(tmp), []byte(strings.TrimSpace(`
memberships:
  - team_id: backend:acme.com
    alias: alice
    cert_path: .aw/team-certs/backend__acme.com.pem
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write teams.yaml: %v", err)
	}

	_, err := LoadTeamState(tmp)
	if err == nil {
		t.Fatal("expected missing active_team to fail")
	}
	if !strings.Contains(err.Error(), "missing active_team") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadTeamStateRejectsDuplicateTeamID(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(TeamStatePath(tmp)), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(TeamStatePath(tmp), []byte(strings.TrimSpace(`
active_team: backend:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    cert_path: .aw/team-certs/backend__acme.com.pem
  - team_id: backend:acme.com
    alias: alice-2
    cert_path: .aw/team-certs/backend__acme.com.pem
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write teams.yaml: %v", err)
	}

	_, err := LoadTeamState(tmp)
	if err == nil {
		t.Fatal("expected duplicate team_id to fail")
	}
	if !strings.Contains(err.Error(), "duplicate membership") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadTeamStateRejectsActiveTeamOutsideMemberships(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Dir(TeamStatePath(tmp)), 0o755); err != nil {
		t.Fatalf("mkdir .aw: %v", err)
	}
	if err := os.WriteFile(TeamStatePath(tmp), []byte(strings.TrimSpace(`
active_team: ops:acme.com
memberships:
  - team_id: backend:acme.com
    alias: alice
    cert_path: .aw/team-certs/backend__acme.com.pem
`)+"\n"), 0o600); err != nil {
		t.Fatalf("write teams.yaml: %v", err)
	}

	_, err := LoadTeamState(tmp)
	if err == nil {
		t.Fatal("expected unmatched active_team to fail")
	}
	if !strings.Contains(err.Error(), "is not present in memberships") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestLoadTeamStateMigratesFromWorkspaceYAML(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	workspacePath := filepath.Join(tmp, DefaultWorktreeWorkspaceRelativePath())
	if err := SaveWorktreeWorkspaceTo(workspacePath, &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai/api",
		ActiveTeam: "backend:acme.com",
		Memberships: []WorktreeMembership{
			{
				TeamID:      "backend:acme.com",
				Alias:       "alice",
				RoleName:    "backend",
				WorkspaceID: "ws-backend",
				CertPath:    TeamCertificateRelativePath("backend:acme.com"),
				JoinedAt:    "2026-04-13T00:00:00Z",
			},
			{
				TeamID:      "ops:acme.com",
				Alias:       "alice-ops",
				RoleName:    "ops",
				WorkspaceID: "ws-ops",
				CertPath:    TeamCertificateRelativePath("ops:acme.com"),
				JoinedAt:    "2026-04-14T00:00:00Z",
			},
		},
	}); err != nil {
		t.Fatalf("save workspace: %v", err)
	}

	got, err := LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}

	want := canonicalTeamState()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("migrated state mismatch:\n got: %#v\nwant: %#v", got, want)
	}

	data, err := os.ReadFile(TeamStatePath(tmp))
	if err != nil {
		t.Fatalf("read migrated teams.yaml: %v", err)
	}
	text := string(data)
	if strings.Contains(text, "workspace_id:") {
		t.Fatalf("teams.yaml should not contain workspace_id:\n%s", text)
	}
	if strings.Contains(text, "role_name:") {
		t.Fatalf("teams.yaml should not contain role_name:\n%s", text)
	}
}

func TestLoadTeamStatePrefersExistingTeamsYAMLOverWorkspaceYAML(t *testing.T) {
	t.Parallel()

	tmp := t.TempDir()
	if err := SaveWorktreeWorkspaceTo(filepath.Join(tmp, DefaultWorktreeWorkspaceRelativePath()), &WorktreeWorkspace{
		AwebURL:    "https://app.aweb.ai/api",
		ActiveTeam: "backend:acme.com",
		Memberships: []WorktreeMembership{{
			TeamID:      "backend:acme.com",
			Alias:       "workspace-alice",
			WorkspaceID: "ws-backend",
			CertPath:    TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt:    "2026-04-13T00:00:00Z",
		}},
	}); err != nil {
		t.Fatalf("save workspace: %v", err)
	}

	want := &TeamState{
		ActiveTeam: "backend:acme.com",
		Memberships: []TeamMembership{{
			TeamID:   "backend:acme.com",
			Alias:    "teams-alice",
			CertPath: TeamCertificateRelativePath("backend:acme.com"),
			JoinedAt: "2026-04-15T00:00:00Z",
		}},
	}
	if err := SaveTeamState(tmp, want); err != nil {
		t.Fatalf("save team state: %v", err)
	}

	got, err := LoadTeamState(tmp)
	if err != nil {
		t.Fatalf("load team state: %v", err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("loaded state mismatch:\n got: %#v\nwant: %#v", got, want)
	}
}
