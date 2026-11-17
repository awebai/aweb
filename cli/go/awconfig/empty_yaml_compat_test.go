package awconfig

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEmptyYAMLLoadersPreserveReleasedCompatibility(t *testing.T) {
	for _, contents := range []string{"", "# empty file\n", "null\n"} {
		t.Run(contents, func(t *testing.T) {
			home := t.TempDir()
			for _, name := range []string{"identity.yaml", "teams.yaml", "workspace.yaml"} {
				if err := os.WriteFile(filepath.Join(home, name), []byte(contents), 0600); err != nil {
					t.Fatal(err)
				}
			}
			identity, err := LoadWorktreeIdentityFrom(filepath.Join(home, "identity.yaml"))
			if err != nil || identity == nil || identity.DID != "" {
				t.Fatalf("identity: %#v, %v", identity, err)
			}
			teams, err := LoadTeamStateFromIdentityHome(home)
			if err != nil || teams == nil || teams.ActiveTeam != "" || len(teams.Memberships) != 0 {
				t.Fatalf("teams: %#v, %v", teams, err)
			}
			workspace, err := LoadWorktreeWorkspaceFrom(filepath.Join(home, "workspace.yaml"))
			if err != nil || workspace == nil || workspace.AwebURL != "" || len(workspace.Memberships) != 0 {
				t.Fatalf("workspace: %#v, %v", workspace, err)
			}
		})
	}
}
