package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

// docs/cli-identity-selection.md:10-17 forbids treating an unreadable selected
// identity as permission to use another principal.
func TestSelectedGrantHomeNeverTreatsBrokenGrantStateAsRootAuthority(t *testing.T) {
	prior := activeIdentityHome
	t.Cleanup(func() { activeIdentityHome = prior })
	for _, scenario := range []string{"root without grant", "valid grant", "corrupt grant", "directory at grant path"} {
		t.Run(scenario, func(t *testing.T) {
			root := t.TempDir()
			activeIdentityHome = awconfig.IdentityHome{Root: root, Source: awconfig.IdentityHomeFlag}
			path := awconfig.GrantHomeStatePath(root)
			switch scenario {
			case "valid grant":
				writeGrantHomeForTest(t, root, "https://service.example")
			case "corrupt grant":
				if err := os.WriteFile(path, []byte("version: ["), 0o600); err != nil {
					t.Fatal(err)
				}
			case "directory at grant path":
				if err := os.Mkdir(filepath.Clean(path), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			grant, err := loadSelectedGrantHome()
			switch scenario {
			case "root without grant":
				if err != nil || grant != nil {
					t.Fatalf("ordinary root: grant=%v error=%v", grant, err)
				}
			case "valid grant":
				if err != nil || grant == nil || grant.GrantID != "grant-777" {
					t.Fatalf("selected grant: grant=%v error=%v", grant, err)
				}
			default:
				if err == nil || grant != nil {
					t.Fatalf("broken grant selected root fallback: grant=%v error=%v", grant, err)
				}
				if err := requireGrantAuthorityHome(); err == nil {
					t.Fatal("broken grant allowed root authority")
				}
			}
		})
	}
}

func TestInvitePlanCannotBorrowControllerAuthorityFromBrokenGrantState(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	root := t.TempDir()
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "one", key); err != nil {
		t.Fatal(err)
	}
	path := awconfig.GrantHomeStatePath(root)
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatal(err)
	}
	source := teamInviteSource{WorkingDir: root, Home: awconfig.IdentityHome{Root: root, Source: awconfig.IdentityHomeFlag}, Domain: "example.com", Team: "one", AwebURL: "https://service.invalid"}
	if _, err := planTeamInvite(source); err == nil {
		t.Fatal("broken grant borrowed the host's controller key")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	plan, err := planTeamInvite(source)
	if err != nil || plan.Kind != inviteAuthorityController {
		t.Fatalf("actual root controller neighbor refused: %v", err)
	}
}
