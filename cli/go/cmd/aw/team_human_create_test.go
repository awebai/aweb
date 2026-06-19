package main

import (
	"os"
	"strings"
	"testing"
)

func resetTeamHumanCreateGlobals(t *testing.T) {
	t.Helper()
	oldRunImplicit := initRunImplicitLocalFlow
	oldJSON := jsonFlag
	oldBYOT := teamHumanCreateBYOT
	oldName := teamHumanCreateName
	oldNamespace := teamHumanCreateNamespace
	oldDisplayName := teamHumanCreateDisplayName
	oldServiceURL := teamHumanCreateServiceURL
	oldRegistryURL := teamHumanCreateRegistryURL
	oldAlias := teamHumanCreateAlias
	oldProfiles := teamHumanCreateProfiles
	oldAddLocal := teamHumanAddLocal
	oldAddGlobal := teamHumanAddGlobal
	oldAddLayoutOnly := teamHumanAddLayoutOnly
	t.Cleanup(func() {
		initRunImplicitLocalFlow = oldRunImplicit
		jsonFlag = oldJSON
		teamHumanCreateBYOT = oldBYOT
		teamHumanCreateName = oldName
		teamHumanCreateNamespace = oldNamespace
		teamHumanCreateDisplayName = oldDisplayName
		teamHumanCreateServiceURL = oldServiceURL
		teamHumanCreateRegistryURL = oldRegistryURL
		teamHumanCreateAlias = oldAlias
		teamHumanCreateProfiles = oldProfiles
		teamHumanAddLocal = oldAddLocal
		teamHumanAddGlobal = oldAddGlobal
		teamHumanAddLayoutOnly = oldAddLayoutOnly
	})
	jsonFlag = false
	teamHumanCreateBYOT = false
	teamHumanCreateName = ""
	teamHumanCreateNamespace = ""
	teamHumanCreateDisplayName = ""
	teamHumanCreateServiceURL = ""
	teamHumanCreateRegistryURL = ""
	teamHumanCreateAlias = ""
	teamHumanCreateProfiles = nil
	teamHumanAddLocal = false
	teamHumanAddGlobal = false
	teamHumanAddLayoutOnly = false
}

func TestTeamHumanCreateEmptyProfileUsesImplicitLocalTeamNameAndNoLibrary(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Setenv("AWEB_API_KEY", "")
	t.Setenv("AWEB_URL", "http://127.0.0.1:8080")
	t.Setenv("AWID_REGISTRY_URL", "http://127.0.0.1:8081")
	t.Chdir(t.TempDir())

	var got implicitLocalInitRequest
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		got = req
		return connectOutput{Status: "connected", TeamID: "eng:local", Alias: req.Alias, AwebURL: req.AwebURL, WorkspaceID: "ws-1"}, nil
	}

	if err := runTeamHumanCreate(nil, []string{"eng"}); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if got.TeamName != "eng" {
		t.Fatalf("TeamName=%q, want eng", got.TeamName)
	}
	if got.Alias != "eng" {
		t.Fatalf("Alias=%q, want eng", got.Alias)
	}
}

func TestTeamHumanAddLayoutOnlyCreatesEmptyIdentityOnlyHomes(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	teamHumanAddLayoutOnly = true

	if err := runTeamHumanAdd(nil, []string{"developer", "reviewer"}); err != nil {
		t.Fatalf("runTeamHumanAdd: %v", err)
	}
	for _, name := range []string{"developer", "reviewer"} {
		home := root + "/agents/instances/" + name
		for _, rel := range []string{"AGENTS.md", ".aw/profile", "skills", "artifacts"} {
			if _, err := os.Stat(home + "/" + rel); !os.IsNotExist(err) {
				t.Fatalf("empty-profile layout-only home %s unexpectedly has %s (err=%v)", home, rel, err)
			}
		}
	}
}

func TestTeamHumanAddRejectsLibraryProfileBeforeSeam(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	t.Chdir(t.TempDir())
	teamHumanAddLayoutOnly = true

	err := runTeamHumanAdd(nil, []string{"developer@aweb.engineering-pack/developer"})
	if err == nil || !strings.Contains(err.Error(), "aw library plugin seam") {
		t.Fatalf("error=%v", err)
	}
	if _, statErr := os.Stat("agents/instances/developer"); !os.IsNotExist(statErr) {
		t.Fatalf("profile-bound add must not create home before seam, stat err=%v", statErr)
	}
}

func TestTeamHumanCreateEmptyProfileRejectsLibraryProfileBeforeSeam(t *testing.T) {
	resetTeamHumanCreateGlobals(t)
	teamHumanCreateProfiles = []string{"aweb.engineering-pack/developer"}
	called := false
	initRunImplicitLocalFlow = func(req implicitLocalInitRequest) (connectOutput, error) {
		called = true
		return connectOutput{}, nil
	}

	err := runTeamHumanCreate(nil, []string{"eng"})
	if err == nil || !strings.Contains(err.Error(), "aw library plugin seam") {
		t.Fatalf("error=%v", err)
	}
	if called {
		t.Fatal("profile-bound create must not call init before aw library seam")
	}
}
