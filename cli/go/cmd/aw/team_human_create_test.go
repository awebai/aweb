package main

import (
	"bytes"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestTeamCreateEmptyProfileUsesImplicitLocalInitAndSkipsLibrary(t *testing.T) {
	resetTeamCreateTestState(t)
	teamHumanCreateName = "eng"
	teamHumanCreateSelfHost = true
	var gotLocal *implicitLocalInitRequest
	teamHumanCreateLocalInit = func(req implicitLocalInitRequest) (connectOutput, error) {
		got := req
		gotLocal = &got
		return connectOutput{Status: "connected", TeamID: "default:local", Alias: req.Alias, AwebURL: req.AwebURL, WorkspaceID: "ws-local"}, nil
	}
	libraryCalls := 0
	teamHumanRegisterLibrary = func(req teamCreateLibraryRegistrationRequest) (string, error) {
		libraryCalls++
		return "registered", nil
	}
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runTeamHumanCreate(cmd, nil); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if gotLocal == nil || gotLocal.Alias != "eng" {
		t.Fatalf("local init not called with alias: %+v", gotLocal)
	}
	if libraryCalls != 0 {
		t.Fatalf("empty-profile team must not register with Library, calls=%d", libraryCalls)
	}
	if !strings.Contains(out.String(), "Profiles: empty") || !strings.Contains(out.String(), "Library registration skipped") {
		t.Fatalf("output=%s", out.String())
	}
}

func TestTeamCreateWithAPIKeyUsesExistingTeamAndRegistersWhenBound(t *testing.T) {
	resetTeamCreateTestState(t)
	t.Setenv("AWEB_API_KEY", "test-key")
	teamHumanCreateName = "eng"
	teamHumanCreateHosted = true
	teamHumanCreateProfiles = []string{"developer@0.1.0:2", "reviewer@0.1.0:1"}
	var gotAPI *apiKeyInitRequest
	teamHumanCreateAPIKeyInit = func(req apiKeyInitRequest) (connectOutput, error) {
		got := req
		gotAPI = &got
		return connectOutput{Status: "connected", TeamID: "team:example.com", Alias: req.Alias, AwebURL: req.AwebURL, WorkspaceID: "ws-api"}, nil
	}
	var gotRegistration *teamCreateLibraryRegistrationRequest
	teamHumanRegisterLibrary = func(req teamCreateLibraryRegistrationRequest) (string, error) {
		got := req
		gotRegistration = &got
		return "deferred_until_library_contract", nil
	}
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	if err := runTeamHumanCreate(cmd, nil); err != nil {
		t.Fatalf("runTeamHumanCreate: %v", err)
	}
	if gotAPI == nil || gotAPI.APIKey != "test-key" || gotAPI.Alias != "eng" {
		t.Fatalf("api init not called: %+v", gotAPI)
	}
	if gotRegistration == nil || gotRegistration.TeamID != "team:example.com" || len(gotRegistration.Profiles) != 2 || gotRegistration.Profiles[0].Count != 2 {
		t.Fatalf("registration=%+v", gotRegistration)
	}
	if !strings.Contains(out.String(), "developer@0.1.0 x2") || !strings.Contains(out.String(), "Library registration: deferred_until_library_contract") {
		t.Fatalf("output=%s", out.String())
	}
}

func TestTeamCreateRequiresExplicitHostedOrSelfHost(t *testing.T) {
	resetTeamCreateTestState(t)
	teamHumanCreateName = "eng"
	var out bytes.Buffer
	cmd := &cobra.Command{}
	cmd.SetOut(&out)
	err := runTeamHumanCreate(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "one of --hosted or --self-host is required") {
		t.Fatalf("error=%v", err)
	}
}

func TestParseTeamCreateProfiles(t *testing.T) {
	profiles, err := parseTeamCreateProfiles([]string{"developer@0.1.0:2", "reviewer@0.1.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(profiles) != 2 || profiles[0].ProfileRef.ID != "developer" || profiles[0].Count != 2 || profiles[1].Count != 1 {
		t.Fatalf("profiles=%+v", profiles)
	}
	for _, bad := range [][]string{{"developer"}, {"../developer@0.1.0:1"}, {"developer@0.1.0:nope"}} {
		if _, err := parseTeamCreateProfiles(bad); err == nil {
			t.Fatalf("expected error for %v", bad)
		}
	}
}

func resetTeamCreateTestState(t *testing.T) {
	t.Helper()
	oldAPI := teamHumanCreateAPIKeyInit
	oldLocal := teamHumanCreateLocalInit
	oldRegister := teamHumanRegisterLibrary
	oldJSON := jsonFlag
	oldWd, _ := os.Getwd()
	tmp := t.TempDir()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	teamHumanCreateBYOT = false
	teamHumanCreateName = ""
	teamHumanCreateNamespace = ""
	teamHumanCreateDisplayName = ""
	teamHumanCreateServiceURL = ""
	teamHumanCreateRegistryURL = ""
	teamHumanCreateHosted = false
	teamHumanCreateSelfHost = false
	teamHumanCreateProfiles = nil
	jsonFlag = false
	t.Cleanup(func() {
		teamHumanCreateAPIKeyInit = oldAPI
		teamHumanCreateLocalInit = oldLocal
		teamHumanRegisterLibrary = oldRegister
		jsonFlag = oldJSON
		teamHumanCreateBYOT = false
		teamHumanCreateName = ""
		teamHumanCreateNamespace = ""
		teamHumanCreateDisplayName = ""
		teamHumanCreateServiceURL = ""
		teamHumanCreateRegistryURL = ""
		teamHumanCreateHosted = false
		teamHumanCreateSelfHost = false
		teamHumanCreateProfiles = nil
		_ = os.Chdir(oldWd)
	})
}
