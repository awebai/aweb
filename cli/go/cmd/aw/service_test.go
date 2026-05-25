package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestActivateExistingTeamMembershipSwitchesActiveTeam(t *testing.T) {
	workingDir := t.TempDir()
	if err := awconfig.SaveTeamState(workingDir, &awconfig.TeamState{
		ActiveTeam: "alpha:example.com",
		Memberships: []awconfig.TeamMembership{
			{TeamID: "alpha:example.com", Alias: "alpha", CertPath: ".aw/team-certs/alpha.pem"},
			{TeamID: "circle:juanreyero.com", Alias: "merlin", CertPath: ".aw/team-certs/circle.pem"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	if err := activateExistingTeamMembership(workingDir, "circle:juanreyero.com"); err != nil {
		t.Fatal(err)
	}

	state, err := awconfig.LoadTeamState(workingDir)
	if err != nil {
		t.Fatal(err)
	}
	if state.ActiveTeam != "circle:juanreyero.com" {
		t.Fatalf("active_team=%q", state.ActiveTeam)
	}
}

func TestActivateExistingTeamMembershipRejectsMissingTeam(t *testing.T) {
	workingDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(workingDir, ".aw"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamState(workingDir, &awconfig.TeamState{
		ActiveTeam: "alpha:example.com",
		Memberships: []awconfig.TeamMembership{
			{TeamID: "alpha:example.com", Alias: "alpha", CertPath: ".aw/team-certs/alpha.pem"},
		},
	}); err != nil {
		t.Fatal(err)
	}

	err := activateExistingTeamMembership(workingDir, "circle:juanreyero.com")
	if err == nil {
		t.Fatal("expected missing membership error")
	}
}
