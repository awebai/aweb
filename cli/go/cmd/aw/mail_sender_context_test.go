package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	aweb "github.com/awebai/aw"
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestIdentityOnlyMailRequiresAnExplicitMultiTeamSenderContext(t *testing.T) {
	home := t.TempDir()
	client, err := aweb.New("https://service.example")
	if err != nil {
		t.Fatal(err)
	}
	selection := &awconfig.Selection{IdentityHome: home}
	state := &awconfig.TeamState{ActiveTeam: "one:example.test", Memberships: []awconfig.TeamMembership{
		{TeamID: "one:example.test", Alias: "worker", CertPath: "one.cert"},
	}}
	if err := awconfig.SaveTeamStateToIdentityHome(home, state); err != nil {
		t.Fatal(err)
	}
	if err := requireMailSenderContext(client, selection); err != nil {
		t.Fatalf("unique context: %v", err)
	}
	state.Memberships = append(state.Memberships, awconfig.TeamMembership{TeamID: "two:example.test", Alias: "worker", CertPath: "two.cert"})
	if err := awconfig.SaveTeamStateToIdentityHome(home, state); err != nil {
		t.Fatal(err)
	}
	if err := requireMailSenderContext(client, selection); err == nil || !strings.Contains(err.Error(), "pass --team") {
		t.Fatalf("ambiguous sender remedy: %v", err)
	}
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	grant, err := aweb.NewWithGrant("https://service.example", key, "scoped-grant")
	if err != nil {
		t.Fatal(err)
	}
	if err := requireMailSenderContext(grant, selection); err != nil {
		t.Fatalf("team-bound grant: %v", err)
	}
	if err := os.WriteFile(filepath.Join(home, "teams.yaml"), []byte("memberships: [\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := requireMailSenderContext(client, selection); err == nil || !strings.Contains(err.Error(), "sender context is unknown") || !strings.Contains(err.Error(), "repair") {
		t.Fatalf("failed read must not become empty: %v", err)
	}
}
