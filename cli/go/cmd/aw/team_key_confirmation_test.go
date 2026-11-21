package main

import (
	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
	"path/filepath"
	"strings"
	"testing"
)

func TestOrdinaryClientConfirmsPendingTeamKeyAndRefusesAnObservedSubstitution(t *testing.T) {
	teamPublic, teamPrivate, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert := signedMemberCertificate(t, teamPrivate, awid.ComputeDIDKey(memberPublic), "", awid.IdentityModeLocal)
	registry := newCertificateRegistry(t, teamPrivate)
	t.Setenv("AWID_REGISTRY_URL", registry.server.URL)
	home := t.TempDir()
	if _, err := awconfig.SaveTeamCertificateForTeamToIdentityHome(home, cert.Team, cert); err != nil {
		t.Fatal(err)
	}
	state := &awconfig.TeamState{ActiveTeam: cert.Team, Memberships: []awconfig.TeamMembership{{
		TeamID: cert.Team, Alias: cert.Alias, CertPath: awconfig.TeamCertificateRelativePath(cert.Team),
		RegistryURL: registry.server.URL,
		TeamKey:     &awid.TeamKeyEvidence{DIDKey: awid.ComputeDIDKey(teamPublic), State: awid.TeamKeyUnconfirmed},
	}}}
	if err := awconfig.SaveTeamStateToIdentityHome(home, state); err != nil {
		t.Fatal(err)
	}
	selection := &awconfig.Selection{IdentityHome: home, WorkingDir: filepath.Dir(home), TeamID: cert.Team}
	// Pending private status404/metadata403 is not agreement or a refusal.
	if err := recheckUnconfirmedTeamKey(selection, cert); err != nil {
		t.Fatal(err)
	}
	loaded, err := awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveMembership().TeamKey.State != awid.TeamKeyUnconfirmed {
		t.Fatal("pending key was promoted")
	}
	registry.register(cert, false)
	if err := recheckUnconfirmedTeamKey(selection, cert); err != nil {
		t.Fatal(err)
	}
	loaded, err = awconfig.LoadTeamStateFromIdentityHome(home)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.ActiveMembership().TeamKey.State != awid.TeamKeyConfirmed {
		t.Fatal("registered key was not confirmed")
	}
	loaded.ActiveMembership().TeamKey.State = awid.TeamKeyUnconfirmed
	if err := awconfig.SaveTeamStateToIdentityHome(home, loaded); err != nil {
		t.Fatal(err)
	}
	anotherPublic, _, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	registry.mu.Lock()
	registry.teamKey = awid.ComputeDIDKey(anotherPublic)
	registry.mu.Unlock()
	err = recheckUnconfirmedTeamKey(selection, cert)
	if err == nil || !strings.Contains(err.Error(), "does not match the registry's") || !strings.Contains(err.Error(), "ask the team's owner") {
		t.Fatalf("substitution: %v", err)
	}
}
