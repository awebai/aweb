package awid

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPendingPrivateTeamKeyIsUnconfirmedUntilAnExistingRegistryReadAnswers(t *testing.T) {
	teamPublic, teamPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPublic, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignTeamCertificate(teamPrivate, TeamCertificateFields{
		Team: "ops:example.test", MemberDIDKey: ComputeDIDKey(memberPublic), Alias: "worker", IdentityScope: IdentityModeLocal,
	})
	if err != nil {
		t.Fatal(err)
	}
	registered, down := false, false
	currentKey := ComputeDIDKey(teamPublic)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if down {
			http.Error(w, "unavailable", http.StatusServiceUnavailable)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/status") {
			if !registered {
				http.NotFound(w, r)
				return
			}
			if err := json.NewEncoder(w).Encode(TeamCertificateStatus{
				TeamID: cert.Team, TeamDIDKey: currentKey, Status: "active",
			}); err != nil {
				t.Error(err)
			}
			return
		}
		http.Error(w, "private team", http.StatusForbidden)
	}))
	defer server.Close()
	registry := NewAWIDRegistryClient(server.Client(), nil)
	registry.DefaultRegistryURL = server.URL
	if err := registry.TrustRegistryOrigin(server.URL); err != nil {
		t.Fatal(err)
	}
	check := CurrentTeamCertificateCheck{RegistryURL: server.URL, Certificate: cert}
	pending, err := registry.CheckTeamCertificateCurrentKey(context.Background(), check)
	if err != nil {
		t.Fatal(err)
	}
	if pending.Evidence.State != TeamKeyUnconfirmed || pending.Evidence.DIDKey != cert.TeamDIDKey {
		t.Fatalf("pending: %+v", pending)
	}
	registered = true
	confirmed, err := registry.CheckTeamCertificateCurrentKey(context.Background(), check)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed.Evidence.State != TeamKeyConfirmed {
		t.Fatalf("confirmed: %+v", confirmed)
	}
	down = true
	unavailable, err := registry.CheckTeamCertificateCurrentKey(context.Background(), check)
	if err != nil || unavailable.Evidence.State != TeamKeyUnconfirmed || unavailable.UnavailableCause == nil {
		t.Fatalf("unavailable: %+v, %v", unavailable, err)
	}
	down = false
	otherPublic, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	currentKey = ComputeDIDKey(otherPublic)
	refused, err := registry.CheckTeamCertificateCurrentKey(context.Background(), check)
	var failure *CurrentTeamCertificateError
	if refused != nil || !errors.As(err, &failure) || failure.Code != CurrentCertificateKeyChanged {
		t.Fatalf("different current key: %+v, %v", refused, err)
	}
	if !strings.Contains(err.Error(), "team key this agent was given does not match the registry's") || !strings.Contains(err.Error(), "ask the team's owner") {
		t.Fatal(err)
	}
}

func TestPublicTeamKeyCanBeConfirmedBeforeCertificateRegistration(t *testing.T) {
	teamPublic, teamPrivate, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	memberPublic, _, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cert, err := SignTeamCertificate(teamPrivate, TeamCertificateFields{Team: "ops:example.test", MemberDIDKey: ComputeDIDKey(memberPublic), Alias: "worker", IdentityScope: IdentityModeLocal})
	if err != nil {
		t.Fatal(err)
	}
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if strings.HasSuffix(r.URL.Path, "/status") {
			http.NotFound(w, r)
			return
		}
		if err := json.NewEncoder(w).Encode(RegistryTeam{TeamID: cert.Team, Domain: "example.test", Name: "ops", TeamDIDKey: ComputeDIDKey(teamPublic)}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	registry := NewAWIDRegistryClient(server.Client(), nil)
	if err := registry.TrustRegistryOrigin(server.URL); err != nil {
		t.Fatal(err)
	}
	observation, err := registry.CheckTeamCertificateCurrentKey(context.Background(), CurrentTeamCertificateCheck{RegistryURL: server.URL, Certificate: cert})
	if err != nil {
		t.Fatal(err)
	}
	if observation.Evidence.State != TeamKeyConfirmed || requests != 2 {
		t.Fatalf("%+v; requests=%d", observation, requests)
	}
	altered := *cert
	altered.Signature = "invalid"
	refused, err := registry.CheckTeamCertificateCurrentKey(context.Background(), CurrentTeamCertificateCheck{RegistryURL: server.URL, Certificate: &altered})
	if refused != nil || err == nil || requests != 2 {
		t.Fatalf("forged artifact must fail before reading: %+v, %v; requests=%d", refused, err, requests)
	}
}
