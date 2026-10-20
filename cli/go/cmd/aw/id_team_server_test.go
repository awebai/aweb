package main

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

type teamServerFixture struct {
	registryURL string
	registry    *awid.RegistryClient
	domain      string
	team        string
	teamKey     ed25519.PrivateKey
	teamDID     string
}

func newTeamServerFixture(t *testing.T, domain string) teamServerFixture {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AWID_SKIP_DNS_VERIFY", "1")
	registryURL := realAWIDFixture(t)
	registry := awid.NewAWIDRegistryClient(nil, nil)
	ctx := context.Background()

	controllerPub, controllerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := registry.RegisterNamespaceAt(ctx, registryURL, domain, awid.ComputeDIDKey(controllerPub), controllerKey); err != nil {
		t.Fatalf("register namespace: %v", err)
	}
	teamPub, teamKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	teamDID := awid.ComputeDIDKey(teamPub)
	if _, err := registry.CreateTeam(ctx, registryURL, domain, "ops", "Ops", teamDID, controllerKey); err != nil {
		t.Fatalf("create team: %v", err)
	}
	if err := awconfig.SaveTeamKey(domain, "ops", teamKey); err != nil {
		t.Fatal(err)
	}
	return teamServerFixture{registryURL: registryURL, registry: registry, domain: domain, team: "ops", teamKey: teamKey, teamDID: teamDID}
}

func (f teamServerFixture) options(serverURL string, now time.Time) teamServerOptions {
	return teamServerOptions{
		Domain:      f.domain,
		Team:        f.team,
		ServerURL:   serverURL,
		RegistryURL: f.registryURL,
		Now:         func() time.Time { return now },
	}
}

func TestTeamSetServerPublishesARecordShowServerVerifies(t *testing.T) {
	f := newTeamServerFixture(t, "set-server.example")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	published, err := executeTeamSetServer(ctx, f.options("https://coord.set-server.example/api", now))
	if err != nil {
		t.Fatalf("set-server: %v", err)
	}
	shown, err := executeTeamShowServer(ctx, f.options("", now))
	if err != nil {
		t.Fatalf("show-server: %v", err)
	}

	if published.Status != "published" || shown.Status != "verified" {
		t.Fatalf("status published=%q shown=%q", published.Status, shown.Status)
	}
	if shown.ServerURL != "https://coord.set-server.example/api" || shown.Audience != "https://coord.set-server.example" {
		t.Fatalf("shown = %+v", shown)
	}
	if shown.TeamDIDKey != f.teamDID || shown.TeamID != "ops:set-server.example" {
		t.Fatalf("shown = %+v", shown)
	}
	stored, err := f.registry.GetTeamServerRecord(ctx, f.registryURL, f.domain, f.team)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := awid.VerifyTeamServerRecord(stored.Record, stored.Signature, "ops:set-server.example", f.teamDID, now); err != nil {
		t.Fatalf("stored record does not verify: %v", err)
	}
}

func TestTeamSetServerRepublishingTheSameSecondIsAccepted(t *testing.T) {
	f := newTeamServerFixture(t, "republish-server.example")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := executeTeamSetServer(ctx, f.options("https://coord.republish-server.example", now)); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := executeTeamSetServer(ctx, f.options("https://coord.republish-server.example", now)); err != nil {
		t.Fatalf("retry of the same record: %v", err)
	}
}

func TestTeamSetServerSurfacesAWIDRefusals(t *testing.T) {
	f := newTeamServerFixture(t, "refused-server.example")
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Second)

	if _, err := executeTeamSetServer(ctx, f.options("https://coord.refused-server.example", now)); err != nil {
		t.Fatalf("publish: %v", err)
	}
	_, older := executeTeamSetServer(ctx, f.options("https://other.refused-server.example", now.Add(-time.Hour)))
	_, future := executeTeamSetServer(ctx, f.options("https://other.refused-server.example", now.Add(time.Hour)))

	if code, _ := registryStatusCode(older); code != http.StatusConflict || teamServerRegistryDetail(older) != "not_newer" {
		t.Fatalf("older record: status=%d detail=%q err=%v", code, teamServerRegistryDetail(older), older)
	}
	if code, _ := registryStatusCode(future); code != http.StatusUnprocessableEntity || teamServerRegistryDetail(future) != "issued_at_in_future" {
		t.Fatalf("future record: status=%d detail=%q err=%v", code, teamServerRegistryDetail(future), future)
	}
}

func TestTeamSetServerRefusesALocalKeyThatIsNotTheTeamKey(t *testing.T) {
	f := newTeamServerFixture(t, "stale-server.example")
	ctx := context.Background()
	_, staleKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey(f.domain, f.team, staleKey); err != nil {
		t.Fatal(err)
	}

	_, publishErr := executeTeamSetServer(ctx, f.options("https://coord.stale-server.example", time.Now().UTC()))
	_, readErr := f.registry.GetTeamServerRecord(ctx, f.registryURL, f.domain, f.team)

	if publishErr == nil {
		t.Fatal("set-server with a stale local key succeeded")
	}
	if code, ok := registryStatusCode(readErr); !ok || code != http.StatusNotFound {
		t.Fatalf("a record was published: %v", readErr)
	}
}

func TestAWIDAnswersARecordSignedByAnotherKeyLikeAnUnknownTeam(t *testing.T) {
	f := newTeamServerFixture(t, "stranger-server.example")
	ctx := context.Background()
	strangerPub, strangerKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	record := awid.NewTeamServerRecord("ops:stranger-server.example", awid.ComputeDIDKey(strangerPub), "https://coord.stranger-server.example", time.Now().UTC())
	signature, err := awid.SignTeamServerRecord(strangerKey, record)
	if err != nil {
		t.Fatal(err)
	}

	_, stranger := f.registry.PublishTeamServerRecord(ctx, f.registryURL, f.domain, f.team, record, signature)
	_, unknown := f.registry.PublishTeamServerRecord(ctx, f.registryURL, f.domain, "missing", record, signature)

	strangerCode, _ := registryStatusCode(stranger)
	unknownCode, _ := registryStatusCode(unknown)
	if strangerCode != http.StatusNotFound || unknownCode != http.StatusNotFound {
		t.Fatalf("stranger=%d unknown=%d", strangerCode, unknownCode)
	}
	if teamServerRegistryDetail(stranger) != teamServerRegistryDetail(unknown) {
		t.Fatalf("stranger detail %q differs from unknown team %q", teamServerRegistryDetail(stranger), teamServerRegistryDetail(unknown))
	}
}

func TestShowServerRefusesWhenNothingIsPublished(t *testing.T) {
	f := newTeamServerFixture(t, "unpublished-server.example")

	_, err := executeTeamShowServer(context.Background(), f.options("", time.Now().UTC()))

	if err == nil {
		t.Fatal("show-server succeeded with no published record")
	}
}

func TestTeamSetServerRefusesNonCanonicalURLsBeforeLoadingKeys(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	for _, serverURL := range []string{"", "https://coord.example/", "http://coord.example", "https://Coord.example"} {
		_, err := executeTeamSetServer(context.Background(), teamServerOptions{
			Domain:      "canonical-server.example",
			Team:        "ops",
			ServerURL:   serverURL,
			RegistryURL: "http://127.0.0.1:1",
		})
		if err == nil {
			t.Fatalf("server URL %q accepted", serverURL)
		}
		if exitCode(err) != 2 {
			t.Fatalf("server URL %q is not refused as a usage error: %v", serverURL, err)
		}
	}
}
