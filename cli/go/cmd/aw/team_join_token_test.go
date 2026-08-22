package main

import (
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedJoinTokenEnvelopeRoundTrip(t *testing.T) {
	wrapped, err := encodeHostedJoinToken("aw_inv_server_secret", "https://host.example/api/")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(wrapped, hostedJoinTokenPrefix) || strings.Contains(wrapped, "server_secret") {
		t.Fatalf("unexpected hosted join envelope %q", wrapped)
	}
	raw, awebURL, err := decodeJoinToken(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if raw != "aw_inv_server_secret" || awebURL != "https://host.example/api" {
		t.Fatalf("decoded raw/url=%q/%q", raw, awebURL)
	}
}

func TestIdentityWithoutWorkspaceErrorUsesCachedServiceURL(t *testing.T) {
	dir := t.TempDir()
	writeIdentityForTest(t, dir, awconfig.WorktreeIdentity{
		DID: "did:key:z6MkiJoined", Custody: awid.CustodySelf, IdentityScope: awid.IdentityModeLocal,
	})
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: "ops:example.test",
		Memberships: []awconfig.TeamMembership{{
			TeamID: "ops:example.test", Alias: "bob", CertPath: "team-certs/ops__example.test.pem", AwebURL: "https://service.example/api",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	_, _, err := resolveClientSelectionForDir(dir)
	if err == nil || !strings.Contains(err.Error(), "aw workspace connect --service https://service.example/api") {
		t.Fatalf("identity-only recovery error=%v", err)
	}
}

func TestDecodeJoinTokenReadsExistingLocalAField(t *testing.T) {
	token, err := awconfig.EncodeInviteToken(&awconfig.TeamInvite{
		InviteID: "invite-1", Domain: "example.test", TeamName: "ops", Secret: "secret", AwebURL: "https://service.example/api/",
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, awebURL, err := decodeJoinToken(token)
	if err != nil {
		t.Fatal(err)
	}
	if raw != token || awebURL != "https://service.example/api" {
		t.Fatalf("decoded raw/url=%q/%q", raw, awebURL)
	}
}

func TestDecodeJoinTokenKeepsLegacyHostedToken(t *testing.T) {
	raw, awebURL, err := decodeJoinToken("aw_inv_legacy_secret")
	if err != nil {
		t.Fatal(err)
	}
	if raw != "aw_inv_legacy_secret" || awebURL != "" {
		t.Fatalf("legacy raw/url=%q/%q", raw, awebURL)
	}
}

func TestWorkspaceRecoveryUsesCachedInviteServiceURL(t *testing.T) {
	dir := t.TempDir()
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: "ops:example.test",
		Memberships: []awconfig.TeamMembership{{
			TeamID: "ops:example.test", Alias: "bob", CertPath: "team-certs/ops__example.test.pem", AwebURL: "https://service.example/api/",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := workspaceConnectRecoveryCommand(dir, ""); !ok || got != "aw workspace connect --service https://service.example/api" {
		t.Fatalf("recovery command=%q", got)
	}
}
