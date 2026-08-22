package main

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestHostedJoinTokenEnvelopeRoundTrip(t *testing.T) {
	wrapped := hostedJoinTokenForTest(t, "aw_inv_server_secret", "https://host.example/api/")
	if !strings.HasPrefix(wrapped, hostedJoinTokenPrefix) || strings.Contains(wrapped, "server_secret") {
		t.Fatalf("unexpected hosted join envelope %q", wrapped)
	}
	raw, awebURL, err := decodeJoinToken(wrapped)
	if err != nil {
		t.Fatal(err)
	}
	if raw != wrapped || awebURL != "https://host.example/api" {
		t.Fatalf("decoded raw/url=%q/%q", raw, awebURL)
	}
}

func TestHostedJoinTokenRejectsUnsafeServiceURLs(t *testing.T) {
	for _, rawURL := range []string{
		"relative/path",
		"http://[::1",
		"file://host/path",
		"https:///missing-host",
	} {
		t.Run(rawURL, func(t *testing.T) {
			if _, err := validateInviteAwebURL(rawURL); err == nil {
				t.Fatalf("validation accepted unsafe service URL %q", rawURL)
			}
			wireToken := hostedJoinTokenForTest(t, "aw_inv_server_secret", rawURL)
			if _, _, err := decodeJoinToken(wireToken); err == nil {
				t.Fatalf("decode accepted unsafe embedded service URL %q", rawURL)
			}
		})
	}
}

func hostedJoinTokenForTest(t *testing.T, innerToken, awebURL string) string {
	t.Helper()
	payload, err := json.Marshal(hostedJoinTokenEnvelope{Version: 1, InnerToken: innerToken, AwebURL: awebURL})
	if err != nil {
		t.Fatal(err)
	}
	return hostedJoinTokenPrefix + base64.RawURLEncoding.EncodeToString(payload)
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

func TestDecodeJoinTokenPassesThroughLegacyTokenCollidingWithV1Prefix(t *testing.T) {
	// A legacy token is aw_inv_ plus 43 base64url characters. Its random suffix
	// may validly start with v1_, making the whole token start with aw_inv_v1_.
	token := "aw_inv_v1_" + strings.Repeat("A", 40)
	raw, awebURL, err := decodeJoinToken(token)
	if err != nil {
		t.Fatalf("legacy collision was incorrectly decoded as an envelope: %v", err)
	}
	if raw != token || awebURL != "" {
		t.Fatalf("legacy collision raw/url=%q/%q want exact pass-through and legacy URL fallback", raw, awebURL)
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

func TestWorkspaceRecoveryShellQuotesServiceURL(t *testing.T) {
	dir := t.TempDir()
	if err := awconfig.SaveTeamState(dir, &awconfig.TeamState{
		ActiveTeam: "ops:example.test",
		Memberships: []awconfig.TeamMembership{{
			TeamID: "ops:example.test", Alias: "bob", CertPath: "team-certs/ops__example.test.pem", AwebURL: "http://[::1]:8100/api",
		}},
	}); err != nil {
		t.Fatal(err)
	}
	if got, ok := workspaceConnectRecoveryCommand(dir, ""); !ok || got != "aw workspace connect --service 'http://[::1]:8100/api'" {
		t.Fatalf("shell-safe recovery command=%q", got)
	}
}
