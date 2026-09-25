package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestTeamAdmissionInviteRequiresTeamAdmissionScopeAndDoesNotAcceptInvite(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldTeamID, oldRequestID, oldAlias, oldJSON := teamAdmissionInviteTeamID, teamAdmissionInviteRequestID, teamAdmissionInviteAliasHint, jsonFlag
	teamAdmissionInviteTeamID = "8ca9f8ea-43a6-45d1-917b-916634a3b5a7"
	teamAdmissionInviteRequestID = "a8d857a5-7c44-45e7-8027-bf4996d5088b"
	teamAdmissionInviteAliasHint = "alice"
	jsonFlag = true
	t.Cleanup(func() {
		teamAdmissionInviteTeamID, teamAdmissionInviteRequestID, teamAdmissionInviteAliasHint, jsonFlag = oldTeamID, oldRequestID, oldAlias, oldJSON
	})
	t.Setenv("HOME", t.TempDir())

	var sawAdmission bool
	serverURL := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			if got := r.Header.Get("Authorization"); got != "Bearer team-access" {
				t.Fatalf("status Authorization=%q", got)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case strings.Replace(teamAdmissionInvitePathTemplate, "{team_id}", teamAdmissionInviteTeamID, 1):
			sawAdmission = true
			if got := r.Header.Get("Authorization"); got != "Bearer team-access" {
				t.Fatalf("admission Authorization=%q", got)
			}
			var req teamAdmissionInviteRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req.RequestID != teamAdmissionInviteRequestID || req.AliasHint != "alice" || req.ExpiresInSeconds != 600 {
				t.Fatalf("request=%+v", req)
			}
			_ = json.NewEncoder(w).Encode(teamAdmissionInviteResponse{InviteID: "invite-1", Token: "aw_inv_secret", TokenPrefix: "aw_inv", MaxUses: 1, ExpiresAt: time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339), TeamID: teamAdmissionInviteTeamID, CanonicalTeamID: "shared:example.aweb.ai", TeamSlug: "shared", Namespace: "example.aweb.ai", ServerURL: serverURL})
		case "/api/v1/spawn/accept-invite":
			t.Fatalf("admission-invite must not accept the returned token")
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	serverURL = server.URL

	if err := saveCLIAuthConfigForScope(cliAuthScope, cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "personal-access", RefreshToken: "personal-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if err := saveCLIAuthConfigForScope(cliAuthScopeTeamAdmission, cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScopeTeamAdmission, ClientID: cliAuthClientID, AccessToken: "team-access", RefreshToken: "team-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&out)
	if err := runTeamAdmissionInvite(t.Context(), cmd); err != nil {
		t.Fatalf("runTeamAdmissionInvite: %v", err)
	}
	if !sawAdmission {
		t.Fatal("admission endpoint was not called")
	}
	var decoded teamAdmissionInviteOutput
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode output: %v\n%s", err, out.String())
	}
	if decoded.Token != "aw_inv_secret" || !strings.Contains(decoded.JoinCommand, "aw team join aw_inv_secret") || decoded.CanonicalTeamID != "shared:example.aweb.ai" {
		t.Fatalf("output=%+v", decoded)
	}
}

func TestTeamAdmissionInviteAcceptsCanonicalTeamReference(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldTeamID, oldRequestID, oldJSON := teamAdmissionInviteTeamID, teamAdmissionInviteRequestID, jsonFlag
	teamAdmissionInviteTeamID = "shared:example.aweb.ai"
	teamAdmissionInviteRequestID = "a8d857a5-7c44-45e7-8027-bf4996d5088b"
	jsonFlag = true
	t.Cleanup(func() { teamAdmissionInviteTeamID, teamAdmissionInviteRequestID, jsonFlag = oldTeamID, oldRequestID, oldJSON })
	t.Setenv("HOME", t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case strings.Replace(teamAdmissionInvitePathTemplate, "{team_id}", teamAdmissionInviteTeamID, 1):
			_ = json.NewEncoder(w).Encode(teamAdmissionInviteResponse{InviteID: "invite-1", Token: "aw_inv_secret", TokenPrefix: "aw_inv", MaxUses: 1, TeamID: "8ca9f8ea-43a6-45d1-917b-916634a3b5a7", CanonicalTeamID: teamAdmissionInviteTeamID})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	if err := saveCLIAuthConfigForScope(cliAuthScopeTeamAdmission, cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScopeTeamAdmission, ClientID: cliAuthClientID, AccessToken: "team-access", RefreshToken: "team-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd := &cobra.Command{Use: "test"}
	cmd.SetOut(&out)
	if err := runTeamAdmissionInvite(t.Context(), cmd); err != nil {
		t.Fatalf("runTeamAdmissionInvite: %v", err)
	}
	var decoded teamAdmissionInviteOutput
	if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
		t.Fatalf("decode output: %v\n%s", err, out.String())
	}
	if decoded.TeamID != "8ca9f8ea-43a6-45d1-917b-916634a3b5a7" || decoded.CanonicalTeamID != "shared:example.aweb.ai" {
		t.Fatalf("output=%+v", decoded)
	}
}

func TestTeamAdmissionInviteRejectsMismatchedCanonicalResponse(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldTeamID, oldRequestID := teamAdmissionInviteTeamID, teamAdmissionInviteRequestID
	teamAdmissionInviteTeamID = "shared:example.aweb.ai"
	teamAdmissionInviteRequestID = "a8d857a5-7c44-45e7-8027-bf4996d5088b"
	t.Cleanup(func() { teamAdmissionInviteTeamID, teamAdmissionInviteRequestID = oldTeamID, oldRequestID })
	t.Setenv("HOME", t.TempDir())

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v1/cli-auth/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "authorized"})
		case strings.Replace(teamAdmissionInvitePathTemplate, "{team_id}", teamAdmissionInviteTeamID, 1):
			_ = json.NewEncoder(w).Encode(teamAdmissionInviteResponse{InviteID: "invite-1", Token: "aw_inv_secret", TokenPrefix: "aw_inv", MaxUses: 1, TeamID: "8ca9f8ea-43a6-45d1-917b-916634a3b5a7", CanonicalTeamID: "other:example.aweb.ai"})
		default:
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
	}))
	defer server.Close()
	if err := saveCLIAuthConfigForScope(cliAuthScopeTeamAdmission, cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScopeTeamAdmission, ClientID: cliAuthClientID, AccessToken: "team-access", RefreshToken: "team-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}

	err := runTeamAdmissionInvite(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "do not match requested team reference") {
		t.Fatalf("err=%v, want team reference mismatch", err)
	}
}

func TestTeamAdmissionInviteRejectsPersonalScopeOnly(t *testing.T) {
	resetAuthCommandGlobals(t)
	oldTeamID, oldRequestID := teamAdmissionInviteTeamID, teamAdmissionInviteRequestID
	teamAdmissionInviteTeamID = "8ca9f8ea-43a6-45d1-917b-916634a3b5a7"
	teamAdmissionInviteRequestID = "a8d857a5-7c44-45e7-8027-bf4996d5088b"
	t.Cleanup(func() { teamAdmissionInviteTeamID, teamAdmissionInviteRequestID = oldTeamID, oldRequestID })
	t.Setenv("HOME", t.TempDir())
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("server should not be called with only personal credentials: %s", r.URL.Path)
	}))
	defer server.Close()
	if err := saveCLIAuthConfigForScope(cliAuthScope, cliAuthConfig{Issuer: server.URL, Resource: server.URL + "/cli", Scope: cliAuthScope, ClientID: cliAuthClientID, AccessToken: "personal-access", RefreshToken: "personal-refresh", TokenType: "bearer", ExpiresAt: time.Now().Add(time.Hour), UpdatedAt: time.Now()}); err != nil {
		t.Fatal(err)
	}
	err := runTeamAdmissionInvite(t.Context(), &cobra.Command{Use: "test"})
	if err == nil || !strings.Contains(err.Error(), "cli.team_admission") {
		t.Fatalf("err=%v, want team admission auth requirement", err)
	}
}
