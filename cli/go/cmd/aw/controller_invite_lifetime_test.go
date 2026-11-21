package main

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestControllerInviteStoresItsOwnLifetime(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	t.Setenv("AW_CONFIG_PATH", "")
	root := t.TempDir()
	_, key, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := awconfig.SaveTeamKey("example.com", "backend", key); err != nil {
		t.Fatal(err)
	}
	for _, duration := range []time.Duration{0, 72 * time.Hour} {
		created, err := mintPlannedTeamInvite(teamInviteMintRequest{
			Plan: teamInvitePlan{Kind: inviteAuthorityController, Source: teamInviteSource{
				WorkingDir: root, Home: awconfig.IdentityHome{Root: awconfig.WorktreeIdentityHome(root)},
				Domain: "example.com", Team: "backend", RegistryURL: "https://registry.example", AwebURL: "https://service.example",
			}}, Scope: inviteMemberLocal, ExpiresAfter: duration,
		})
		if err != nil {
			t.Fatal(err)
		}
		saved, err := awconfig.LoadTeamInvite(created.InviteID)
		if err != nil {
			t.Fatal(err)
		}
		state, err := awconfig.InspectTeamInviteLifecycle(awconfig.TeamInviteLifecycleRequest{Invite: saved, Now: time.Now()})
		want := duration
		if want == 0 {
			want = 24 * time.Hour
		}
		if err != nil || state.State != awconfig.TeamInviteUnused || state.ExpiresAt.Sub(state.CreatedAt) != want || created.ExpiresAt != saved.ExpiresAt {
			t.Fatalf("stored lifetime=%+v err=%v", state, err)
		}
		public, err := base64.RawURLEncoding.DecodeString(created.Token)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(public), "expires") {
			t.Fatal("bearer supplied its own expiry authority")
		}
	}
}
