package main

import (
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/awid"
)

func TestResolveIdentityMessagingClientSelectionFallsBackToSigningKeyWithoutIdentityFile(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("HOME", tmp)

	memberPub, memberKey, err := awid.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	workspace := awconfig.WorktreeWorkspace{
		AwebURL:    "https://app.aweb.test",
		ActiveTeam: "backend:demo",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      "backend:demo",
			Alias:       "alice",
			WorkspaceID: "workspace-1",
			CertPath:    awconfig.TeamCertificateRelativePath("backend:demo"),
			JoinedAt:    "2026-04-09T00:00:00Z",
		}},
	}
	if err := awid.SaveSigningKey(awconfig.WorktreeSigningKeyPath(tmp), memberKey); err != nil {
		t.Fatal(err)
	}
	writeTeamCertificateWorkspaceForTest(t, tmp, workspace, &testSelectionFixture{
		AwebURL:     "https://app.aweb.test",
		TeamID:      "backend:demo",
		Alias:       "alice",
		WorkspaceID: "workspace-1",
		DID:         awid.ComputeDIDKey(memberPub),
		Lifetime:    awid.LifetimeEphemeral,
		SigningKey:  memberKey,
		CreatedAt:   "2026-04-09T00:00:00Z",
	})
	writeWorkspaceBindingForTest(t, tmp, workspace)

	client, sel, err := resolveIdentityMessagingClientSelectionForDir(tmp)
	if err != nil {
		t.Fatal(err)
	}

	wantDID := awid.ComputeDIDKey(memberPub)
	if got := client.DID(); got != wantDID {
		t.Fatalf("client did=%q want %q", got, wantDID)
	}
	if got := client.StableID(); got != "" {
		t.Fatalf("client stable_id=%q want empty", got)
	}
	if got := client.Address(); got != "" {
		t.Fatalf("client address=%q want empty", got)
	}
	if got := sel.StableID; got != "" {
		t.Fatalf("selection stable_id=%q want empty", got)
	}
	if got := sel.Address; got != "" {
		t.Fatalf("selection address=%q want empty", got)
	}
	if got := sel.DID; got != "" {
		t.Fatalf("selection did=%q want empty without identity file", got)
	}
}
