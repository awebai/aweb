package main

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

func TestGrantClientUsesRequestedTeamInsteadOfAmbientFlag(t *testing.T) {
	workingDir := t.TempDir()
	home := filepath.Join(workingDir, ".aw")
	writeGrantHomeForTest(t, home, "https://app.example.test")
	previousHome, previousTeam := activeIdentityHome, teamFlag
	activeIdentityHome = awconfig.IdentityHome{Root: home}
	teamFlag = "backend:acme.com"
	t.Cleanup(func() { activeIdentityHome, teamFlag = previousHome, previousTeam })
	resolveURL := func(_ context.Context, raw string) (string, error) { return raw, nil }
	client, selection, err := buildClientSelectionForDir(context.Background(), workingDir, "other:acme.com", resolveURL)
	if err == nil || !strings.Contains(err.Error(), "--team other:acme.com conflicts") || client != nil || selection != nil {
		t.Fatalf("grant ignored requested team: client=%v selection=%+v err=%v", client, selection, err)
	}
	client, selection, err = buildClientSelectionForDir(context.Background(), workingDir, "backend:acme.com", resolveURL)
	if err != nil || client == nil || selection.TeamID != "backend:acme.com" {
		t.Fatalf("matching grant team refused: selection=%+v err=%v", selection, err)
	}
}

func TestClientRequestKeepsExplicitHomeTeamAndRecordingPolicy(t *testing.T) {
	workingDir := t.TempDir()
	home := awconfig.IdentityHome{Root: filepath.Join(t.TempDir(), "principal"), Source: awconfig.IdentityHomeFlag}
	_, grant := writeGrantHomeForTest(t, home.Root, "https://app.example.test")
	previousClient, previousHome, previousTeam := lastClient, activeIdentityHome, teamFlag
	t.Cleanup(func() { lastClient, activeIdentityHome, teamFlag = previousClient, previousHome, previousTeam })
	activeIdentityHome = awconfig.IdentityHome{Root: filepath.Join(t.TempDir(), "wrong")}
	teamFlag = "wrong:acme.com"
	lastClient = nil
	request := clientRequest{
		WorkingDir: workingDir, Home: home, TeamID: grant.TeamID,
		BaseURL: func(_ context.Context, value string) (string, error) { return value, nil },
		Record: clientDetached,
	}
	client, selected, err := newClient(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if selected.TeamID != grant.TeamID || selected.IdentityHome != home.Root || !selected.ExternalIdentityHome || client.GrantID() != grant.GrantID {
		t.Fatalf("request was replaced by ambient selection: %+v", selected)
	}
	if lastClient != nil {
		t.Fatal("detached client changed command state")
	}
	request.Record = clientForCommand
	client, _, err = newClient(context.Background(), request)
	if err != nil || lastClient != client {
		t.Fatalf("command client was not recorded: %v", err)
	}
	request.TeamID = "other:acme.com"
	if _, _, err := newClient(context.Background(), request); err == nil || !strings.Contains(err.Error(), "--team other:acme.com conflicts") {
		t.Fatalf("conflicting requested team: %v", err)
	}
	if lastClient != client {
		t.Fatal("failed construction replaced the last successful command client")
	}
}
