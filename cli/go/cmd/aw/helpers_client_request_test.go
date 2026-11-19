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
