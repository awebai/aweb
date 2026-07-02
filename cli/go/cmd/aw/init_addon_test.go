package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
	"github.com/spf13/cobra"
)

func TestRunInitSetupChannelExistingWorkspaceStaysAddonWithURLFlags(t *testing.T) {
	oldURL := initURL
	oldAwebURL := initAwebURL
	oldAWIDRegistry := initAWIDRegistry
	oldBYOD := initBYOD
	oldUsername := initUsername
	oldDomain := initDomain
	oldAlias := initAlias
	oldName := initName
	oldInjectDocs := initInjectDocs
	oldSetupHooks := initSetupHooks
	oldSetupChannel := initSetupChannel
	oldRole := initRole
	oldPersistent := initPersistent
	oldIsTTY := initIsTTY
	t.Cleanup(func() {
		initURL = oldURL
		initAwebURL = oldAwebURL
		initAWIDRegistry = oldAWIDRegistry
		initBYOD = oldBYOD
		initUsername = oldUsername
		initDomain = oldDomain
		initAlias = oldAlias
		initName = oldName
		initInjectDocs = oldInjectDocs
		initSetupHooks = oldSetupHooks
		initSetupChannel = oldSetupChannel
		initRole = oldRole
		initPersistent = oldPersistent
		initIsTTY = oldIsTTY
	})

	tmp := t.TempDir()
	writeWorkspaceBindingForTest(t, tmp, awconfig.WorktreeWorkspace{
		AwebURL: "https://app.aweb.ai/api",
		Memberships: []awconfig.WorktreeMembership{{
			TeamID:      "default:alice.aweb.ai",
			Alias:       "alice",
			RoleName:    "coordinator",
			WorkspaceID: "ws-1",
			CertPath:    ".aw/team-certs/default_alice.aweb.ai.json",
			JoinedAt:    "2026-05-15T00:00:00Z",
		}},
	})

	origWd, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(origWd)

	t.Setenv(initAPIKeyEnvVar, "")
	t.Setenv("AWEB_URL", "")
	initURL = "https://app.aweb.ai"
	initAwebURL = "https://app.aweb.ai/api"
	initAWIDRegistry = "https://awid.ai"
	initBYOD = false
	initUsername = ""
	initDomain = ""
	initAlias = ""
	initName = ""
	initInjectDocs = false
	initSetupHooks = false
	initSetupChannel = true
	initRole = ""
	initPersistent = false
	initIsTTY = func() bool { return false }
	oldRunner := runClaudeChannelPluginCommand
	runClaudeChannelPluginCommand = func(args ...string) error { return nil }
	t.Cleanup(func() { runClaudeChannelPluginCommand = oldRunner })
	bin := filepath.Join(tmp, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "claude"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))

	if err := runInit(&cobra.Command{}, nil); err != nil {
		t.Fatalf("runInit setup-channel addon failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".mcp.json")); !os.IsNotExist(err) {
		t.Fatalf("setup-channel unexpectedly created broken .mcp.json: %v", err)
	}
}
