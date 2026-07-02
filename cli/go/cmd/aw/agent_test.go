package main

import (
	"io"
	"path/filepath"
	"strings"
	"testing"
)

func resetAgentGlobals(t *testing.T) {
	t.Helper()
	oldHome := agentHomeFlag
	t.Cleanup(func() { agentHomeFlag = oldHome })
	agentHomeFlag = ""
}

func TestAgentCommandKeepsProfileOnly(t *testing.T) {
	if agentCmd == nil {
		t.Fatal("agent command is not registered")
	}
	if _, _, err := agentCmd.Find([]string{"profile", "show"}); err != nil {
		t.Fatalf("agent profile show missing: %v", err)
	}
	for _, removed := range []string{"start", "status", "stop", "restart", "logs"} {
		if cmd, _, err := agentCmd.Find([]string{removed}); err == nil && cmd != nil && cmd.Name() == removed {
			t.Fatalf("removed aw agent %s command is still registered", removed)
		}
	}
}

func TestAgentCommandRejectsRemovedRuntimeSubcommands(t *testing.T) {
	t.Cleanup(func() {
		rootCmd.SetArgs(nil)
		rootCmd.SetOut(nil)
		rootCmd.SetErr(nil)
	})
	for _, removed := range []string{"start", "status", "stop", "restart", "logs"} {
		t.Run(removed, func(t *testing.T) {
			rootCmd.SetArgs([]string{"agent", removed})
			rootCmd.SetOut(io.Discard)
			rootCmd.SetErr(io.Discard)
			err := rootCmd.Execute()
			if err == nil {
				t.Fatalf("removed runtime subcommand %q succeeded", removed)
			}
			if !strings.Contains(err.Error(), "unknown command") {
				t.Fatalf("error=%v, want unknown command", err)
			}
		})
	}
}

func TestResolveAgentHomeRejectsUnsafeDefaultNameUnlessHomeExplicit(t *testing.T) {
	resetAgentGlobals(t)
	root := t.TempDir()
	t.Chdir(root)
	if _, err := resolveAgentHome("../developer"); err == nil || !strings.Contains(err.Error(), "invalid agent name") {
		t.Fatalf("unsafe default name error=%v", err)
	}
	home := filepath.Join(root, "explicit-home")
	agentHomeFlag = home
	got, err := resolveAgentHome("../developer")
	if err != nil {
		t.Fatalf("explicit --home should allow non-default name token: %v", err)
	}
	if got != home {
		t.Fatalf("home=%q, want %q", got, home)
	}
}
