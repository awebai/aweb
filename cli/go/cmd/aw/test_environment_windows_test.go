//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestHermeticClaudeWinsOverCompetingCurrentDirectoryExecutable(t *testing.T) {
	if _, ok := os.LookupEnv(windowsNoCurrentDirectoryPathEnv); !ok {
		t.Fatalf("%s is absent, so Windows may search the working directory before PATH", windowsNoCurrentDirectoryPathEnv)
	}

	oldWorkingDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	workingDir := t.TempDir()
	if err := os.Chdir(workingDir); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(oldWorkingDir); err != nil {
			t.Errorf("restore working directory: %v", err)
		}
	})

	competing := filepath.Join(workingDir, "claude.exe")
	if err := os.WriteFile(competing, []byte("not a runnable PE executable"), 0o600); err != nil {
		t.Fatal(err)
	}

	// This assertion calls exec.LookPath from the competing executable's own
	// directory and requires the marked harness executable ahead of it.
	assertHermeticClaudeOnPath(t)

	cmd := exec.Command("claude", "plugin", "install", "must-stay-inert")
	cmd.Dir = workingDir
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("direct child selected the competing current-directory executable: %v\n%s", err, output)
	}
}
