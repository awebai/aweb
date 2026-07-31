package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/awebai/aw/awconfig"
)

const hermeticClaudeDirEnv = "AW_TEST_HERMETIC_CLAUDE_DIR"

func assertHermeticClaudeOnPath(t *testing.T) {
	t.Helper()
	dir := os.Getenv(hermeticClaudeDirEnv)
	if dir == "" {
		t.Fatal("package test harness did not identify its hermetic Claude directory")
	}
	got, err := exec.LookPath("claude")
	if err != nil {
		t.Fatalf("package test harness did not provide Claude on PATH: %v", err)
	}
	want := filepath.Join(dir, "claude")
	if filepath.Clean(got) != filepath.Clean(want) {
		t.Fatalf("claude resolved from ambient PATH: got %q, want harness executable %q", got, want)
	}
}

func restoreTestEnvironment(name, value string, existed bool) error {
	if existed {
		return os.Setenv(name, value)
	}
	return os.Unsetenv(name)
}

func TestMain(m *testing.M) {
	_ = os.Unsetenv(awconfig.IdentityHomeEnv)

	oldRunner := runClaudeChannelPluginCommand
	oldPath, hadPath := os.LookupEnv("PATH")
	oldHermeticDir, hadHermeticDir := os.LookupEnv(hermeticClaudeDirEnv)

	dir, err := os.MkdirTemp("", "aw-cmd-test-claude-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create hermetic Claude directory: %v\n", err)
		os.Exit(1)
	}
	claudePath := filepath.Join(dir, "claude")
	if err := os.WriteFile(claudePath, []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "create hermetic Claude executable: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv(hermeticClaudeDirEnv, dir); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "publish hermetic Claude directory: %v\n", err)
		os.Exit(1)
	}
	testPath := dir
	if hadPath && oldPath != "" {
		testPath += string(os.PathListSeparator) + oldPath
	}
	if err := os.Setenv("PATH", testPath); err != nil {
		_ = restoreTestEnvironment(hermeticClaudeDirEnv, oldHermeticDir, hadHermeticDir)
		_ = os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "prepend hermetic Claude to PATH: %v\n", err)
		os.Exit(1)
	}

	// Channel setup installs the aweb-channel plugin at user scope, which is
	// shared by every agent on the host and is not something running the unit
	// tests should touch. The runner stub protects in-process tests. The inert
	// executable also makes LookPath deterministic and is inherited by child aw
	// processes, which do not share this package global.
	runClaudeChannelPluginCommand = func(args ...string) error { return nil }
	code := m.Run()

	// os.Exit does not run defers. Restore every package/environment mutation and
	// remove the executable explicitly before exiting the test process.
	runClaudeChannelPluginCommand = oldRunner
	if err := restoreTestEnvironment("PATH", oldPath, hadPath); err != nil {
		fmt.Fprintf(os.Stderr, "restore PATH after cmd/aw tests: %v\n", err)
		code = 1
	}
	if err := restoreTestEnvironment(hermeticClaudeDirEnv, oldHermeticDir, hadHermeticDir); err != nil {
		fmt.Fprintf(os.Stderr, "restore %s after cmd/aw tests: %v\n", hermeticClaudeDirEnv, err)
		code = 1
	}
	if err := os.RemoveAll(dir); err != nil {
		fmt.Fprintf(os.Stderr, "remove hermetic Claude directory: %v\n", err)
		code = 1
	}
	os.Exit(code)
}
