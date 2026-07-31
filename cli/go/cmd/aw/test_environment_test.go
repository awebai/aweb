package main

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/awebai/aw/awconfig"
)

const (
	hermeticClaudeDirEnv             = "AW_TEST_HERMETIC_CLAUDE_DIR"
	windowsNoCurrentDirectoryPathEnv = "NoDefaultCurrentDirectoryInExePath"
)

func hermeticClaudeExecutableName(goos string) string {
	if goos == "windows" {
		return "claude.exe"
	}
	return "claude"
}

func hermeticClaudeLookupEnvironment(goos string) map[string]string {
	if goos != "windows" {
		return nil
	}
	return map[string]string{
		"PATHEXT":                        ".COM;.EXE;.BAT;.CMD",
		windowsNoCurrentDirectoryPathEnv: "1",
	}
}

func sameHermeticExecutablePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func runningAsHermeticClaude() bool {
	dir := os.Getenv(hermeticClaudeDirEnv)
	if dir == "" {
		return false
	}
	executable, err := os.Executable()
	if err != nil {
		return false
	}
	want := filepath.Join(dir, hermeticClaudeExecutableName(runtime.GOOS))
	return sameHermeticExecutablePath(executable, want)
}

func copyHermeticClaudeExecutable(destination string) error {
	source, err := os.Executable()
	if err != nil {
		return err
	}
	in, err := os.Open(source)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.OpenFile(destination, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o700)
	if err != nil {
		return err
	}
	_, copyErr := io.Copy(out, in)
	closeErr := out.Close()
	if copyErr != nil {
		_ = os.Remove(destination)
		return copyErr
	}
	if closeErr != nil {
		_ = os.Remove(destination)
		return closeErr
	}
	return nil
}

func createHermeticClaudeExecutable(dir string) (string, error) {
	path := filepath.Join(dir, hermeticClaudeExecutableName(runtime.GOOS))
	if runtime.GOOS == "windows" {
		return path, copyHermeticClaudeExecutable(path)
	}
	return path, os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o700)
}

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
	want := filepath.Join(dir, hermeticClaudeExecutableName(runtime.GOOS))
	if !sameHermeticExecutablePath(got, want) {
		t.Fatalf("claude resolved from ambient PATH: got %q, want harness executable %q", got, want)
	}
}

func TestHermeticClaudeExecutableNameIsRunnableOnTargetOS(t *testing.T) {
	for goos, want := range map[string]string{
		"darwin":  "claude",
		"linux":   "claude",
		"windows": "claude.exe",
	} {
		t.Run(goos, func(t *testing.T) {
			if got := hermeticClaudeExecutableName(goos); got != want {
				t.Fatalf("hermetic Claude executable for %s=%q, want %q", goos, got, want)
			}
		})
	}
}

func TestHermeticClaudeWindowsLookupExcludesCurrentDirectory(t *testing.T) {
	environment := hermeticClaudeLookupEnvironment("windows")
	if _, ok := environment[windowsNoCurrentDirectoryPathEnv]; !ok {
		t.Fatal("Windows hermetic Claude environment permits current-directory lookup ahead of PATH")
	}
}

func TestHermeticClaudeExecutableRunsInChildProcess(t *testing.T) {
	assertHermeticClaudeOnPath(t)
	if output, err := exec.Command("claude", "plugin", "install", "must-stay-inert").CombinedOutput(); err != nil {
		t.Fatalf("execute hermetic Claude: %v\n%s", err, output)
	}
}

func restoreTestEnvironment(name, value string, existed bool) error {
	if existed {
		return os.Setenv(name, value)
	}
	return os.Unsetenv(name)
}

func TestMain(m *testing.M) {
	if runningAsHermeticClaude() {
		os.Exit(0)
	}
	_ = os.Unsetenv(awconfig.IdentityHomeEnv)

	oldRunner := runClaudeChannelPluginCommand
	oldPath, hadPath := os.LookupEnv("PATH")
	oldPathExt, hadPathExt := os.LookupEnv("PATHEXT")
	oldNoCurrentDirectoryPath, hadNoCurrentDirectoryPath := os.LookupEnv(windowsNoCurrentDirectoryPathEnv)
	oldHermeticDir, hadHermeticDir := os.LookupEnv(hermeticClaudeDirEnv)

	dir, err := os.MkdirTemp("", "aw-cmd-test-claude-")
	if err != nil {
		fmt.Fprintf(os.Stderr, "create hermetic Claude directory: %v\n", err)
		os.Exit(1)
	}
	if _, err := createHermeticClaudeExecutable(dir); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "create hermetic Claude executable: %v\n", err)
		os.Exit(1)
	}
	if err := os.Setenv(hermeticClaudeDirEnv, dir); err != nil {
		_ = os.RemoveAll(dir)
		fmt.Fprintf(os.Stderr, "publish hermetic Claude directory: %v\n", err)
		os.Exit(1)
	}
	if runtime.GOOS == "windows" {
		lookupEnvironment := hermeticClaudeLookupEnvironment(runtime.GOOS)
		if err := os.Setenv(windowsNoCurrentDirectoryPathEnv, lookupEnvironment[windowsNoCurrentDirectoryPathEnv]); err != nil {
			_ = restoreTestEnvironment(hermeticClaudeDirEnv, oldHermeticDir, hadHermeticDir)
			_ = os.RemoveAll(dir)
			fmt.Fprintf(os.Stderr, "disable Windows current-directory executable lookup: %v\n", err)
			os.Exit(1)
		}
		if err := os.Setenv("PATHEXT", lookupEnvironment["PATHEXT"]); err != nil {
			_ = restoreTestEnvironment(windowsNoCurrentDirectoryPathEnv, oldNoCurrentDirectoryPath, hadNoCurrentDirectoryPath)
			_ = restoreTestEnvironment(hermeticClaudeDirEnv, oldHermeticDir, hadHermeticDir)
			_ = os.RemoveAll(dir)
			fmt.Fprintf(os.Stderr, "set deterministic PATHEXT: %v\n", err)
			os.Exit(1)
		}
	}
	testPath := dir
	if hadPath && oldPath != "" {
		testPath += string(os.PathListSeparator) + oldPath
	}
	if err := os.Setenv("PATH", testPath); err != nil {
		if runtime.GOOS == "windows" {
			_ = restoreTestEnvironment("PATHEXT", oldPathExt, hadPathExt)
			_ = restoreTestEnvironment(windowsNoCurrentDirectoryPathEnv, oldNoCurrentDirectoryPath, hadNoCurrentDirectoryPath)
		}
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
	if runtime.GOOS == "windows" {
		if err := restoreTestEnvironment("PATHEXT", oldPathExt, hadPathExt); err != nil {
			fmt.Fprintf(os.Stderr, "restore PATHEXT after cmd/aw tests: %v\n", err)
			code = 1
		}
		if err := restoreTestEnvironment(windowsNoCurrentDirectoryPathEnv, oldNoCurrentDirectoryPath, hadNoCurrentDirectoryPath); err != nil {
			fmt.Fprintf(os.Stderr, "restore %s after cmd/aw tests: %v\n", windowsNoCurrentDirectoryPathEnv, err)
			code = 1
		}
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
