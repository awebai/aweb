package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestEnsureTeamUpGuardedAgentPathMaterializesBlockingShim(t *testing.T) {
	home := t.TempDir()
	realBin := filepath.Join(t.TempDir(), "real-bin")
	if err := os.MkdirAll(realBin, 0o755); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(t.TempDir(), "real-tmux.log")
	realTmux := filepath.Join(realBin, "tmux")
	realScript := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> \"$TMUX_TEST_LOG\"\n"
	if err := os.WriteFile(realTmux, []byte(realScript), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("PATH", realBin+string(os.PathListSeparator)+"/usr/bin:/bin")
	t.Setenv("TMUX_TEST_LOG", logPath)

	guardedPath, err := ensureTeamUpGuardedAgentPath()
	if err != nil {
		t.Fatal(err)
	}
	guardPath := filepath.Join(home, ".config", "aw", "guard-bin", "tmux")
	if !strings.HasPrefix(guardedPath, filepath.Dir(guardPath)+string(os.PathListSeparator)) {
		t.Fatalf("guarded PATH=%q", guardedPath)
	}
	info, err := os.Stat(guardPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o755 {
		t.Fatalf("guard mode=%o", info.Mode().Perm())
	}

	for _, operation := range []string{"kill-server", "kill-serv"} {
		blocked := exec.Command(guardPath, operation)
		blocked.Env = os.Environ()
		output, err := blocked.CombinedOutput()
		var exitErr *exec.ExitError
		if !errors.As(err, &exitErr) || exitErr.ExitCode() != 86 {
			t.Fatalf("%s err=%v output=%s", operation, err, output)
		}
		if !strings.Contains(string(output), "kill-server REFUSED") {
			t.Fatalf("blocked output=%q", output)
		}
	}
	if _, err := os.Stat(logPath); !os.IsNotExist(err) {
		t.Fatalf("blocked kill reached real tmux: %v", err)
	}

	allowed := exec.Command(guardPath, "list-sessions")
	allowed.Env = os.Environ()
	if output, err := allowed.CombinedOutput(); err != nil {
		t.Fatalf("allowed command err=%v output=%s", err, output)
	}
	log, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(string(log)) != "list-sessions" {
		t.Fatalf("real tmux log=%q", log)
	}
}

func TestEmbeddedTmuxGuardMatchesRepositoryGuard(t *testing.T) {
	_, sourcePath, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("resolve test source path")
	}
	repositoryGuardPath := filepath.Clean(filepath.Join(filepath.Dir(sourcePath), "../../../../scripts/guard-bin/tmux"))
	repositoryGuard, err := os.ReadFile(repositoryGuardPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(embeddedTmuxGuard, repositoryGuard) {
		t.Fatal("embedded and repository tmux guards diverged")
	}
}

func TestLaunchAgentWindowFailsClosedWhenGuardCannotBePrepared(t *testing.T) {
	resetTeamUpTmuxForTest(t)
	teamUpSessionExists = func(string) bool { return true }
	teamUpGuardedAgentPath = func() (string, error) { return "", errors.New("guard unavailable") }

	agent := teamUpAgentPlan{Name: "developer", HomeDir: "/tmp/dev", Command: []string{"pi", "--approve"}}
	err := launchAgentWindow(nil, teamUpConfiguredTmuxContext, "aw-team", agent)
	if err == nil || !strings.Contains(err.Error(), "prepare tmux guard") {
		t.Fatalf("error=%v", err)
	}
}
