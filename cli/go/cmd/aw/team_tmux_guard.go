package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
)

//go:embed tmux_guard.sh
var embeddedTmuxGuard []byte

func ensureTeamUpGuardedAgentPath() (string, error) {
	guardDir, err := awconfig.PathInUserState("guard-bin")
	if err != nil {
		return "", fmt.Errorf("resolve tmux guard directory: %w", err)
	}
	if err := materializeTeamUpTmuxGuard(filepath.Join(guardDir, "tmux")); err != nil {
		return "", err
	}
	return guardDir + string(os.PathListSeparator) + os.Getenv("PATH"), nil
}

func materializeTeamUpTmuxGuard(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("create tmux guard directory: %w", err)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmux-guard-*")
	if err != nil {
		return fmt.Errorf("create tmux guard: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o755); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod tmux guard: %w", err)
	}
	if _, err := tmp.Write(embeddedTmuxGuard); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write tmux guard: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync tmux guard: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close tmux guard: %w", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install tmux guard: %w", err)
	}
	return nil
}
