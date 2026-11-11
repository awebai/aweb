package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/awconfig"
	"github.com/awebai/aw/internal/atomicfile"
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
	if err := atomicfile.Write(path, embeddedTmuxGuard, 0o755); err != nil {
		return fmt.Errorf("install tmux guard: %w", err)
	}
	return nil
}
