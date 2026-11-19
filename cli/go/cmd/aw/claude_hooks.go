package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/internal/atomicfile"
	"github.com/awebai/aw/internal/pathpreflight"
)

const (
	notifyHookCommand       = "aw notify"
	legacyNotifyHookCommand = "bdh :notify"
)

type claudeHooksResult struct {
	Created       bool
	Updated       bool
	AlreadyExists bool
	Skipped       bool
	Error         error
	FilePath      string
}

type hookConfirmation uint8

const (
	skipHookConfirmation hookConfirmation = iota
	requireHookConfirmation
)

func hookConfirmationForTerminal(interactive bool) hookConfirmation {
	if interactive {
		return requireHookConfirmation
	}
	return skipHookConfirmation
}

func SetupClaudeHooks(repoRoot string, confirmation hookConfirmation) *claudeHooksResult {
	result := &claudeHooksResult{
		FilePath: filepath.Join(repoRoot, ".claude", "settings.json"),
	}

	if err := pathpreflight.PreflightFile(result.FilePath, "Claude hook config", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		result.Error = err
		result.Skipped = true
		return result
	}

	content, err := os.ReadFile(result.FilePath)
	if err != nil && !os.IsNotExist(err) {
		result.Error = fmt.Errorf("reading %s: %w", result.FilePath, err)
		result.Skipped = true
		return result
	}

	input := content
	if len(input) == 0 {
		input = []byte("{}\n")
	}
	_, exists, err := installNotifyHookBytes(input)
	if err != nil {
		result.Error = hookSettingsParseError(result.FilePath, err)
		result.Skipped = true
		return result
	}
	if exists {
		result.AlreadyExists = true
		return result
	}
	if confirmation == requireHookConfirmation {
		answer, err := promptString("Enable Claude Code polling fallback? (chat only, after tool calls; no mail or idle wake-ups) (y/n)", "n")
		if err != nil {
			result.Error = err
			result.Skipped = true
			return result
		}
		normalized := strings.ToLower(strings.TrimSpace(answer))
		if normalized != "y" && normalized != "yes" {
			result.Skipped = true
			return result
		}
	}
	settingsDir := filepath.Dir(result.FilePath)
	if err := pathpreflight.PreflightDir(settingsDir, "Claude hook config directory", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		result.Error = err
		result.Skipped = true
		return result
	}
	if err := os.MkdirAll(settingsDir, 0o755); err != nil {
		result.Error = fmt.Errorf("creating %s: %w", settingsDir, err)
		result.Skipped = true
		return result
	}
	if err := pathpreflight.PreflightDir(settingsDir, "Claude hook config directory", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		result.Error = err
		result.Skipped = true
		return result
	}

	if err := withHookSettingsLock(result.FilePath, func() error { return installClaudeNotifyFile(result) }); err != nil {
		result.Error = err
		result.Skipped = true
		return result
	}
	return result
}

// installClaudeNotifyFile reads after confirmation, while the settings lock is
// held, so an edit made during the prompt remains part of the replacement.
func installClaudeNotifyFile(result *claudeHooksResult) error {
	if err := pathpreflight.PreflightFile(result.FilePath, "Claude hook config", pathpreflight.AllowTempAmbientSymlinkPrefix()); err != nil {
		return err
	}
	content, err := os.ReadFile(result.FilePath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading %s: %w", result.FilePath, err)
	}
	input := content
	if len(input) == 0 {
		input = []byte("{}\n")
	}
	data, exists, err := installNotifyHookBytes(input)
	if err != nil {
		return hookSettingsParseError(result.FilePath, err)
	}
	if exists {
		result.AlreadyExists = true
		return nil
	}
	mode := os.FileMode(0o644)
	info, statErr := os.Stat(result.FilePath)
	if statErr == nil {
		mode = info.Mode().Perm()
	} else if !os.IsNotExist(statErr) {
		return statErr
	}
	if err := atomicfile.Write(result.FilePath, data, mode); err != nil {
		return fmt.Errorf("writing %s: %w", result.FilePath, err)
	}
	if len(content) == 0 {
		result.Created = true
	} else {
		result.Updated = true
	}
	return nil
}

func printClaudeHooksResult(result *claudeHooksResult) {
	if result == nil {
		return
	}
	fmt.Fprintln(os.Stderr, "Claude Code polling fallback: chat only, after tool calls; no mail or idle wake-ups. Prefer the aweb channel plugin or host wake broker.")
	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "Warning: Claude Code hook: not installed. %v\n", result.Error)
		return
	}
	if result.AlreadyExists {
		fmt.Fprintln(commandStdout, "Claude Code hook: already configured")
		return
	}
	if result.Skipped {
		fmt.Fprintln(commandStdout, "Claude Code hook: skipped")
		return
	}
	if result.Created {
		fmt.Fprintf(commandStdout, "Created %s with notification hook\n", result.FilePath)
		return
	}
	if result.Updated {
		fmt.Fprintf(commandStdout, "Added notification hook to %s\n", result.FilePath)
	}
}
