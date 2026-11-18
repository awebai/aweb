package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/awebai/aw/internal/atomicfile"
	"github.com/awebai/aw/internal/pathpreflight"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

type claudeNotifyCleanupResult struct {
	FilePath   string `json:"file_path"`
	BackupPath string `json:"backup_path,omitempty"`
	Removed    int    `json:"removed"`
	Error      error  `json:"-"`
	ErrorText  string `json:"error,omitempty"`
}

// CleanupClaudeNotifyHook is an explicit local operation. Installing a plugin
// does not establish working delivery, so setup/init/upgrade never call this
// implicitly. Explicit setup and historical materialization wrote this settings.json.
func CleanupClaudeNotifyHook(repoRoot string) *claudeNotifyCleanupResult {
	result := &claudeNotifyCleanupResult{FilePath: filepath.Join(repoRoot, ".claude", "settings.json")}
	result.Error = cleanupClaudeNotifyFile(result)
	if result.Error != nil && result.BackupPath != "" {
		result.Error = fmt.Errorf("%w (original backup: %s)", result.Error, result.BackupPath)
	}
	return result
}

// Test seam for a concurrent settings edit before the final snapshot check.
var beforeClaudeNotifyCleanupRecheck func(string)

func cleanupClaudeNotifyFile(result *claudeNotifyCleanupResult) error {
	path := result.FilePath
	preflight := func() error {
		return pathpreflight.PreflightFile(path, "Claude hook config", pathpreflight.AllowTempAmbientSymlinkPrefix())
	}
	if err := preflight(); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s is not a regular file", path)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	updated, removed, err := removeNotifyHookBytes(original)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}
	if removed == 0 {
		return nil
	}
	if info.Mode().Perm()&0200 == 0 {
		return fmt.Errorf("%s is read-only; no hook removed", path)
	}

	// Exclusive backup creation must succeed before changing the settings file.
	backup, err := os.CreateTemp(filepath.Dir(path), "settings.json.aw-notify-backup-*")
	if err != nil {
		return fmt.Errorf("creating backup for %s: %w", path, err)
	}
	backupPath := backup.Name()
	if err := backup.Close(); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			return errors.Join(err, removeErr)
		}
		return err
	}
	if err := atomicfile.Write(backupPath, original, 0o600); err != nil {
		if removeErr := os.Remove(backupPath); removeErr != nil {
			return errors.Join(err, removeErr)
		}
		return fmt.Errorf("writing backup for %s: %w", path, err)
	}
	result.BackupPath = backupPath
	if beforeClaudeNotifyCleanupRecheck != nil {
		beforeClaudeNotifyCleanupRecheck(path)
	}
	if err := preflight(); err != nil {
		return err
	}
	currentInfo, err := os.Lstat(path)
	if err != nil {
		return err
	}
	current, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !os.SameFile(info, currentInfo) || info.Mode() != currentInfo.Mode() || !bytes.Equal(original, current) {
		return fmt.Errorf("%s changed during cleanup; left it unchanged (backup %s)", path, result.BackupPath)
	}
	if err := atomicfile.Write(path, updated, info.Mode().Perm()); err != nil {
		return err
	}
	result.Removed = removed
	return nil
}

func removeNotifyHookBytes(data []byte) ([]byte, int, error) {
	root, err := parseHookJSON(data)
	if err != nil {
		return nil, 0, err
	}
	if _, err := notifyHandlers(root); err != nil {
		return nil, 0, err
	}

	post := root.member("hooks").member("PostToolUse")
	if post == nil {
		return data, 0, nil
	}
	groups := post.array
	removeGroups := make([]bool, len(groups))
	var spans []hookByteSpan
	removed := 0
	for i, group := range groups {
		if !ownedNotifyGroup(group) {
			continue
		}
		inner := group.member("hooks")
		if inner == nil && notifyHookMatches(group, notifyHookCommand) {
			removeGroups[i] = true
			removed++
			continue
		}
		if inner == nil || len(inner.array) == 0 {
			continue
		}
		removeInner := make([]bool, len(inner.array))
		count := 0
		for j, handler := range inner.array {
			if notifyHookMatches(handler, notifyHookCommand) {
				removeInner[j] = true
				count++
			}
		}
		if count == 0 {
			continue
		}
		removed += count
		// Drop an empty standard matcher group; preserve any additional metadata.
		standard := true
		for key := range group.object {
			if key != "matcher" && key != "hooks" {
				standard = false
			}
		}
		if count == len(inner.array) && standard {
			removeGroups[i] = true
		} else {
			spans = append(spans, hookArrayRemovalSpans(inner.array, removeInner)...)
		}
	}
	spans = append(spans, hookArrayRemovalSpans(groups, removeGroups)...)

	edits := make([]hookJSONEdit, 0, len(spans))
	for _, span := range spans {
		edits = append(edits, hookJSONEdit{start: span.start, end: span.end})
	}
	updated, err := editHookJSON(data, edits)
	if err != nil {
		return nil, 0, err
	}
	return updated, removed, nil
}

func runRemoveClaudeNotifyHook(cmd *cobra.Command) error {
	var conflict string
	cmd.Flags().Visit(func(flag *pflag.Flag) {
		switch flag.Name {
		case "remove-notify-hook", "json", "debug", "trace", "identity-home", "server-name", "team":
		default:
			conflict = flag.Name
		}
	})
	if conflict != "" || initSetupHooks || initSetupChannel || initInjectDocs {
		return usageError("--remove-notify-hook cannot be combined with other init actions; run it on its own")
	}
	wd, err := os.Getwd()
	if err != nil {
		return err
	}
	targets := []string{wd}
	if root := resolveRepoRoot(wd); root != wd {
		targets = append(targets, root)
	}
	results := make([]*claudeNotifyCleanupResult, 0, len(targets))
	var failures []error
	for _, target := range targets {
		result := CleanupClaudeNotifyHook(target)
		if result.Error != nil {
			result.ErrorText = result.Error.Error()
			failures = append(failures, fmt.Errorf("%s: %w", result.FilePath, result.Error))
		}
		results = append(results, result)
		if !jsonFlag {
			switch {
			case result.Error != nil:
				fmt.Fprintf(cmd.OutOrStdout(), "Could not remove Claude Code notify hook from %s: %v\n", result.FilePath, result.Error)
			case result.Removed == 0:
				fmt.Fprintf(cmd.OutOrStdout(), "No exact aw notify PostToolUse hook in %s; settings unchanged\n", result.FilePath)
			default:
				fmt.Fprintf(cmd.OutOrStdout(), "Removed %d aw notify PostToolUse hook(s) from %s; backup: %s\n", result.Removed, result.FilePath, result.BackupPath)
				fmt.Fprintln(cmd.OutOrStdout(), "You can delete the backup once you have checked the updated settings.")
			}
		}
	}
	if jsonFlag {
		output := struct {
			Results []*claudeNotifyCleanupResult `json:"results"`
		}{Results: results}
		if err := writeOutput(cmd.OutOrStdout(), output, nil); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}
