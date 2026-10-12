package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

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
	if err := writeAndSyncHookFile(backup, original); err != nil {
		_ = os.Remove(backup.Name())
		return fmt.Errorf("writing backup for %s: %w", path, err)
	}
	result.BackupPath = backup.Name()
	replacement, err := os.CreateTemp(filepath.Dir(path), ".aw-notify-cleanup-*")
	if err != nil {
		return fmt.Errorf("creating replacement (backup %s): %w", result.BackupPath, err)
	}
	defer os.Remove(replacement.Name())
	if err := replacement.Chmod(info.Mode().Perm()); err != nil {
		_ = replacement.Close()
		return err
	}
	if err := writeAndSyncHookFile(replacement, updated); err != nil {
		return err
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
	if err := os.Rename(replacement.Name(), path); err != nil {
		return err
	}
	result.Removed = removed
	return nil
}

func writeAndSyncHookFile(file *os.File, data []byte) error {
	_, err := io.Copy(file, bytes.NewReader(data))
	if err == nil {
		err = file.Sync()
	}
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}

// Only byte spans of removed array elements and their comma separators are
// deleted. No surviving JSON value, key, escape, number or whitespace is encoded
// again. Duplicate keys are refused rather than guessing which value Claude uses.
type hookJSONNode struct {
	start, end int
	object     map[string]*hookJSONNode
	array      []*hookJSONNode
	value      any
}

func (n *hookJSONNode) member(key string) *hookJSONNode {
	if n == nil {
		return nil
	}
	return n.object[key]
}
func (n *hookJSONNode) stringValue() string {
	if n == nil {
		return ""
	}
	value, _ := n.value.(string)
	return value
}

func readHookJSONNode(dec *json.Decoder, data []byte) (*hookJSONNode, error) {
	start := int(dec.InputOffset())
	// InputOffset before a value includes the preceding comma/colon and whitespace.
	for start < len(data) && (data[start] == ' ' || data[start] == '\n' || data[start] == '\r' || data[start] == '\t' || data[start] == ':' || data[start] == ',') {
		start++
	}
	token, err := dec.Token()
	if err != nil {
		return nil, err
	}
	n := &hookJSONNode{start: start, value: token}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			n.object = map[string]*hookJSONNode{}
			for dec.More() {
				keyToken, err := dec.Token()
				if err != nil {
					return nil, err
				}
				key := keyToken.(string)
				if _, exists := n.object[key]; exists {
					return nil, fmt.Errorf("duplicate JSON key %q", key)
				}
				child, err := readHookJSONNode(dec, data)
				if err != nil {
					return nil, err
				}
				n.object[key] = child
			}
		case '[':
			for dec.More() {
				child, err := readHookJSONNode(dec, data)
				if err != nil {
					return nil, err
				}
				n.array = append(n.array, child)
			}
		}
		if _, err := dec.Token(); err != nil {
			return nil, err
		}
	}
	n.end = int(dec.InputOffset())
	return n, nil
}

type hookByteSpan struct{ start, end int }

func hookArrayRemovalSpans(nodes []*hookJSONNode, remove []bool) []hookByteSpan {
	var spans []hookByteSpan
	for i := 0; i < len(nodes); {
		if !remove[i] {
			i++
			continue
		}
		first := i
		for i < len(nodes) && remove[i] {
			i++
		}
		start, end := nodes[first].start, nodes[i-1].end
		if i < len(nodes) {
			end = nodes[i].start
		} else if first > 0 {
			start = nodes[first-1].end
		}
		spans = append(spans, hookByteSpan{start, end})
	}
	return spans
}

func exactNotifyHook(n *hookJSONNode) bool {
	kind := n.member("type").stringValue()
	return n.member("command").stringValue() == notifyHookCommand && (n.member("type") == nil || kind == "command")
}

func removeNotifyHookBytes(data []byte) ([]byte, int, error) {
	if !json.Valid(data) {
		return nil, 0, fmt.Errorf("invalid JSON; settings left unchanged")
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	root, err := readHookJSONNode(dec, data)
	if err != nil {
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
		inner := group.member("hooks")
		if inner == nil && exactNotifyHook(group) {
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
			if exactNotifyHook(handler) {
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
	sort.Slice(spans, func(i, j int) bool { return spans[i].start < spans[j].start })
	var updated bytes.Buffer
	position := 0
	for _, span := range spans {
		updated.Write(data[position:span.start])
		position = span.end
	}
	updated.Write(data[position:])
	if !json.Valid(updated.Bytes()) {
		return nil, 0, fmt.Errorf("cleanup would produce invalid JSON; settings left unchanged")
	}
	return updated.Bytes(), removed, nil
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
