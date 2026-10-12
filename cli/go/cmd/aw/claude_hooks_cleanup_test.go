package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeNotifySettings(t *testing.T, root, content string) string {
	t.Helper()
	path := filepath.Join(root, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0640); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCleanupClaudeNotifyHookInstalledByOldPath(t *testing.T) {
	root := t.TempDir()
	path := writeNotifySettings(t, root, `{"other":"kept","hooks":{"PreToolUse":[{"command":"keep"}]}}`)
	// The unchanged installer is the historical --setup-hooks path.
	installed := SetupClaudeHooks(root, false)
	if installed.Error != nil {
		t.Fatal(installed.Error)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0640); err != nil {
		t.Fatal(err)
	}
	result := CleanupClaudeNotifyHook(root)
	if result.Error != nil {
		t.Fatal(result.Error)
	}
	if result.Removed != 1 || result.BackupPath == "" {
		t.Fatalf("cleanup=%+v", result)
	}
	backup, err := os.ReadFile(result.BackupPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(backup, before) {
		t.Fatal("backup differs from original")
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(after, &settings); err != nil {
		t.Fatal(err)
	}
	if hookExists(settings) || settings["other"] != "kept" {
		t.Fatalf("settings=%s", after)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0640 {
		t.Fatalf("mode=%v", info.Mode())
	}
	again := CleanupClaudeNotifyHook(root)
	if again.Error != nil || again.Removed != 0 || again.BackupPath != "" {
		t.Fatalf("repeat=%+v", again)
	}
	unchanged, _ := os.ReadFile(path)
	if !bytes.Equal(after, unchanged) {
		t.Fatal("repeat changed bytes")
	}
}

func TestCleanupClaudeNotifyHookPreservesSurvivingBytes(t *testing.T) {
	for _, tc := range []struct {
		name, before, after string
		removed             int
	}{
		{"mixed", `{
 "large":123456789012345678901234567890, "escaped":"\u0061",
 "hooks": { "PostToolUse": [
 {"matcher":".*", "hooks":[{"type":"command","command":"before"}, {"type":"command","command":"aw notify"}, {"type":"command","command":"after"}], "extra":true},
 {"command":"aw notify"},
 {"matcher":".*","hooks":[{"type":"command","command":"aw notify"}]},
 {"command":"echo aw notify"}, {"command":"aw notify --json"}, {"command":"aw notify && other"}, {"command":"bdh :notify"}
 ], "PreToolUse":[{"command":"aw notify"}] }, "other" : [1, 2]
}`, `{
 "large":123456789012345678901234567890, "escaped":"\u0061",
 "hooks": { "PostToolUse": [
 {"matcher":".*", "hooks":[{"type":"command","command":"before"}, {"type":"command","command":"after"}], "extra":true},
 {"command":"echo aw notify"}, {"command":"aw notify --json"}, {"command":"aw notify && other"}, {"command":"bdh :notify"}
 ], "PreToolUse":[{"command":"aw notify"}] }, "other" : [1, 2]
}`, 3},
		{"first", `{"hooks":{"PostToolUse":[{"command":"aw notify"},  {"command":"keep"}]}}`, `{"hooks":{"PostToolUse":[{"command":"keep"}]}}`, 1},
		{"tail", `{"hooks":{"PostToolUse":[{"command":"keep"},  {"command":"aw notify"}, {"command":"aw notify"}]}}`, `{"hooks":{"PostToolUse":[{"command":"keep"}]}}`, 2},
		{"all", `{"hooks":{"PostToolUse":[ {"command":"aw notify"} ]}}`, `{"hooks":{"PostToolUse":[  ]}}`, 1},
		{"metadata", `{"hooks":{"PostToolUse":[{"extra":42,"hooks":[{"type":"command","command":"aw notify"}]}]}}`, `{"hooks":{"PostToolUse":[{"extra":42,"hooks":[]}]}}`, 1},
		{"other-type", `{"hooks":{"PostToolUse":[{"hooks":[{"type":"prompt","command":"aw notify"}]}]}}`, `{"hooks":{"PostToolUse":[{"hooks":[{"type":"prompt","command":"aw notify"}]}]}}`, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := writeNotifySettings(t, root, tc.before)
			result := CleanupClaudeNotifyHook(root)
			if result.Error != nil || result.Removed != tc.removed {
				t.Fatalf("result=%+v", result)
			}
			after, _ := os.ReadFile(path)
			if string(after) != tc.after {
				t.Fatalf("bytes differ\ngot: %s\nwant: %s", after, tc.after)
			}
			if !json.Valid(after) {
				t.Fatalf("invalid JSON: %s", after)
			}
		})
	}
}

func TestCleanupClaudeNotifyHookRefusesUnsafeSettings(t *testing.T) {
	for _, content := range []string{`{"hooks":`, `{"hooks":{},"hooks":{"PostToolUse":[{"command":"aw notify"}]}}`} {
		root := t.TempDir()
		path := writeNotifySettings(t, root, content)
		result := CleanupClaudeNotifyHook(root)
		if result.Error == nil {
			t.Fatalf("accepted ambiguous/invalid input: %s", content)
		}
		after, _ := os.ReadFile(path)
		if string(after) != content {
			t.Fatal("changed refused input")
		}
		backups, _ := filepath.Glob(path + ".aw-notify-backup-*")
		if len(backups) != 0 {
			t.Fatal("backup for refused input")
		}
	}
	root := t.TempDir()
	outside := writeNotifySettings(t, t.TempDir(), `{"hooks":{"PostToolUse":[{"command":"aw notify"}]}}`)
	if err := os.Symlink(filepath.Dir(outside), filepath.Join(root, ".claude")); err != nil {
		t.Fatal(err)
	}
	if result := CleanupClaudeNotifyHook(root); result.Error == nil {
		t.Fatal("accepted symlinked directory")
	}
	root = t.TempDir()
	path := writeNotifySettings(t, root, `{}`)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, path); err != nil {
		t.Fatal(err)
	}
	if result := CleanupClaudeNotifyHook(root); result.Error == nil {
		t.Fatal("accepted symlinked file")
	}
	data, _ := os.ReadFile(outside)
	if !strings.Contains(string(data), "aw notify") {
		t.Fatal("modified symlink target")
	}
}

func TestCleanupClaudeNotifyHookMissingAndUnmatchedAreSilent(t *testing.T) {
	root := t.TempDir()
	if result := CleanupClaudeNotifyHook(root); result.Error != nil || result.Removed != 0 || result.BackupPath != "" {
		t.Fatalf("missing=%+v", result)
	}
	if _, err := os.Stat(filepath.Join(root, ".claude")); !os.IsNotExist(err) {
		t.Fatal("created missing directory")
	}
	path := writeNotifySettings(t, root, "{ \"other\" : true }\n")
	result := CleanupClaudeNotifyHook(root)
	if result.Error != nil || result.Removed != 0 || result.BackupPath != "" {
		t.Fatalf("unmatched=%+v", result)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "{ \"other\" : true }\n" {
		t.Fatal("unmatched changed")
	}
}
