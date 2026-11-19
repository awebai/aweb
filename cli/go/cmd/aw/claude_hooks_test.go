package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSetupClaudeHooksCreatesNew(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	result := SetupClaudeHooks(tmp, skipHookConfirmation)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Created {
		t.Fatal("expected created")
	}
	data, err := os.ReadFile(filepath.Join(tmp, ".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if !hookExists(t, settings) {
		t.Fatal("expected hook in file")
	}
}

func TestSetupClaudeHooksRejectsSymlinkedClaudeDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	outsideDir := t.TempDir()
	if err := os.Symlink(outsideDir, filepath.Join(tmp, ".claude")); err != nil {
		t.Fatal(err)
	}

	result := SetupClaudeHooks(tmp, skipHookConfirmation)
	if result.Error == nil {
		t.Fatal("expected symlinked .claude directory to be rejected")
	}
	if _, err := os.Lstat(filepath.Join(outsideDir, "settings.json")); !os.IsNotExist(err) {
		t.Fatalf("outside settings created through symlinked .claude: %v", err)
	}
}

func TestSetupClaudeHooksRejectsSymlinkedSettings(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.MkdirAll(filepath.Join(tmp, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(outside, []byte(`{"hooks":{}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tmp, ".claude", "settings.json")); err != nil {
		t.Fatal(err)
	}

	result := SetupClaudeHooks(tmp, skipHookConfirmation)
	if result.Error == nil {
		t.Fatal("expected symlinked settings.json to be rejected")
	}
	data, err := os.ReadFile(outside)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"hooks":{}}` {
		t.Fatalf("outside settings mutated: %s", data)
	}
}

func TestSetupClaudeHooksMigratesLegacyHook(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	path := filepath.Join(tmp, ".claude")
	if err := os.MkdirAll(path, 0o755); err != nil {
		t.Fatal(err)
	}
	settings := map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []any{
				map[string]any{
					"matcher": ".*",
					"hooks": []any{
						map[string]any{"type": "command", "command": legacyNotifyHookCommand},
					},
				},
			},
		},
	}
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(path, "settings.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	result := SetupClaudeHooks(tmp, skipHookConfirmation)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Updated {
		t.Fatal("expected updated")
	}

	updatedData, err := os.ReadFile(filepath.Join(path, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	var updated map[string]any
	if err := json.Unmarshal(updatedData, &updated); err != nil {
		t.Fatal(err)
	}
	if !hookExists(t, updated) {
		t.Fatal("expected aw notify hook")
	}
	if findNotifyHook(t, updated, legacyNotifyHookCommand) {
		t.Fatal("legacy hook should be migrated")
	}
}

// Read-only assertion for real-file install/cleanup tests, using the production predicate.
func hookExists(t *testing.T, settings map[string]any) bool {
	t.Helper()
	return findNotifyHook(t, settings, notifyHookCommand)
}
func findNotifyHook(t *testing.T, settings map[string]any, command string) bool {
	t.Helper()
	data, err := json.Marshal(settings)
	if err != nil {
		t.Fatal(err)
	}
	root, err := parseHookJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	handlers, err := notifyHandlers(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, handler := range handlers {
		if notifyHookMatches(handler, command) {
			return true
		}
	}
	return false
}
