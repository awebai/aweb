package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestHookExistsEmpty(t *testing.T) {
	t.Parallel()
	if hookExists(map[string]any{}) {
		t.Fatal("expected false")
	}
}

func TestHookExistsWithNotifyHook(t *testing.T) {
	t.Parallel()
	settings := map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []any{
				map[string]any{
					"matcher": ".*",
					"hooks": []any{
						map[string]any{"type": "command", "command": notifyHookCommand},
					},
				},
			},
		},
	}
	if !hookExists(settings) {
		t.Fatal("expected true")
	}
}

func TestAddNotifyHookPreservesExisting(t *testing.T) {
	t.Parallel()
	settings := map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []any{map[string]any{"command": "existing"}},
			"PreToolUse":  []any{map[string]any{"command": "pre"}},
		},
		"other": "value",
	}
	addNotifyHook(settings)
	if settings["other"] != "value" {
		t.Fatal("expected other settings preserved")
	}
	hooks := settings["hooks"].(map[string]any)
	postToolUse := hooks["PostToolUse"].([]any)
	if len(postToolUse) != 2 {
		t.Fatalf("len(PostToolUse)=%d", len(postToolUse))
	}
	if !hookExists(settings) {
		t.Fatal("expected hook to exist")
	}
}

func TestReplaceLegacyNotifyHooks(t *testing.T) {
	t.Parallel()
	settings := map[string]any{
		"hooks": map[string]any{
			"PostToolUse": []any{
				map[string]any{
					"matcher": ".*",
					"hooks": []any{
						map[string]any{"type": "command", "command": legacyNotifyHookCommand},
					},
				},
				map[string]any{"command": legacyNotifyHookCommand},
			},
		},
	}
	if !replaceLegacyNotifyHooks(settings) {
		t.Fatal("expected migration")
	}
	if !hookExists(settings) {
		t.Fatal("expected aw notify after migration")
	}
	if findNotifyHook(settings, legacyNotifyHookCommand) {
		t.Fatal("legacy hook should be gone")
	}
}

func TestSetupClaudeHooksCreatesNew(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	result := SetupClaudeHooks(tmp, false)
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
	if !hookExists(settings) {
		t.Fatal("expected hook in file")
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
	data, _ := json.Marshal(settings)
	if err := os.WriteFile(filepath.Join(path, "settings.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	result := SetupClaudeHooks(tmp, false)
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
	if !hookExists(updated) {
		t.Fatal("expected aw notify hook")
	}
	if findNotifyHook(updated, legacyNotifyHookCommand) {
		t.Fatal("legacy hook should be migrated")
	}
}
