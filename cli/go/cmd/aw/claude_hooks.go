package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
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

func SetupClaudeHooks(repoRoot string, askConfirmation bool) *claudeHooksResult {
	result := &claudeHooksResult{
		FilePath: filepath.Join(repoRoot, ".claude", "settings.json"),
	}

	content, err := os.ReadFile(result.FilePath)
	if err != nil && !os.IsNotExist(err) {
		result.Error = fmt.Errorf("reading %s: %w", result.FilePath, err)
		result.Skipped = true
		return result
	}

	settings := map[string]any{}
	if len(content) > 0 {
		if err := json.Unmarshal(content, &settings); err != nil {
			result.Error = fmt.Errorf("parsing %s: %w", result.FilePath, err)
			result.Skipped = true
			return result
		}
	}

	if hookExists(settings) {
		result.AlreadyExists = true
		return result
	}

	migrated := replaceLegacyNotifyHooks(settings)
	if !migrated && askConfirmation {
		answer, err := promptString("Set up Claude Code hook for chat notifications? (y/n)", "y")
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

	if !migrated {
		addNotifyHook(settings)
	}

	if err := os.MkdirAll(filepath.Dir(result.FilePath), 0o755); err != nil {
		result.Error = fmt.Errorf("creating %s: %w", filepath.Dir(result.FilePath), err)
		result.Skipped = true
		return result
	}

	data, err := json.MarshalIndent(settings, "", "  ")
	if err != nil {
		result.Error = fmt.Errorf("marshaling settings: %w", err)
		result.Skipped = true
		return result
	}
	if err := os.WriteFile(result.FilePath, append(data, '\n'), 0o644); err != nil {
		result.Error = fmt.Errorf("writing %s: %w", result.FilePath, err)
		result.Skipped = true
		return result
	}

	if len(content) == 0 {
		result.Created = true
	} else {
		result.Updated = true
	}
	return result
}

func hookExists(settings map[string]any) bool {
	return findNotifyHook(settings, notifyHookCommand)
}

func findNotifyHook(settings map[string]any, target string) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	postToolUse, ok := hooks["PostToolUse"].([]any)
	if !ok {
		return false
	}
	for _, entry := range postToolUse {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if cmd, ok := entryMap["command"].(string); ok && cmd == target {
			return true
		}
		innerHooks, ok := entryMap["hooks"].([]any)
		if !ok {
			continue
		}
		for _, h := range innerHooks {
			hookMap, ok := h.(map[string]any)
			if !ok {
				continue
			}
			if cmd, ok := hookMap["command"].(string); ok && cmd == target {
				return true
			}
		}
	}
	return false
}

func addNotifyHook(settings map[string]any) {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		hooks = map[string]any{}
		settings["hooks"] = hooks
	}
	postToolUse, ok := hooks["PostToolUse"].([]any)
	if !ok {
		postToolUse = []any{}
	}
	postToolUse = append(postToolUse, map[string]any{
		"matcher": ".*",
		"hooks": []any{
			map[string]any{
				"type":    "command",
				"command": notifyHookCommand,
			},
		},
	})
	hooks["PostToolUse"] = postToolUse
}

func replaceLegacyNotifyHooks(settings map[string]any) bool {
	hooks, ok := settings["hooks"].(map[string]any)
	if !ok {
		return false
	}
	postToolUse, ok := hooks["PostToolUse"].([]any)
	if !ok {
		return false
	}
	changed := false
	for _, entry := range postToolUse {
		entryMap, ok := entry.(map[string]any)
		if !ok {
			continue
		}
		if cmd, ok := entryMap["command"].(string); ok && cmd == legacyNotifyHookCommand {
			entryMap["command"] = notifyHookCommand
			changed = true
		}
		if innerHooks, ok := entryMap["hooks"].([]any); ok {
			for _, h := range innerHooks {
				hookMap, ok := h.(map[string]any)
				if !ok {
					continue
				}
				if cmd, ok := hookMap["command"].(string); ok && cmd == legacyNotifyHookCommand {
					hookMap["command"] = notifyHookCommand
					changed = true
				}
			}
		}
	}
	return changed
}

func printClaudeHooksResult(result *claudeHooksResult) {
	if result == nil {
		return
	}
	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not set up Claude Code hooks: %v\n", result.Error)
		printManualHookInstructions()
		return
	}
	if result.AlreadyExists {
		fmt.Println("Claude Code hook: already configured")
		return
	}
	if result.Skipped {
		fmt.Println("Claude Code hook: skipped")
		printManualHookInstructions()
		return
	}
	if result.Created {
		fmt.Printf("Created %s with notification hook\n", result.FilePath)
		return
	}
	if result.Updated {
		fmt.Printf("Added notification hook to %s\n", result.FilePath)
	}
}

func printManualHookInstructions() {
	fmt.Println()
	fmt.Println("To enable chat notifications, add to .claude/settings.json:")
	fmt.Println(`  {
    "hooks": {
      "PostToolUse": [{
        "matcher": ".*",
        "hooks": [{"type": "command", "command": "aw notify"}]
      }]
    }
  }`)
}
