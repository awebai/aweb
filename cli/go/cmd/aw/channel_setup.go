package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func channelMCPExists(settings map[string]any) bool {
	servers, ok := settings["mcpServers"].(map[string]any)
	if !ok {
		return false
	}
	_, ok = servers["aweb"]
	return ok
}

func addChannelMCP(settings map[string]any, cwd string) {
	servers, ok := settings["mcpServers"].(map[string]any)
	if !ok {
		servers = map[string]any{}
		settings["mcpServers"] = servers
	}
	servers["aweb"] = map[string]any{
		"command": "npx",
		"args":    []string{"@awebai/channel"},
		"cwd":     cwd,
	}
}

func SetupChannelMCP(repoRoot string, askConfirmation bool) *claudeHooksResult {
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

	if channelMCPExists(settings) {
		result.AlreadyExists = true
		return result
	}

	if askConfirmation {
		answer, err := promptString("Set up Claude Code channel MCP server? (y/n)", "y")
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

	addChannelMCP(settings, repoRoot)

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

func printChannelMCPResult(result *claudeHooksResult) {
	if result == nil {
		return
	}
	if result.Error != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not set up channel MCP server: %v\n", result.Error)
		printManualChannelInstructions()
		return
	}
	if result.AlreadyExists {
		fmt.Println("Channel MCP server: already configured")
		return
	}
	if result.Skipped {
		fmt.Println("Channel MCP server: skipped")
		printManualChannelInstructions()
		return
	}
	if result.Created {
		fmt.Printf("Created %s with channel MCP server\n", result.FilePath)
		return
	}
	if result.Updated {
		fmt.Printf("Added channel MCP server to %s\n", result.FilePath)
	}
}

func printManualChannelInstructions() {
	fmt.Println()
	fmt.Println("To enable the channel MCP server, add to .claude/settings.json:")
	fmt.Println(`  {
    "mcpServers": {
      "aweb": {
        "command": "npx",
        "args": ["@awebai/channel"],
        "cwd": "<project directory>"
      }
    }
  }`)
}
