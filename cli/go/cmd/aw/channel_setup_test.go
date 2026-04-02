package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSetupChannelMCPCreatesNew(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	result := SetupChannelMCP(tmp, false)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Created {
		t.Fatal("expected created")
	}

	data, err := os.ReadFile(filepath.Join(tmp, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(data, &settings); err != nil {
		t.Fatal(err)
	}
	if !channelMCPExists(settings) {
		t.Fatal("expected mcpServers.aweb in file")
	}

	aweb := settings["mcpServers"].(map[string]any)["aweb"].(map[string]any)
	if aweb["command"] != "npx" {
		t.Fatalf("expected command=npx, got %v", aweb["command"])
	}
	if aweb["cwd"] != tmp {
		t.Fatalf("expected cwd=%s, got %v", tmp, aweb["cwd"])
	}
}

func TestSetupChannelMCPMergesExisting(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	existing := map[string]any{
		"mcpServers": map[string]any{
			"other": map[string]any{"url": "http://example.com"},
		},
	}
	data, _ := json.Marshal(existing)
	if err := os.WriteFile(filepath.Join(tmp, ".mcp.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	result := SetupChannelMCP(tmp, false)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Updated {
		t.Fatal("expected updated")
	}

	updatedData, err := os.ReadFile(filepath.Join(tmp, ".mcp.json"))
	if err != nil {
		t.Fatal(err)
	}
	var settings map[string]any
	if err := json.Unmarshal(updatedData, &settings); err != nil {
		t.Fatal(err)
	}

	if !channelMCPExists(settings) {
		t.Fatal("expected mcpServers.aweb")
	}
	servers := settings["mcpServers"].(map[string]any)
	if _, ok := servers["other"]; !ok {
		t.Fatal("expected other server preserved")
	}
}

func TestSetupChannelMCPAlreadyExists(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	existing := map[string]any{
		"mcpServers": map[string]any{
			"aweb": map[string]any{"command": "npx", "args": []any{"@awebai/channel"}, "cwd": "/old/path"},
		},
	}
	data, _ := json.Marshal(existing)
	if err := os.WriteFile(filepath.Join(tmp, ".mcp.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}

	result := SetupChannelMCP(tmp, false)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.AlreadyExists {
		t.Fatal("expected already exists")
	}
}

func TestChannelMCPExistsEmpty(t *testing.T) {
	t.Parallel()
	if channelMCPExists(map[string]any{}) {
		t.Fatal("expected false for empty settings")
	}
}
