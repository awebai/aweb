package main

import (
	"encoding/json"
	"testing"
)

func TestChannelMCPConfig(t *testing.T) {
	t.Parallel()
	cfg := channelMCPConfig("/tmp/test-project")
	out, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(out, &parsed); err != nil {
		t.Fatal(err)
	}

	servers, ok := parsed["mcpServers"].(map[string]any)
	if !ok {
		t.Fatal("expected mcpServers key")
	}
	aweb, ok := servers["aweb"].(map[string]any)
	if !ok {
		t.Fatal("expected aweb server entry")
	}

	if aweb["command"] != "npx" {
		t.Fatalf("expected command=npx, got %v", aweb["command"])
	}
	args, ok := aweb["args"].([]any)
	if !ok || len(args) != 1 || args[0] != "@awebai/channel" {
		t.Fatalf("expected args=[@awebai/channel], got %v", aweb["args"])
	}
	if aweb["cwd"] != "/tmp/test-project" {
		t.Fatalf("expected cwd=/tmp/test-project, got %v", aweb["cwd"])
	}
}

func TestChannelMCPConfigNoHeaders(t *testing.T) {
	t.Parallel()
	cfg := channelMCPConfig("/tmp/test")
	out, _ := json.Marshal(cfg)
	var parsed map[string]any
	json.Unmarshal(out, &parsed)

	servers := parsed["mcpServers"].(map[string]any)
	aweb := servers["aweb"].(map[string]any)
	if _, ok := aweb["headers"]; ok {
		t.Fatal("channel config should not include headers")
	}
	if _, ok := aweb["url"]; ok {
		t.Fatal("channel config should not include url")
	}
}
