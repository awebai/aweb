package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func withFakeClaudePluginRunner(t *testing.T, err error) *[][]string {
	t.Helper()
	old := runClaudeChannelPluginCommand
	var calls [][]string
	runClaudeChannelPluginCommand = func(args ...string) error {
		calls = append(calls, append([]string(nil), args...))
		return err
	}
	t.Cleanup(func() { runClaudeChannelPluginCommand = old })
	return &calls
}

func withFakeClaudeOnPath(t *testing.T) {
	t.Helper()
	bin := t.TempDir()
	path := filepath.Join(bin, "claude")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestEnsureClaudeChannelPluginRunsMarketplaceAndInstall(t *testing.T) {
	withFakeClaudeOnPath(t)
	calls := withFakeClaudePluginRunner(t, nil)
	result := EnsureClaudeChannelPlugin(channelPluginOptions{RequireClaude: true})
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	want := [][]string{
		{"plugin", "marketplace", "add", claudeChannelMarketplace},
		{"plugin", "install", claudeChannelPlugin},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls=%v, want %v", *calls, want)
	}
}

func TestEnsureClaudeChannelPluginReturnsErrorWhenRequired(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	result := EnsureClaudeChannelPlugin(channelPluginOptions{RequireClaude: true})
	if result.Error == nil {
		t.Fatal("expected missing claude error")
	}
}

func TestEnsureClaudeChannelPluginSkipsWhenOptional(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	result := EnsureClaudeChannelPlugin(channelPluginOptions{RequireClaude: false})
	if result.Error != nil || !result.Skipped {
		t.Fatalf("result=%+v err=%v", result, result.Error)
	}
}

func TestSetupChannelMCPDoesNotWriteMCPJSON(t *testing.T) {
	withFakeClaudeOnPath(t)
	calls := withFakeClaudePluginRunner(t, nil)
	tmp := t.TempDir()
	result := SetupChannelMCP(tmp, false)
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if _, err := os.Stat(filepath.Join(tmp, ".mcp.json")); !os.IsNotExist(err) {
		t.Fatalf("SetupChannelMCP should not write .mcp.json, stat err=%v", err)
	}
	if len(*calls) != 2 {
		t.Fatalf("plugin setup calls=%v", *calls)
	}
}

func TestSetupChannelMCPReportsPluginErrors(t *testing.T) {
	withFakeClaudeOnPath(t)
	withFakeClaudePluginRunner(t, errors.New("boom"))
	result := SetupChannelMCP(t.TempDir(), false)
	if result.Error == nil {
		t.Fatal("expected plugin setup error")
	}
}
