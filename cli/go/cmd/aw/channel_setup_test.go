package main

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
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

func withFakeCommandOnPath(t *testing.T, name string) {
	t.Helper()
	bin := t.TempDir()
	path := filepath.Join(bin, name)
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func withFakeClaudeOnPath(t *testing.T) {
	t.Helper()
	withFakeCommandOnPath(t, "claude")
}

func withFakePiOnPath(t *testing.T) {
	t.Helper()
	withFakeCommandOnPath(t, "pi")
}

func withFakePiExtensionRunner(t *testing.T, fn func(args ...string) ([]byte, error)) *[][]string {
	t.Helper()
	old := runPiChannelExtensionCommand
	var calls [][]string
	runPiChannelExtensionCommand = func(args ...string) ([]byte, error) {
		calls = append(calls, append([]string(nil), args...))
		return fn(args...)
	}
	t.Cleanup(func() { runPiChannelExtensionCommand = old })
	return &calls
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

func TestEnsurePiChannelExtensionSkipsInstallWhenPresent(t *testing.T) {
	withFakePiOnPath(t)
	calls := withFakePiExtensionRunner(t, func(args ...string) ([]byte, error) {
		return []byte("User packages:\n  npm:@awebai/pi\n"), nil
	})
	result := EnsurePiChannelExtension()
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.AlreadyExists || result.Created {
		t.Fatalf("result=%+v", result)
	}
	want := [][]string{{"list", "--no-approve"}}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls=%v, want %v", *calls, want)
	}
}

func TestEnsurePiChannelExtensionInstallsAndVerifiesWhenMissing(t *testing.T) {
	withFakePiOnPath(t)
	listCount := 0
	calls := withFakePiExtensionRunner(t, func(args ...string) ([]byte, error) {
		switch strings.Join(args, " ") {
		case "list --no-approve":
			listCount++
			if listCount == 1 {
				return []byte("No packages installed\n"), nil
			}
			return []byte("User packages:\n  npm:@awebai/pi\n"), nil
		case "install npm:@awebai/pi@latest --no-approve":
			return []byte("installed\n"), nil
		default:
			return nil, errors.New("unexpected command")
		}
	})
	result := EnsurePiChannelExtension()
	if result.Error != nil {
		t.Fatalf("unexpected error: %v", result.Error)
	}
	if !result.Created || result.AlreadyExists {
		t.Fatalf("result=%+v", result)
	}
	want := [][]string{
		{"list", "--no-approve"},
		{"install", piChannelExtensionSource, "--no-approve"},
		{"list", "--no-approve"},
	}
	if !reflect.DeepEqual(*calls, want) {
		t.Fatalf("calls=%v, want %v", *calls, want)
	}
}

func TestEnsurePiChannelExtensionReturnsErrorWhenPiMissing(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	result := EnsurePiChannelExtension()
	if result.Error == nil || !strings.Contains(result.Error.Error(), "pi is required") {
		t.Fatalf("expected missing pi error, got %+v", result)
	}
}

func TestEnsurePiChannelExtensionReturnsInstallError(t *testing.T) {
	withFakePiOnPath(t)
	withFakePiExtensionRunner(t, func(args ...string) ([]byte, error) {
		if strings.Join(args, " ") == "list --no-approve" {
			return []byte("No packages installed\n"), nil
		}
		return []byte("network down"), errors.New("boom")
	})
	result := EnsurePiChannelExtension()
	if result.Error == nil || !strings.Contains(result.Error.Error(), "pi install npm:@awebai/pi@latest --no-approve") || !strings.Contains(result.Error.Error(), "network down") {
		t.Fatalf("expected install error with output, got %+v", result)
	}
}

func TestPiChannelExtensionPresentMatchesOnlyAwebPiPackage(t *testing.T) {
	if !piChannelExtensionPresent("User packages:\n  npm:@awebai/pi@latest\n") {
		t.Fatal("expected @awebai/pi@latest to match")
	}
	if piChannelExtensionPresent("User packages:\n  npm:@awebai/pi-other\n") {
		t.Fatal("did not expect @awebai/pi-other to match")
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
