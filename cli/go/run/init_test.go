package run

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestInitUserConfigWritesConfig(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AW_CONFIG_PATH", "")

	input := strings.NewReader("coordinate with mia\nreview before finish\nreturn to work\n15\n45\n")
	var output bytes.Buffer

	if err := InitUserConfig(input, &output, UserConfig{}); err != nil {
		t.Fatalf("InitUserConfig returned error: %v", err)
	}

	cfg, err := LoadUserConfig(dir)
	if err != nil {
		t.Fatalf("LoadUserConfig returned error: %v", err)
	}
	if cfg.BasePrompt == nil || *cfg.BasePrompt != "coordinate with mia" {
		t.Fatalf("expected base prompt, got %#v", cfg.BasePrompt)
	}
	if cfg.WorkPromptSuffix == nil || *cfg.WorkPromptSuffix != "review before finish" {
		t.Fatalf("expected work suffix, got %#v", cfg.WorkPromptSuffix)
	}
	if cfg.CommsPromptSuffix == nil || *cfg.CommsPromptSuffix != "return to work" {
		t.Fatalf("expected comms suffix, got %#v", cfg.CommsPromptSuffix)
	}
	if cfg.WaitSeconds == nil || *cfg.WaitSeconds != 15 {
		t.Fatalf("expected wait_seconds=15, got %#v", cfg.WaitSeconds)
	}
	if cfg.IdleWaitSeconds == nil || *cfg.IdleWaitSeconds != 45 {
		t.Fatalf("expected idle_wait_seconds=45, got %#v", cfg.IdleWaitSeconds)
	}
	if !strings.Contains(output.String(), filepath.Join(dir, ".config", "aw", "run.json")) {
		t.Fatalf("expected output to mention config path, got %q", output.String())
	}
}

func TestInitUserConfigSeedsSuggestedDefaultsWhenUnset(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AW_CONFIG_PATH", "")

	input := strings.NewReader("\n\n\n\n\n")
	var output bytes.Buffer

	if err := InitUserConfig(input, &output, UserConfig{}); err != nil {
		t.Fatalf("InitUserConfig returned error: %v", err)
	}

	cfg, err := LoadUserConfig(dir)
	if err != nil {
		t.Fatalf("LoadUserConfig returned error: %v", err)
	}
	if cfg.BasePrompt == nil || *cfg.BasePrompt != DefaultInitBasePrompt {
		t.Fatalf("expected suggested base prompt, got %#v", cfg.BasePrompt)
	}
	if cfg.WorkPromptSuffix == nil || *cfg.WorkPromptSuffix != DefaultWorkPromptSuffix {
		t.Fatalf("expected default work suffix, got %#v", cfg.WorkPromptSuffix)
	}
	if cfg.CommsPromptSuffix == nil || *cfg.CommsPromptSuffix != DefaultInitCommsSuffix {
		t.Fatalf("expected suggested comms suffix, got %#v", cfg.CommsPromptSuffix)
	}
	if cfg.WaitSeconds == nil || *cfg.WaitSeconds != DefaultWaitSeconds {
		t.Fatalf("expected default wait_seconds, got %#v", cfg.WaitSeconds)
	}
	if cfg.IdleWaitSeconds == nil || *cfg.IdleWaitSeconds != DefaultIdleWaitSeconds {
		t.Fatalf("expected default idle_wait_seconds, got %#v", cfg.IdleWaitSeconds)
	}
}

func TestPromptConfigStringClearsOnDash(t *testing.T) {
	reader := strings.NewReader("-\n")
	var output bytes.Buffer

	value, err := promptConfigString(bufio.NewReader(reader), &output, "base_prompt", "current")
	if err != nil {
		t.Fatalf("promptConfigString returned error: %v", err)
	}
	if value == nil || *value != "" {
		t.Fatalf("expected cleared string, got %#v", value)
	}
}
