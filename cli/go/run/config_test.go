package run

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadUserConfigMissingReturnsZero(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AW_CONFIG_PATH", "")

	cfg, err := LoadUserConfig(dir)
	if err != nil {
		t.Fatalf("LoadUserConfig returned error: %v", err)
	}
	if cfg.BasePrompt != nil || cfg.WorkPromptSuffix != nil || cfg.CommsPromptSuffix != nil || cfg.WaitSeconds != nil || cfg.IdleWaitSeconds != nil {
		t.Fatalf("expected zero config, got %#v", cfg)
	}
}

func TestLoadUserConfigReadsFile(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AW_CONFIG_PATH", "")
	path := filepath.Join(dir, ".config", "aw", "run.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir failed: %v", err)
	}
	if err := os.WriteFile(path, []byte(`{"base_prompt":"coordinate with mia","work_prompt_suffix":"review before finish","comms_prompt_suffix":"return to your current work after handling comms","wait_seconds":11,"idle_wait_seconds":44}`), 0o600); err != nil {
		t.Fatalf("write failed: %v", err)
	}

	cfg, err := LoadUserConfig(dir)
	if err != nil {
		t.Fatalf("LoadUserConfig returned error: %v", err)
	}
	if cfg.WaitSeconds == nil || *cfg.WaitSeconds != 11 {
		t.Fatalf("expected wait_seconds=11, got %#v", cfg.WaitSeconds)
	}
	if cfg.IdleWaitSeconds == nil || *cfg.IdleWaitSeconds != 44 {
		t.Fatalf("expected idle_wait_seconds=44, got %#v", cfg.IdleWaitSeconds)
	}
	if cfg.BasePrompt == nil || *cfg.BasePrompt != "coordinate with mia" {
		t.Fatalf("expected base_prompt, got %#v", cfg.BasePrompt)
	}
	if cfg.WorkPromptSuffix == nil || *cfg.WorkPromptSuffix != "review before finish" {
		t.Fatalf("expected work_prompt_suffix, got %#v", cfg.WorkPromptSuffix)
	}
	if cfg.CommsPromptSuffix == nil || *cfg.CommsPromptSuffix != "return to your current work after handling comms" {
		t.Fatalf("expected comms_prompt_suffix, got %#v", cfg.CommsPromptSuffix)
	}
	if len(cfg.Services) != 0 {
		t.Fatalf("expected no services, got %#v", cfg.Services)
	}
}

func TestLoadUserConfigLocalOverridesGlobal(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("AW_CONFIG_PATH", "")
	workspaceRoot := filepath.Join(dir, "workspace")
	if err := os.MkdirAll(filepath.Join(workspaceRoot, ".aw"), 0o755); err != nil {
		t.Fatalf("mkdir workspace failed: %v", err)
	}
	if err := os.WriteFile(filepath.Join(workspaceRoot, ".aw", "context"), []byte("default_account: rose\n"), 0o600); err != nil {
		t.Fatalf("write .aw/context failed: %v", err)
	}

	globalPath := filepath.Join(dir, ".config", "aw", "run.json")
	if err := os.MkdirAll(filepath.Dir(globalPath), 0o755); err != nil {
		t.Fatalf("mkdir global config failed: %v", err)
	}
	if err := os.WriteFile(globalPath, []byte(`{"base_prompt":"global base","work_prompt_suffix":"global work","wait_seconds":11,"idle_wait_seconds":44,"services":[{"name":"backend","command":"make run-backend","description":"Backend API"}]}`), 0o600); err != nil {
		t.Fatalf("write global config failed: %v", err)
	}

	localPath := filepath.Join(workspaceRoot, ".aw", "run.json")
	if err := os.WriteFile(localPath, []byte(`{"base_prompt":"local base","comms_prompt_suffix":"local comms","idle_wait_seconds":9,"services":[{"name":"frontend","command":"make run-frontend","description":"Frontend UI"}]}`), 0o600); err != nil {
		t.Fatalf("write local config failed: %v", err)
	}

	cfg, err := LoadUserConfig(workspaceRoot)
	if err != nil {
		t.Fatalf("LoadUserConfig returned error: %v", err)
	}
	if cfg.BasePrompt == nil || *cfg.BasePrompt != "local base" {
		t.Fatalf("expected local base_prompt to win, got %#v", cfg.BasePrompt)
	}
	if cfg.WorkPromptSuffix == nil || *cfg.WorkPromptSuffix != "global work" {
		t.Fatalf("expected global work suffix to remain, got %#v", cfg.WorkPromptSuffix)
	}
	if cfg.CommsPromptSuffix == nil || *cfg.CommsPromptSuffix != "local comms" {
		t.Fatalf("expected local comms suffix, got %#v", cfg.CommsPromptSuffix)
	}
	if cfg.WaitSeconds == nil || *cfg.WaitSeconds != 11 {
		t.Fatalf("expected global wait_seconds to remain, got %#v", cfg.WaitSeconds)
	}
	if cfg.IdleWaitSeconds == nil || *cfg.IdleWaitSeconds != 9 {
		t.Fatalf("expected local idle_wait_seconds to win, got %#v", cfg.IdleWaitSeconds)
	}
	if len(cfg.Services) != 1 || cfg.Services[0].Name != "frontend" {
		t.Fatalf("expected local services to override global, got %#v", cfg.Services)
	}
}

func TestResolveSettingsPrecedence(t *testing.T) {
	wait := 9
	idleWait := 41
	basePrompt := "config base"
	workSuffix := "config work suffix"
	commsSuffix := "config comms suffix"
	cfg := UserConfig{
		BasePrompt:        &basePrompt,
		WorkPromptSuffix:  &workSuffix,
		CommsPromptSuffix: &commsSuffix,
		WaitSeconds:       &wait,
		IdleWaitSeconds:   &idleWait,
	}
	flagWait := 7
	flagIdleWait := 13

	settings, err := ResolveSettings(cfg, SettingOverrides{
		WaitSeconds:     &flagWait,
		IdleWaitSeconds: &flagIdleWait,
	})
	if err != nil {
		t.Fatalf("ResolveSettings returned error: %v", err)
	}
	if settings.WaitSeconds != 7 {
		t.Fatalf("expected flag wait to win, got %d", settings.WaitSeconds)
	}
	if settings.IdleWaitSeconds != 13 {
		t.Fatalf("expected flag idle wait to win, got %d", settings.IdleWaitSeconds)
	}
	if settings.BasePrompt != "config base" {
		t.Fatalf("expected base prompt from config, got %q", settings.BasePrompt)
	}
	if settings.WorkPromptSuffix != "config work suffix" {
		t.Fatalf("expected work suffix from config, got %q", settings.WorkPromptSuffix)
	}
	if settings.CommsPromptSuffix != "config comms suffix" {
		t.Fatalf("expected comms suffix from config, got %q", settings.CommsPromptSuffix)
	}
}
