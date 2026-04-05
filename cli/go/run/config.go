package run

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/awebai/aw/awconfig"
)

const (
	DefaultWaitSeconds      = 20
	DefaultIdleWaitSeconds  = 30
	DefaultBasePrompt       = ""
	DefaultWorkPromptSuffix = "Before finishing, run a self-review or code-review pass on your changes."
	DefaultCommsPrompt      = ""
)

type UserConfig struct {
	BasePrompt        *string         `json:"base_prompt"`
	WorkPromptSuffix  *string         `json:"work_prompt_suffix"`
	CommsPromptSuffix *string         `json:"comms_prompt_suffix"`
	WaitSeconds       *int            `json:"wait_seconds"`
	IdleWaitSeconds   *int            `json:"idle_wait_seconds"`
	Services          []ServiceConfig `json:"services"`
}

type Settings struct {
	BasePrompt        string
	WorkPromptSuffix  string
	CommsPromptSuffix string
	WaitSeconds       int
	IdleWaitSeconds   int
	Services          []ServiceConfig
}

type SettingOverrides struct {
	BasePrompt        *string
	WorkPromptSuffix  *string
	CommsPromptSuffix *string
	WaitSeconds       *int
	IdleWaitSeconds   *int
}

func DefaultConfigPath() (string, error) {
	return awconfig.DefaultRunConfigPath()
}

func FindLocalConfigPath(startDir string) (string, error) {
	if strings.TrimSpace(startDir) == "" {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}
		startDir = wd
	}
	ctxPath, err := awconfig.FindWorktreeContextPath(startDir)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(ctxPath), "run.json"), nil
}

func LoadUserConfig(startDir string) (UserConfig, error) {
	if strings.TrimSpace(startDir) == "" {
		wd, err := os.Getwd()
		if err != nil {
			return UserConfig{}, err
		}
		startDir = wd
	}
	globalPath, err := DefaultConfigPath()
	if err != nil {
		return UserConfig{}, err
	}
	cfg, err := loadUserConfigFile(globalPath)
	if err != nil {
		return UserConfig{}, err
	}

	localPath, err := FindLocalConfigPath(startDir)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return UserConfig{}, err
	}
	localCfg, err := loadUserConfigFile(localPath)
	if err != nil {
		return UserConfig{}, err
	}
	return mergeUserConfig(cfg, localCfg), nil
}

func WriteUserConfig(cfg UserConfig) (string, error) {
	path, err := DefaultConfigPath()
	if err != nil {
		return "", err
	}
	return path, writeUserConfigTo(path, cfg)
}

func ResolveSettings(cfg UserConfig, overrides SettingOverrides) (Settings, error) {
	settings := Settings{
		BasePrompt:        DefaultBasePrompt,
		WorkPromptSuffix:  DefaultWorkPromptSuffix,
		CommsPromptSuffix: DefaultCommsPrompt,
		WaitSeconds:       DefaultWaitSeconds,
		IdleWaitSeconds:   DefaultIdleWaitSeconds,
	}

	if cfg.BasePrompt != nil {
		settings.BasePrompt = *cfg.BasePrompt
	}
	if cfg.WorkPromptSuffix != nil {
		settings.WorkPromptSuffix = *cfg.WorkPromptSuffix
	}
	if cfg.CommsPromptSuffix != nil {
		settings.CommsPromptSuffix = *cfg.CommsPromptSuffix
	}
	if cfg.WaitSeconds != nil {
		settings.WaitSeconds = *cfg.WaitSeconds
	}
	if cfg.IdleWaitSeconds != nil {
		settings.IdleWaitSeconds = *cfg.IdleWaitSeconds
	}
	if cfg.Services != nil {
		settings.Services = append([]ServiceConfig(nil), cfg.Services...)
	}

	if overrides.BasePrompt != nil {
		settings.BasePrompt = *overrides.BasePrompt
	}
	if overrides.WorkPromptSuffix != nil {
		settings.WorkPromptSuffix = *overrides.WorkPromptSuffix
	}
	if overrides.CommsPromptSuffix != nil {
		settings.CommsPromptSuffix = *overrides.CommsPromptSuffix
	}
	if overrides.WaitSeconds != nil {
		settings.WaitSeconds = *overrides.WaitSeconds
	}
	if overrides.IdleWaitSeconds != nil {
		settings.IdleWaitSeconds = *overrides.IdleWaitSeconds
	}
	if settings.WaitSeconds < 0 {
		return Settings{}, fmt.Errorf("wait_seconds must be >= 0")
	}
	if settings.IdleWaitSeconds < 0 {
		return Settings{}, fmt.Errorf("idle_wait_seconds must be >= 0")
	}
	for _, service := range settings.Services {
		if strings.TrimSpace(service.Name) == "" {
			return Settings{}, fmt.Errorf("services.name must be non-empty")
		}
		if strings.TrimSpace(service.Command) == "" {
			return Settings{}, fmt.Errorf("services[%s].command must be non-empty", service.Name)
		}
	}

	return settings, nil
}

func loadUserConfigFile(path string) (UserConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return UserConfig{}, nil
		}
		return UserConfig{}, err
	}

	var cfg UserConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return UserConfig{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}

func mergeUserConfig(base UserConfig, override UserConfig) UserConfig {
	merged := base
	if override.BasePrompt != nil {
		merged.BasePrompt = override.BasePrompt
	}
	if override.WorkPromptSuffix != nil {
		merged.WorkPromptSuffix = override.WorkPromptSuffix
	}
	if override.CommsPromptSuffix != nil {
		merged.CommsPromptSuffix = override.CommsPromptSuffix
	}
	if override.WaitSeconds != nil {
		merged.WaitSeconds = override.WaitSeconds
	}
	if override.IdleWaitSeconds != nil {
		merged.IdleWaitSeconds = override.IdleWaitSeconds
	}
	if override.Services != nil {
		merged.Services = append([]ServiceConfig(nil), override.Services...)
	}
	return merged
}

func writeUserConfigTo(path string, cfg UserConfig) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')

	return atomicWriteFileMode(path, data, 0o600)
}

func atomicWriteFileMode(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}

	tmp, err := os.CreateTemp(dir, ".tmp.*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()

	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	return os.Rename(tmpName, path)
}
