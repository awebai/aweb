package awconfig

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Settings is an identity's local preferences, kept in settings.yaml of its
// identity home. A grant home carries a copy taken when the grant was minted.
type Settings struct {
	Messaging MessagingSettings `yaml:"messaging,omitempty"`
}

type MessagingSettings struct {
	// EncryptByDefault, when true, encrypts a send that no mode flag or
	// encrypted source decides, if the recipient has a published key. Unset
	// means false.
	EncryptByDefault *bool `yaml:"encrypt_by_default,omitempty"`
}

// EncryptsByDefault reports the effective value of
// messaging.encrypt_by_default.
func (s Settings) EncryptsByDefault() bool {
	return s.Messaging.EncryptByDefault != nil && *s.Messaging.EncryptByDefault
}

func IdentitySettingsPath(root string) string {
	return filepath.Join(filepath.Clean(root), "settings.yaml")
}

// LoadIdentitySettings reads settings.yaml from an identity home. A home
// without one has the zero Settings.
func LoadIdentitySettings(root string) (Settings, error) {
	path := IdentitySettingsPath(root)
	if err := preflightIdentityFile(path, "settings file"); err != nil {
		return Settings{}, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Settings{}, nil
	}
	if err != nil {
		return Settings{}, err
	}
	var settings Settings
	if err := yaml.Unmarshal(data, &settings); err != nil {
		return Settings{}, err
	}
	return settings, nil
}

func SaveIdentitySettings(root string, settings Settings) error {
	if strings.TrimSpace(root) == "" {
		return errors.New("identity home is required")
	}
	path := IdentitySettingsPath(root)
	if err := preflightIdentityFile(path, "settings file"); err != nil {
		return err
	}
	data, err := yaml.Marshal(settings)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(bytesTrimRightNewlines(data), '\n'))
}
